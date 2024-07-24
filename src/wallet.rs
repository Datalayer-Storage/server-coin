use std::{collections::HashSet, sync::Arc};

use anyhow::anyhow;
use chia_bls::{sign, DerivableKey, PublicKey, SecretKey, Signature};
use chia_client::Peer;
use chia_protocol::{Bytes32, Coin, CoinSpend, CoinState, SpendBundle};
use chia_puzzles::{
    standard::{StandardArgs, StandardSolution},
    DeriveSynthetic,
};
use chia_wallet_sdk::{
    conditions::{Condition, CreateCoin},
    select_coins, Conditions, RequiredSignature, SpendContext,
};
use clvm_utils::CurriedProgram;
use clvmr::Allocator;
use indexmap::IndexSet;

use crate::server_coin::{morph_launcher_id, MirrorArgs, MirrorExt, MirrorSolution};

const MIN_UNUSED: u32 = 1000;
const BATCH_SIZE: usize = 500;

pub struct Wallet {
    peer: Arc<Peer>,
    agg_sig_me: Bytes32,
    intermediate_sk: SecretKey,
    p2_puzzle_hashes: IndexSet<Bytes32>,
    synthetic_keys: IndexSet<PublicKey>,
    coins: HashSet<Coin>,
}

impl Wallet {
    pub fn new(peer: Arc<Peer>, agg_sig_me: Bytes32, intermediate_sk: SecretKey) -> Self {
        Self {
            peer,
            agg_sig_me,
            intermediate_sk,
            p2_puzzle_hashes: IndexSet::new(),
            synthetic_keys: IndexSet::new(),
            coins: HashSet::new(),
        }
    }

    pub async fn initial_sync(&mut self) -> anyhow::Result<()> {
        self.sync_unused_puzzle_hash().await?;
        Ok(())
    }

    pub fn derivation_index(&self) -> u32 {
        self.p2_puzzle_hashes.len() as u32
    }

    pub fn puzzle_hash_index(&self, puzzle_hash: Bytes32) -> Option<u32> {
        self.p2_puzzle_hashes
            .get_index_of(&puzzle_hash)
            .map(|index| index as u32)
    }

    pub fn public_key_index(&self, public_key: PublicKey) -> Option<u32> {
        self.synthetic_keys
            .get_index_of(&public_key)
            .map(|index| index as u32)
    }

    pub fn synthetic_key(&self, index: u32) -> Option<PublicKey> {
        self.synthetic_keys.get_index(index as usize).copied()
    }

    pub fn apply(&mut self, coin_states: Vec<CoinState>) {
        for coin_state in coin_states {
            if coin_state.spent_height.is_some() {
                self.coins.remove(&coin_state.coin);
            } else {
                self.coins.insert(coin_state.coin);
            }
        }
    }

    pub async fn create_server_coin(
        &mut self,
        launcher_id: Bytes32,
        amount: u64,
        fee: u64,
        uris: Vec<String>,
    ) -> anyhow::Result<()> {
        let coins = self.select(amount + fee)?;
        let change_puzzle_hash = self.sync_unused_puzzle_hash().await?;

        let mut memos = Vec::with_capacity(uris.len() + 1);
        memos.push(morph_launcher_id(launcher_id).to_vec().into());

        for url in uris {
            memos.push(url.as_bytes().into());
        }

        let mut ctx = SpendContext::new();

        let conditions = Conditions::new()
            .condition(Condition::CreateCoin(CreateCoin {
                puzzle_hash: MirrorArgs::curry_tree_hash().into(),
                amount,
                memos,
            }))
            .reserve_fee(fee);

        self.spend(
            &mut ctx,
            &coins,
            conditions,
            amount + fee,
            change_puzzle_hash,
        )?;

        let coin_spends = ctx.take_spends();
        let spend_bundle = self.sign(coin_spends)?;
        let ack = self.peer.send_transaction(spend_bundle).await?;

        if let Some(error) = ack.error {
            return Err(anyhow!(error));
        }

        Ok(())
    }

    pub async fn delete_server_coins(
        &mut self,
        server_coins: Vec<Coin>,
        mut fee: u64,
    ) -> anyhow::Result<()> {
        if server_coins.is_empty() {
            return Ok(());
        }

        let mut ctx = SpendContext::new();
        let mirror_puzzle = ctx.mirror_puzzle()?;
        let standard_puzzle = ctx.standard_puzzle()?;

        let puzzle_reveal = ctx.serialize(&CurriedProgram {
            program: mirror_puzzle,
            args: MirrorArgs::default(),
        })?;

        for server_coin in server_coins {
            let parent_coin = self
                .peer
                .register_for_coin_updates(vec![server_coin.parent_coin_info], 0)
                .await?
                .remove(0);

            let index = self
                .puzzle_hash_index(parent_coin.coin.puzzle_hash)
                .ok_or_else(|| {
                    anyhow!(
                        "Parent puzzle hash does not belong to wallet or is not an XCH address."
                    )
                })?;

            let pk = self.synthetic_key(index).unwrap();

            let solution = ctx.serialize(&MirrorSolution {
                parent_parent_id: parent_coin.coin.parent_coin_info,
                parent_inner_puzzle: CurriedProgram {
                    program: standard_puzzle,
                    args: StandardArgs::new(pk),
                },
                parent_amount: parent_coin.coin.amount,
                parent_solution: StandardSolution {
                    original_public_key: None,
                    delegated_puzzle: (),
                    solution: (),
                },
            })?;

            fee = fee.saturating_sub(server_coin.amount);
            ctx.insert_coin_spend(CoinSpend::new(server_coin, puzzle_reveal.clone(), solution));
        }

        let coins = self.select(fee)?;
        let change_puzzle_hash = self.sync_unused_puzzle_hash().await?;
        let conditions = Conditions::new().reserve_fee(fee);
        self.spend(&mut ctx, &coins, conditions, fee, change_puzzle_hash)?;

        let coin_spends = ctx.take_spends();
        let spend_bundle = self.sign(coin_spends)?;
        let ack = self.peer.send_transaction(spend_bundle).await?;

        if let Some(error) = ack.error {
            return Err(anyhow!(error));
        }

        Ok(())
    }

    fn select(&self, amount: u64) -> anyhow::Result<Vec<Coin>> {
        Ok(select_coins(
            self.coins.iter().copied().collect(),
            amount as u128,
        )?)
    }

    fn unused_puzzle_hash(&self) -> Option<Bytes32> {
        self.p2_puzzle_hashes
            .iter()
            .find(|&ph| !self.coins.iter().any(|coin| coin.puzzle_hash == *ph))
            .copied()
    }

    fn spend(
        &self,
        ctx: &mut SpendContext,
        coins: &[Coin],
        conditions: Conditions,
        output: u64,
        change_puzzle_hash: Bytes32,
    ) -> anyhow::Result<()> {
        let change = coins.iter().map(|coin| coin.amount).sum::<u64>() - output;

        let mut coin_id = Bytes32::default();

        for (i, &coin) in coins.iter().enumerate() {
            let index = self
                .puzzle_hash_index(coin.puzzle_hash)
                .ok_or_else(|| anyhow!("Puzzle hash not found"))?;

            let synthetic_key = self.synthetic_key(index).unwrap();

            if i == 0 {
                coin_id = coin.coin_id();

                ctx.spend_p2_coin(
                    coin,
                    synthetic_key,
                    conditions
                        .clone()
                        .create_coin_announcement(b"$".to_vec().into())
                        .create_coin(change_puzzle_hash, change),
                )?;
            } else {
                ctx.spend_p2_coin(
                    coin,
                    synthetic_key,
                    Conditions::new().assert_coin_announcement(coin_id, b"$"),
                )?;
            }
        }
        Ok(())
    }

    fn sign(&self, coin_spends: Vec<CoinSpend>) -> anyhow::Result<SpendBundle> {
        let mut allocator = Allocator::new();
        let mut aggregate = Signature::default();

        for item in
            RequiredSignature::from_coin_spends(&mut allocator, &coin_spends, self.agg_sig_me)?
        {
            let Some(index) = self.public_key_index(item.public_key()) else {
                return Err(anyhow!("Public key not found"));
            };

            let sk = self
                .intermediate_sk
                .derive_unhardened(index)
                .derive_synthetic();

            aggregate += &sign(&sk, item.final_message())
        }

        Ok(SpendBundle::new(coin_spends, aggregate))
    }

    async fn sync_unused_puzzle_hash(&mut self) -> anyhow::Result<Bytes32> {
        loop {
            let next_derivation_index = self.derivation_index();

            if let Some(unused_puzzle_hash) = self.unused_puzzle_hash() {
                let index = self.puzzle_hash_index(unused_puzzle_hash).unwrap();

                if next_derivation_index - index >= MIN_UNUSED {
                    break;
                }
            }

            let mut new_puzzle_hashes = Vec::new();

            for index in next_derivation_index..next_derivation_index + MIN_UNUSED {
                let sk = self
                    .intermediate_sk
                    .derive_unhardened(index)
                    .derive_synthetic();
                let pk = sk.public_key();
                let puzzle_hash = StandardArgs::curry_tree_hash(pk).into();

                self.p2_puzzle_hashes.insert(puzzle_hash);
                self.synthetic_keys.insert(pk);
                new_puzzle_hashes.push(puzzle_hash);
            }

            for puzzle_hashes in new_puzzle_hashes.chunks(BATCH_SIZE) {
                let coin_states = self
                    .peer
                    .register_for_ph_updates(puzzle_hashes.to_vec(), 0)
                    .await?;

                self.apply(coin_states);
            }
        }

        Ok(self.unused_puzzle_hash().unwrap())
    }
}
