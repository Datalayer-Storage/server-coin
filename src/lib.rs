#![deny(clippy::all)]

use std::{str::FromStr, sync::Arc};

use bip39::Mnemonic;
use chia_bls::{SecretKey, Signature};
use chia_client::Peer as RustPeer;
use chia_protocol::{Coin as RustCoin, CoinState, NodeType, SpendBundle};
use chia_wallet_sdk::{
    connect_peer, create_tls_connector, incremental_sync, load_ssl_cert, sign_spend_bundle,
    Condition, DerivationStore, MemoryCoinStore, PublicKeyStore, SimpleDerivationStore, SyncConfig,
};
use clvm_traits::{FromClvm, ToNodePtr};
use clvm_utils::tree_hash;
use clvmr::{cost::Cost, Allocator, NodePtr};
use napi::{bindgen_prelude::Uint8Array, Error, Result};
use native_tls::TlsConnector;

mod server_coin;

use server_coin::{
    create_server_coin, delete_server_coins, morph_launcher_id, urls_from_conditions,
    ServerCoin as RustServerCoin,
};
use tokio::sync::{mpsc, Mutex};

#[macro_use]
extern crate napi_derive;

#[napi]
pub struct Tls(TlsConnector);

#[napi]
impl Tls {
    #[napi(constructor)]
    pub fn new(cert_path: String, key_path: String) -> Self {
        let cert = load_ssl_cert(&cert_path, &key_path);
        let tls = create_tls_connector(&cert);
        Self(tls)
    }
}

#[napi]
pub struct Peer(Arc<RustPeer>);

#[napi]
impl Peer {
    #[napi(factory)]
    pub async fn connect(node_uri: String, network_id: String, tls: &Tls) -> Result<Self> {
        let peer = connect_peer(&node_uri, tls.0.clone()).await.map_err(js)?;

        peer.send_handshake(network_id, NodeType::Wallet)
            .await
            .map_err(js)?;

        Ok(Self(peer))
    }

    #[napi]
    pub async fn fetch_server_coins(&self, launcher_id: Uint8Array) -> Result<ServerCoinIterator> {
        let launcher_id = bytes32(launcher_id)?;

        let hint = morph_launcher_id(launcher_id);
        let mut response = self
            .0
            .register_for_ph_updates(vec![hint.into()], 0)
            .await
            .map_err(|_| Error::from_reason("could not fetch server coins"))?;
        response.retain(|coin_state| coin_state.spent_height.is_none());
        response.sort_by_key(|coin_state| coin_state.coin.amount);

        Ok(ServerCoinIterator {
            peer: self.0.clone(),
            coin_states: Arc::new(Mutex::new(response)),
        })
    }
}

#[napi]
pub struct ServerCoinIterator {
    peer: Arc<RustPeer>,
    coin_states: Arc<Mutex<Vec<CoinState>>>,
}

#[napi]
impl ServerCoinIterator {
    #[napi]
    pub async fn next(&self) -> Result<Option<ServerCoin>> {
        loop {
            let Some(coin_state) = self.coin_states.lock().await.pop() else {
                return Ok(None);
            };

            let Some(created_height) = coin_state.created_height else {
                continue;
            };

            let spend = self
                .peer
                .request_puzzle_and_solution(coin_state.coin.parent_coin_info, created_height)
                .await
                .map_err(|_| Error::from_reason("failed to fetch puzzle and solution"))?;

            let mut a = Allocator::new();

            let Ok(output) = spend.puzzle.run(&mut a, 0, Cost::MAX, &spend.solution) else {
                continue;
            };

            let Ok(conditions) = Vec::<Condition<NodePtr>>::from_clvm(&a, output.1) else {
                continue;
            };

            let Some(urls) = urls_from_conditions(&coin_state.coin, &conditions) else {
                continue;
            };

            let puzzle = spend.puzzle.to_node_ptr(&mut a).unwrap();

            return Ok(Some(
                RustServerCoin {
                    coin: coin_state.coin,
                    p2_puzzle_hash: tree_hash(&a, puzzle).into(),
                    memo_urls: urls,
                }
                .into(),
            ));
        }
    }
}

#[napi]
pub struct Wallet {
    peer: Arc<RustPeer>,
    derivation_store: Arc<SimpleDerivationStore>,
    coin_store: Arc<MemoryCoinStore>,
    agg_sig_me: [u8; 32],
}

#[napi]
impl Wallet {
    #[napi(factory)]
    pub async fn initial_sync(
        peer: &Peer,
        mnemonic: String,
        agg_sig_me: Uint8Array,
    ) -> Result<Self> {
        let peer = peer.0.clone();
        let agg_sig_me = bytes32(agg_sig_me)?;

        let mnemonic = Mnemonic::from_str(&mnemonic).map_err(js)?;
        let seed = mnemonic.to_seed("");
        let sk = SecretKey::from_seed(&seed);

        let derivation_store = Arc::new(SimpleDerivationStore::new(&sk));
        let coin_store = Arc::new(MemoryCoinStore::new());

        let (sender, mut receiver) = mpsc::channel(32);

        let peer_2 = peer.clone();
        let derivation_store_2 = derivation_store.clone();
        let coin_store_2 = coin_store.clone();

        tokio::spawn(async move {
            incremental_sync(
                peer_2,
                derivation_store_2,
                coin_store_2,
                SyncConfig {
                    minimum_unused_derivations: 100,
                },
                sender,
            )
            .await
            .unwrap();
        });

        receiver.recv().await.unwrap();

        Ok(Self {
            peer,
            derivation_store,
            coin_store,
            agg_sig_me,
        })
    }

    #[napi]
    pub async fn derivation_index(&self) -> u32 {
        self.derivation_store.count().await
    }

    #[napi]
    pub async fn has_puzzle_hash(&self, puzzle_hash: Uint8Array) -> Result<bool> {
        let puzzle_hash = bytes32(puzzle_hash)?;
        Ok(self
            .derivation_store
            .index_of_ph(puzzle_hash)
            .await
            .is_some())
    }

    #[napi]
    pub async fn create_server_coin(
        &self,
        launcher_id: Uint8Array,
        amount: f64,
        fee: f64,
        urls: Vec<String>,
    ) -> Result<bool> {
        let launcher_id = bytes32(launcher_id)?;

        let coin_spends = create_server_coin(
            &self.peer,
            self.derivation_store.as_ref(),
            self.coin_store.as_ref(),
            amount as u64,
            fee as u64,
            launcher_id,
            urls,
        )
        .await
        .map_err(js)?;

        let mut a = Allocator::new();
        let mut spend_bundle = SpendBundle::new(coin_spends, Signature::default());
        let signature = sign_spend_bundle(
            self.derivation_store.as_ref(),
            &mut a,
            &spend_bundle,
            self.agg_sig_me,
        )
        .await
        .map_err(js)?;
        spend_bundle.aggregated_signature = signature;

        let ack = self.peer.send_transaction(spend_bundle).await.map_err(js)?;

        Ok(ack.status == 1 && ack.error.is_none())
    }

    #[napi]
    pub async fn delete_server_coins(&self, coins: Vec<Coin>, fee: f64) -> Result<bool> {
        let coin_spends = delete_server_coins(
            &self.peer,
            self.derivation_store.as_ref(),
            self.coin_store.as_ref(),
            coins
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<RustCoin>>>()?,
            fee as u64,
        )
        .await
        .map_err(js)?;

        let mut a = Allocator::new();
        let mut spend_bundle = SpendBundle::new(coin_spends, Signature::default());
        let signature = sign_spend_bundle(
            self.derivation_store.as_ref(),
            &mut a,
            &spend_bundle,
            self.agg_sig_me,
        )
        .await
        .map_err(js)?;
        spend_bundle.aggregated_signature = signature;

        let ack = self.peer.send_transaction(spend_bundle).await.map_err(js)?;

        Ok(ack.status == 1 && ack.error.is_none())
    }
}

#[napi(object)]
pub struct ServerCoin {
    pub coin: Coin,
    pub p2_puzzle_hash: Uint8Array,
    pub memo_urls: Vec<String>,
}

impl From<RustServerCoin> for ServerCoin {
    fn from(value: RustServerCoin) -> Self {
        Self {
            coin: value.coin.into(),
            p2_puzzle_hash: value.p2_puzzle_hash.to_bytes().into(),
            memo_urls: value.memo_urls,
        }
    }
}

#[napi(object)]
pub struct Coin {
    pub parent_coin_info: Uint8Array,
    pub puzzle_hash: Uint8Array,
    pub amount: f64,
}

#[napi]
pub fn to_coin_id(coin: Coin) -> Result<Uint8Array> {
    Ok(RustCoin::try_from(coin)?.coin_id().into())
}

#[napi]
pub fn bytes_equal(a: Uint8Array, b: Uint8Array) -> bool {
    a.to_vec() == b.to_vec()
}

impl From<RustCoin> for Coin {
    fn from(value: RustCoin) -> Self {
        Self {
            parent_coin_info: value.parent_coin_info.to_bytes().into(),
            puzzle_hash: value.puzzle_hash.to_bytes().into(),
            amount: value.amount as f64,
        }
    }
}

impl TryFrom<Coin> for RustCoin {
    type Error = Error;

    fn try_from(value: Coin) -> Result<Self> {
        Ok(Self {
            parent_coin_info: bytes32(value.parent_coin_info)?.into(),
            puzzle_hash: bytes32(value.puzzle_hash)?.into(),
            amount: value.amount as u64,
        })
    }
}

fn bytes32(value: Uint8Array) -> Result<[u8; 32]> {
    value
        .to_vec()
        .try_into()
        .map_err(|_| Error::from_reason("invalid 32 byte array"))
}

fn js<T>(error: T) -> Error
where
    T: ToString,
{
    Error::from_reason(error.to_string())
}
