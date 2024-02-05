use chia_client::Peer;
use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use chia_wallet::standard::{StandardArgs, StandardSolution, STANDARD_PUZZLE};
use chia_wallet_sdk::{
    select_coins, spend_standard_coins, sync_to_unused_index, CoinSelectionError, CoinStore,
    Condition, CreateCoin, DerivationStore, SyncConfig,
};
use clvm_traits::{FromClvm, FromNodePtr, ToClvm, ToNodePtr};
use clvm_utils::{curry_tree_hash, tree_hash, tree_hash_atom, CurriedProgram};
use clvmr::{cost::Cost, serde::node_from_bytes, Allocator, NodePtr};
use hex_literal::hex;
use num_bigint::BigInt;
use rand::{seq::SliceRandom, thread_rng};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct MirrorArgs<M> {
    pub morpher: M,
}

#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct MirrorSolution<I, S> {
    pub parent_parent_id: Bytes32,
    pub parent_inner_puzzle: I,
    pub parent_amount: u64,
    pub parent_solution: S,
}

pub const MIRROR_PUZZLE: [u8; 242] = hex!(
    "
    ff02ffff01ff04ffff04ff08ffff04ffff02ff0affff04ff02ffff04ff0bffff
    04ffff02ff05ffff02ff0effff04ff02ffff04ff17ff8080808080ffff04ff2f
    ff808080808080ff808080ffff02ff17ff5f8080ffff04ffff01ffff4720ffff
    02ffff03ffff22ffff09ffff0dff0580ff0c80ffff09ffff0dff0b80ff0c80ff
    ff15ff17ffff0181ff8080ffff01ff0bff05ff0bff1780ffff01ff088080ff01
    80ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff0effff04ff02ff
    ff04ff09ff80808080ffff02ff0effff04ff02ffff04ff0dff8080808080ffff
    01ff0bffff0101ff058080ff0180ff018080
    "
);

pub const MIRROR_PUZZLE_HASH: [u8; 32] = hex!(
    "
    b10ce2d0b18dcf8c21ddfaf55d9b9f0adcbf1e0beb55b1a8b9cad9bbff4e5f22
    "
);

pub fn server_coin_hash() -> [u8; 32] {
    let morpher = tree_hash_atom(&u64_to_bytes(1));
    mirror_puzzle_hash(morpher)
}

pub fn mirror_puzzle_hash(morpher: [u8; 32]) -> [u8; 32] {
    curry_tree_hash(MIRROR_PUZZLE_HASH, &[morpher])
}

pub fn morph_launcher_id(launcher_id: [u8; 32]) -> [u8; 32] {
    let launcher_id_int = BigInt::from_signed_bytes_be(&launcher_id);
    let morphed_int = launcher_id_int + BigInt::from(1);

    let mut bytes = morphed_int.to_signed_bytes_be();
    if bytes.len() > 32 {
        return [0; 32];
    }

    while bytes.len() < 32 {
        bytes.insert(0, 0u8);
    }

    bytes.try_into().unwrap()
}

pub fn urls_from_conditions(
    server_coin: &Coin,
    parent_conditions: &[Condition<NodePtr>],
) -> Option<Vec<String>> {
    parent_conditions.iter().find_map(|condition| {
        let Condition::CreateCoin(CreateCoin::Memos {
            puzzle_hash,
            amount,
            memos,
        }) = condition
        else {
            return None;
        };

        if puzzle_hash != &server_coin.puzzle_hash || *amount != server_coin.amount {
            return None;
        }

        memos
            .iter()
            .skip(1)
            .map(|memo| String::from_utf8(memo.as_ref().to_vec()).ok())
            .collect()
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerCoin {
    pub coin: Coin,
    pub p2_puzzle_hash: Bytes32,
    pub memo_urls: Vec<String>,
}

pub async fn fetch_server_coins(
    peer: &Peer,
    launcher_id: [u8; 32],
    coin_limit: usize,
) -> Result<Vec<ServerCoin>, chia_client::Error<()>> {
    let hint = morph_launcher_id(launcher_id);
    let mut response = peer.register_for_ph_updates(vec![hint.into()], 0).await?;
    response.retain(|state| state.spent_height.is_none());

    response.shuffle(&mut thread_rng());

    let mut results = Vec::new();

    for coin_state in response.into_iter().take(coin_limit) {
        let Some(created_height) = coin_state.created_height else {
            continue;
        };

        let Ok(spend) = peer
            .request_puzzle_and_solution(coin_state.coin.parent_coin_info, created_height)
            .await
        else {
            continue;
        };

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

        results.push(ServerCoin {
            coin: coin_state.coin,
            p2_puzzle_hash: tree_hash(&a, puzzle).into(),
            memo_urls: urls,
        });
    }

    Ok(results)
}

#[derive(Debug, Error)]
pub enum SpendError {
    #[error("could not select coins: {0}")]
    CoinSelection(#[from] CoinSelectionError),

    #[error("could not fetch data from peer: {0}")]
    PeerError(#[from] chia_client::Error<()>),
}

pub async fn create_server_coin(
    peer: &Peer,
    derivation_store: &impl DerivationStore,
    coin_store: &impl CoinStore,
    server_coin_amount: u64,
    fee_amount: u64,
    launcher_id: [u8; 32],
    memo_urls: Vec<String>,
) -> Result<Vec<CoinSpend>, SpendError> {
    let minimum_select_amount = server_coin_amount as u128 + fee_amount as u128;

    let coins: Vec<Coin> = select_coins(coin_store.unspent_coins().await, minimum_select_amount)?
        .into_iter()
        .collect();

    let change_index =
        sync_to_unused_index(peer, derivation_store, coin_store, &SyncConfig::default()).await?;
    let change_ph = derivation_store.puzzle_hash(change_index).await.unwrap();

    let total_amount = coins
        .iter()
        .fold(0u128, |acc, coin| acc + coin.amount as u128);
    let change_amount = (total_amount - minimum_select_amount) as u64;

    let mut a = Allocator::new();
    let standard_puzzle_ptr = node_from_bytes(&mut a, &STANDARD_PUZZLE).unwrap();

    let mut memos = Vec::with_capacity(memo_urls.len() + 1);
    memos.push(morph_launcher_id(launcher_id).to_vec().into());

    for url in memo_urls {
        memos.push(url.as_bytes().into());
    }

    let mut conditions = vec![
        Condition::CreateCoin(CreateCoin::Memos {
            puzzle_hash: server_coin_hash().into(),
            amount: server_coin_amount,
            memos,
        }),
        Condition::ReserveFee { amount: fee_amount },
    ];

    if change_amount > 0 {
        conditions.push(Condition::CreateCoin(CreateCoin::Normal {
            puzzle_hash: change_ph.into(),
            amount: change_amount,
        }));
    }

    let result = spend_standard_coins(
        &mut a,
        standard_puzzle_ptr,
        derivation_store,
        coins,
        &conditions,
    )
    .await;

    Ok(result)
}

pub async fn delete_server_coins(
    peer: &Peer,
    derivation_store: &impl DerivationStore,
    coin_store: &impl CoinStore,
    server_coins: Vec<Coin>,
    fee_amount: u64,
) -> Result<Vec<CoinSpend>, SpendError> {
    if server_coins.is_empty() {
        return Ok(Vec::new());
    }

    let mut a = Allocator::new();
    let standard_puzzle_ptr = node_from_bytes(&mut a, &STANDARD_PUZZLE).unwrap();
    let mirror_puzzle_ptr = node_from_bytes(&mut a, &MIRROR_PUZZLE).unwrap();

    let curried_ptr = CurriedProgram {
        program: mirror_puzzle_ptr,
        args: MirrorArgs { morpher: 1 },
    }
    .to_node_ptr(&mut a)
    .unwrap();

    let puzzle = Program::from_node_ptr(&a, curried_ptr).unwrap();

    let mut coin_spends = Vec::with_capacity(server_coins.len());
    let mut spent_amount = 0;

    for server_coin in server_coins {
        let parent_coin = peer
            .register_for_coin_updates(vec![server_coin.clone().parent_coin_info], 0)
            .await?
            .remove(0);

        let index = derivation_store
            .index_of_ph(parent_coin.coin.puzzle_hash.into())
            .await
            .unwrap();

        let pk = derivation_store.public_key(index).await.unwrap();

        let solution = MirrorSolution {
            parent_parent_id: parent_coin.coin.parent_coin_info,
            parent_inner_puzzle: CurriedProgram {
                program: standard_puzzle_ptr,
                args: StandardArgs { synthetic_key: pk },
            },
            parent_amount: parent_coin.coin.amount,
            parent_solution: StandardSolution {
                original_public_key: None,
                delegated_puzzle: (),
                solution: (),
            },
        }
        .to_node_ptr(&mut a)
        .unwrap();

        spent_amount += server_coin.amount;

        coin_spends.push(CoinSpend::new(
            server_coin,
            puzzle.clone(),
            Program::from_node_ptr(&a, solution).unwrap(),
        ));
    }

    let required_amount = fee_amount.saturating_sub(spent_amount);

    let coins: Vec<Coin> = select_coins(coin_store.unspent_coins().await, required_amount as u128)?
        .into_iter()
        .collect();

    let change_index =
        sync_to_unused_index(peer, derivation_store, coin_store, &SyncConfig::default()).await?;
    let change_ph = derivation_store.puzzle_hash(change_index).await.unwrap();

    let total_amount = coins.iter().fold(0, |acc, coin| acc + coin.amount);
    let change_amount = total_amount - required_amount;

    let mut conditions = vec![Condition::ReserveFee {
        amount: required_amount,
    }];

    if change_amount > 0 {
        conditions.push(Condition::CreateCoin(CreateCoin::Normal {
            puzzle_hash: change_ph.into(),
            amount: change_amount,
        }));
    }

    coin_spends.extend(
        spend_standard_coins(
            &mut a,
            standard_puzzle_ptr,
            derivation_store,
            coins,
            &conditions,
        )
        .await,
    );

    Ok(coin_spends)
}

fn u64_to_bytes(amount: u64) -> Vec<u8> {
    let bytes: Vec<u8> = amount.to_be_bytes().into();
    let mut slice = bytes.as_slice();

    // Remove leading zeros.
    while (!slice.is_empty()) && (slice[0] == 0) {
        if slice.len() > 1 && (slice[1] & 0x80 == 0x80) {
            break;
        }
        slice = &slice[1..];
    }

    slice.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_morph() {
        let mut id = [3u8; 32];
        id[31] = 255;

        let mut expected = id;
        expected[31] = 0;
        expected[30] = 4;

        let actual = morph_launcher_id(id);

        assert_eq!(hex::encode(actual), hex::encode(expected));
    }
}
