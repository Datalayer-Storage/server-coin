#![deny(clippy::all)]

use std::{str::FromStr, sync::Arc};

use bip39::Mnemonic;
use chia_bls::{derive_keys::master_to_wallet_unhardened_intermediate, SecretKey};
use chia_client::PeerEvent;
use chia_protocol::{Bytes32, CoinState, NodeType};
use chia_wallet_sdk::{conditions::Condition, connect_peer, create_tls_connector, load_ssl_cert};
use clvm_traits::{FromClvm, ToNodePtr};
use clvm_utils::tree_hash;
use clvmr::{cost::Cost, Allocator};
use napi::{bindgen_prelude::Uint8Array, Error, Result};
use native_tls::TlsConnector;

mod server_coin;
mod wallet;

use server_coin::{morph_launcher_id, urls_from_conditions};
use tokio::sync::Mutex;

#[macro_use]
extern crate napi_derive;

#[napi]
pub struct Tls(TlsConnector);

#[napi]
impl Tls {
    #[napi(constructor)]
    pub fn new(cert_path: String, key_path: String) -> Result<Self> {
        let cert = load_ssl_cert(&cert_path, &key_path).map_err(js)?;
        let tls = create_tls_connector(&cert).map_err(js)?;
        Ok(Self(tls))
    }
}

#[napi]
pub struct Peer(Arc<chia_client::Peer>);

#[napi]
impl Peer {
    #[napi(factory)]
    pub async fn connect(node_uri: String, network_id: String, tls: &Tls) -> Result<Self> {
        let peer = connect_peer(&node_uri, tls.0.clone()).await.map_err(js)?;

        peer.send_handshake(network_id, NodeType::Wallet)
            .await
            .map_err(js)?;

        Ok(Self(Arc::new(peer)))
    }

    #[napi]
    pub async fn fetch_server_coins(&self, launcher_id: Uint8Array) -> Result<ServerCoinIterator> {
        let launcher_id = bytes32(launcher_id)?;
        let hint = morph_launcher_id(launcher_id);

        let mut response = self
            .0
            .register_for_ph_updates(vec![hint], 0)
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
    peer: Arc<chia_client::Peer>,
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

            let Ok(conditions) = Vec::<Condition>::from_clvm(&a, output.1) else {
                continue;
            };

            let Some(urls) = urls_from_conditions(&coin_state.coin, &conditions) else {
                continue;
            };

            let puzzle = spend.puzzle.to_node_ptr(&mut a).unwrap();

            return Ok(Some(
                server_coin::ServerCoin {
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
pub struct Wallet(Arc<Mutex<wallet::Wallet>>);

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
        let intermediate_sk = master_to_wallet_unhardened_intermediate(&sk);

        let wallet = Arc::new(Mutex::new(wallet::Wallet::new(
            peer.clone(),
            agg_sig_me,
            intermediate_sk,
        )));

        let mut receiver = peer.receiver().resubscribe();
        let incremental_wallet = wallet.clone();

        tokio::spawn(async move {
            while let Ok(event) = receiver.recv().await {
                if let PeerEvent::CoinStateUpdate(update) = event {
                    incremental_wallet.lock().await.apply(update.items);
                }
            }
        });

        wallet.lock().await.initial_sync().await.map_err(js)?;

        Ok(Self(wallet))
    }

    #[napi]
    pub async fn derivation_index(&self) -> u32 {
        self.0.lock().await.derivation_index()
    }

    #[napi]
    pub async fn has_puzzle_hash(&self, puzzle_hash: Uint8Array) -> Result<bool> {
        let puzzle_hash = bytes32(puzzle_hash)?;
        Ok(self.0.lock().await.puzzle_hash_index(puzzle_hash).is_some())
    }

    #[napi]
    pub async fn create_server_coin(
        &self,
        launcher_id: Uint8Array,
        amount: f64,
        fee: f64,
        uris: Vec<String>,
    ) -> Result<()> {
        let launcher_id = bytes32(launcher_id)?;

        self.0
            .lock()
            .await
            .create_server_coin(launcher_id, amount as u64, fee as u64, uris)
            .await
            .map_err(js)
    }

    #[napi]
    pub async fn delete_server_coins(&self, coins: Vec<Coin>, fee: f64) -> Result<()> {
        let coins = coins
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>>>()?;

        self.0
            .lock()
            .await
            .delete_server_coins(coins, fee as u64)
            .await
            .map_err(js)
    }
}

#[napi(object)]
pub struct ServerCoin {
    pub coin: Coin,
    pub p2_puzzle_hash: Uint8Array,
    pub memo_urls: Vec<String>,
}

impl From<server_coin::ServerCoin> for ServerCoin {
    fn from(value: server_coin::ServerCoin) -> Self {
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
    Ok(chia_protocol::Coin::try_from(coin)?.coin_id().into())
}

#[napi]
pub fn bytes_equal(a: Uint8Array, b: Uint8Array) -> bool {
    a.to_vec() == b.to_vec()
}

impl From<chia_protocol::Coin> for Coin {
    fn from(value: chia_protocol::Coin) -> Self {
        Self {
            parent_coin_info: value.parent_coin_info.to_bytes().into(),
            puzzle_hash: value.puzzle_hash.to_bytes().into(),
            amount: value.amount as f64,
        }
    }
}

impl TryFrom<Coin> for chia_protocol::Coin {
    type Error = Error;

    fn try_from(value: Coin) -> Result<Self> {
        Ok(Self {
            parent_coin_info: bytes32(value.parent_coin_info)?,
            puzzle_hash: bytes32(value.puzzle_hash)?,
            amount: value.amount as u64,
        })
    }
}

fn bytes32(value: Uint8Array) -> Result<Bytes32> {
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
