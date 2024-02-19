#![deny(clippy::all)]

use std::{str::FromStr, sync::Arc};

use bip39::Mnemonic;
use chia_bls::{SecretKey, Signature};
use chia_client::Peer as RustPeer;
use chia_protocol::{Coin as RustCoin, NodeType, SpendBundle};
use chia_wallet_sdk::{
    connect_peer, create_tls_connector, incremental_sync, load_ssl_cert, sign_spend_bundle,
    MemoryCoinStore, PublicKeyStore, SimpleDerivationStore, SyncConfig,
};
use clvmr::Allocator;
use napi::{bindgen_prelude::Uint8Array, Error, Result};
use native_tls::TlsConnector;

mod server_coin;

use server_coin::{
    create_server_coin, delete_server_coins, fetch_server_coins, ServerCoin as RustServerCoin,
};
use tokio::sync::mpsc;

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
    pub async fn fetch_server_coins(
        &self,
        launcher_id: Uint8Array,
        count: u32,
    ) -> Result<Vec<ServerCoin>> {
        let launcher_id = bytes32(launcher_id)?;

        let server_coins = fetch_server_coins(&self.0, launcher_id, count as usize)
            .await
            .map_err(|_| Error::from_reason("could not fetch server coins"))?;

        Ok(server_coins.into_iter().map(Into::into).collect())
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
