#![allow(dead_code)]

use std::sync::Arc;

use chia_bls::SecretKey;
use chia_client::Peer;
use chia_protocol::NodeType;
use chia_wallet_sdk::{
    connect_peer, create_tls_connector, incremental_sync, load_ssl_cert, MemoryCoinStore,
    SimpleDerivationStore, SyncConfig,
};
use tokio::{sync::mpsc, task::JoinHandle};

mod server_coin;

struct Wallet {
    peer: Arc<Peer>,
    derivation_store: Arc<SimpleDerivationStore>,
    coin_store: Arc<MemoryCoinStore>,
    sync: JoinHandle<()>,
}

impl Wallet {
    pub async fn start(
        node_uri: &str,
        network_id: &str,
        crt_path: &str,
        key_path: &str,
        sk: &SecretKey,
    ) -> Self {
        let cert = load_ssl_cert(crt_path, key_path);
        let tls = create_tls_connector(&cert);
        let peer = connect_peer(node_uri, tls).await.unwrap();

        peer.send_handshake(network_id.to_string(), NodeType::Wallet)
            .await
            .unwrap();

        let derivation_store = Arc::new(SimpleDerivationStore::new(sk));
        let coin_store = Arc::new(MemoryCoinStore::new());

        let (sender, _) = mpsc::channel(32);

        let peer_2 = peer.clone();
        let derivation_store_2 = derivation_store.clone();
        let coin_store_2 = coin_store.clone();
        let sync = tokio::spawn(async move {
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

        Self {
            peer,
            derivation_store,
            coin_store,
            sync,
        }
    }
}

#[tokio::main]
async fn main() {
    Wallet::start(
        "localhost:54939",
        "simulator0",
        "wallet.crt",
        "wallet.key",
        &SecretKey::from_bytes(&[0; 32]).unwrap(),
    )
    .await;
}
