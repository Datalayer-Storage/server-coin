#![allow(dead_code)]

use std::sync::Arc;

use chia_bls::{SecretKey, Signature};
use chia_protocol::{NodeType, SpendBundle};
use chia_wallet_sdk::{
    connect_peer, create_tls_connector, incremental_sync, load_ssl_cert, sign_spend_bundle,
    MemoryCoinStore, SimpleDerivationStore, SyncConfig,
};
use clvmr::Allocator;
use hex_literal::hex;
use tokio::sync::mpsc;

mod server_coin;

use server_coin::*;

#[tokio::main]
async fn main() {
    let cert = load_ssl_cert("wallet.crt", "wallet.key");
    let tls = create_tls_connector(&cert);
    let peer = connect_peer("localhost:54939", tls).await.unwrap();

    peer.send_handshake("simulator0".to_string(), NodeType::Wallet)
        .await
        .unwrap();

    let sk = SecretKey::from_bytes(&[0; 32]).unwrap();

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

    println!("Wallet is synced.");

    let agg_sig_me = hex!("ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb");
    let launcher_id = [0u8; 32];
    let fee = (0.00005 * 1.0e12) as u64;

    let servers = fetch_server_coins(&peer, launcher_id, usize::MAX)
        .await
        .unwrap();

    let urls: Vec<String> = servers.iter().flat_map(|sc| sc.memo_urls.clone()).collect();

    println!("{:?}", urls);

    /*let coin_spends = delete_server_coins(
        peer.as_ref(),
        derivation_store.as_ref(),
        coin_store.as_ref(),
        servers.into_iter().map(|sc| sc.coin).collect(),
        fee,
    )
    .await
    .unwrap();*/

    /*let coin_spends = create_server_coin(
        peer.as_ref(),
        derivation_store.as_ref(),
        coin_store.as_ref(),
        1,
        fee,
        launcher_id,
        vec![format!("Server coin #{}", servers.len())],
    )
    .await
    .unwrap();*/

    /*let mut a = Allocator::new();
    let mut spend_bundle = SpendBundle::new(coin_spends, Signature::default());
    let signature = sign_spend_bundle(derivation_store.as_ref(), &mut a, &spend_bundle, agg_sig_me)
        .await
        .unwrap();
    spend_bundle.aggregated_signature = signature;

    let ack = peer.send_transaction(spend_bundle).await.unwrap();
    dbg!(ack);*/
}
