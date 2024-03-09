use hudsucker::{certificate_authority::RcgenAuthority, *};
use rustls_pemfile as pemfile;
use std::net::SocketAddr;
use tracing::*;

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let mut private_key_bytes: &[u8] = include_bytes!("ca/hudsucker.key");
    let mut ca_cert_bytes: &[u8] = include_bytes!("ca/hudsucker.cer");
    let private_key = pemfile::private_key(&mut private_key_bytes)
        .unwrap()
        .expect("Failed to parse private key");
    let ca_cert = pemfile::certs(&mut ca_cert_bytes)
        .next()
        .unwrap()
        .expect("Failed to parse CA certificate");

    let ca = RcgenAuthority::new(private_key, ca_cert, 1_000)
        .expect("Failed to create Certificate Authority");

    let proxy = Proxy::builder()
        .with_addr(SocketAddr::from(([127, 0, 0, 1], 3000)))
        .with_rustls_client()
        .with_ca(ca)
        .with_graceful_shutdown(shutdown_signal())
        .build();

    if let Err(e) = proxy.start().await {
        error!("{}", e);
    }
}
