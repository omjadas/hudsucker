use hudsucker::{
    hyper::{Body, Response},
    rustls::internal::pemfile,
    *,
};
use log::*;
use std::{future::Future, net::SocketAddr, pin::Pin};

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let request_handler = |req| -> Pin<Box<dyn Future<Output = RequestOrResponse> + Send>> {
        Box::pin(async {
            println!("{:?}", req);
            RequestOrResponse::Request(req)
        })
    };

    let response_handler = |res| -> Pin<Box<dyn Future<Output = Response<Body>> + Send>> {
        Box::pin(async {
            println!("{:?}", res);
            res
        })
    };

    let mut private_key_bytes: &[u8] = include_bytes!("ca/hudsucker.key");
    let mut ca_cert_bytes: &[u8] = include_bytes!("ca/hudsucker.pem");
    let private_key = pemfile::pkcs8_private_keys(&mut private_key_bytes)
        .expect("Failed to parse private key")
        .remove(0);
    let ca_cert = pemfile::certs(&mut ca_cert_bytes)
        .expect("Failed to parse CA certificate")
        .remove(0);

    let ca = CertificateAuthority::new(private_key, ca_cert, 1_000)
        .expect("Failed to create Certificate Authority");

    let proxy_config = ProxyConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
        shutdown_signal: shutdown_signal(),
        request_handler,
        response_handler,
        incoming_message_handler: |msg| Some(msg),
        outgoing_message_handler: |msg| Some(msg),
        upstream_proxy: None,
        ca,
    };

    if let Err(e) = start_proxy(proxy_config).await {
        error!("{}", e);
    }
}
