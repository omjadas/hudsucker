use futures::try_join;
use hudsucker::{
    hyper_proxy::{Intercept, Proxy as UpstreamProxy},
    rustls::internal::pemfile,
    *,
};
use log::*;
use std::net::SocketAddr;

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let request_handler = |req| {
        println!("{:?}", req);
        RequestOrResponse::Request(req)
    };

    let response_handler = |res| {
        println!("{:?}", res);
        res
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
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 3001)),
        shutdown_signal: shutdown_signal(),
        request_handler,
        response_handler,
        incoming_message_handler: |msg| msg,
        outgoing_message_handler: |msg| msg,
        upstream_proxy: None,
        ca: ca.clone(),
    };

    let proxy_config_2 = ProxyConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
        request_handler: |req| RequestOrResponse::Request(req),
        response_handler: |res| res,
        incoming_message_handler: |msg| msg,
        outgoing_message_handler: |msg| msg,
        shutdown_signal: shutdown_signal(),
        upstream_proxy: Some(UpstreamProxy::new(
            Intercept::All,
            "http://127.0.0.1:3001"
                .parse()
                .expect("Failed to parse upstream proxy URI"),
        )),
        ca,
    };

    let proxy_1 = start_proxy(proxy_config);
    let proxy_2 = start_proxy(proxy_config_2);

    if let Err(e) = try_join!(proxy_1, proxy_2) {
        error!("{}", e);
    };
}
