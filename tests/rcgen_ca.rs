use hudsucker::{
    certificate_authority::RcgenAuthority,
    rcgen::{CertificateParams, KeyPair},
    rustls::crypto::aws_lc_rs,
};
use std::sync::atomic::Ordering;

mod common;

fn build_ca() -> RcgenAuthority {
    let key_pair = include_str!("../examples/ca/hudsucker.key");
    let ca_cert = include_str!("../examples/ca/hudsucker.cer");
    let key_pair = KeyPair::from_pem(key_pair).expect("Failed to parse private key");
    let ca_cert = CertificateParams::from_ca_cert_pem(ca_cert)
        .expect("Failed to parse CA certificate")
        .self_signed(&key_pair)
        .expect("Failed to sign CA certificate");

    RcgenAuthority::new(key_pair, ca_cert, 1000, aws_lc_rs::default_provider())
}

#[tokio::test]
async fn https_rustls() {
    let (proxy_addr, handler, stop_proxy) = common::start_proxy(
        build_ca(),
        common::rustls_client(),
        common::rustls_websocket_connector(),
    )
    .await
    .unwrap();

    let (server_addr, stop_server) = common::start_https_server(build_ca()).await.unwrap();
    let client = common::build_client(&proxy_addr.to_string());

    let res = client
        .get(format!("https://localhost:{}/hello", server_addr.port()))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    assert_eq!(handler.request_counter.load(Ordering::Relaxed), 2);
    assert_eq!(handler.response_counter.load(Ordering::Relaxed), 1);

    stop_server.send(()).unwrap();
    stop_proxy.send(()).unwrap();
}

#[tokio::test]
async fn https_native_tls() {
    let (proxy_addr, handler, stop_proxy) = common::start_proxy(
        build_ca(),
        common::native_tls_client(),
        common::native_tls_websocket_connector(),
    )
    .await
    .unwrap();

    let (server_addr, stop_server) = common::start_https_server(build_ca()).await.unwrap();
    let client = common::build_client(&proxy_addr.to_string());

    let res = client
        .get(format!("https://localhost:{}/hello", server_addr.port()))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    assert_eq!(handler.request_counter.load(Ordering::Relaxed), 2);
    assert_eq!(handler.response_counter.load(Ordering::Relaxed), 1);

    stop_server.send(()).unwrap();
    stop_proxy.send(()).unwrap();
}

#[tokio::test]
async fn without_intercept() {
    let (proxy_addr, handler, stop_proxy) = common::start_proxy_without_intercept(
        build_ca(),
        common::http_client(),
        common::plain_websocket_connector(),
    )
    .await
    .unwrap();

    let (server_addr, stop_server) = common::start_https_server(build_ca()).await.unwrap();
    let client = common::build_client(&proxy_addr.to_string());

    let res = client
        .get(format!("https://localhost:{}/hello", server_addr.port()))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    assert_eq!(handler.request_counter.load(Ordering::Relaxed), 1);
    assert_eq!(handler.response_counter.load(Ordering::Relaxed), 0);

    stop_server.send(()).unwrap();
    stop_proxy.send(()).unwrap();
}

#[tokio::test]
async fn decodes_response() {
    let (proxy_addr, _, stop_proxy) = common::start_proxy(
        build_ca(),
        common::native_tls_client(),
        common::native_tls_websocket_connector(),
    )
    .await
    .unwrap();

    let (server_addr, stop_server) = common::start_http_server().await.unwrap();
    let client = common::build_client(&proxy_addr.to_string());

    let res = client
        .get(format!("http://{}/hello/gzip", server_addr))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    assert_eq!(res.bytes().await.unwrap(), common::HELLO_WORLD);

    stop_server.send(()).unwrap();
    stop_proxy.send(()).unwrap();
}

#[tokio::test]
async fn noop() {
    let (proxy_addr, stop_proxy) = common::start_noop_proxy(build_ca()).await.unwrap();
    let (server_addr, stop_server) = common::start_http_server().await.unwrap();
    let client = common::build_client(&proxy_addr.to_string());

    let res = client
        .get(format!("http://{}/hello", server_addr))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    assert_eq!(res.bytes().await.unwrap(), common::HELLO_WORLD);

    stop_server.send(()).unwrap();
    stop_proxy.send(()).unwrap();
}
