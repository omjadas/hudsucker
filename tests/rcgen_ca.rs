use hudsucker::{certificate_authority::RcgenAuthority, rustls};
use rustls_pemfile as pemfile;
use std::sync::atomic::Ordering;

mod common;

fn build_ca() -> RcgenAuthority {
    let mut private_key_bytes: &[u8] = include_bytes!("../examples/ca/hudsucker.key");
    let mut ca_cert_bytes: &[u8] = include_bytes!("../examples/ca/hudsucker.cer");
    let private_key = rustls::PrivateKey(
        pemfile::pkcs8_private_keys(&mut private_key_bytes)
            .expect("Failed to parse private key")
            .remove(0),
    );
    let ca_cert = rustls::Certificate(
        pemfile::certs(&mut ca_cert_bytes)
            .expect("Failed to parse CA certificate")
            .remove(0),
    );

    RcgenAuthority::new(private_key, ca_cert, 1_000)
        .expect("Failed to create Certificate Authority")
}

#[tokio::test]
async fn https() {
    let (proxy_addr, http_handler, stop_proxy) = common::start_proxy(build_ca()).unwrap();
    let client = common::build_client(&proxy_addr.to_string());

    let res = client.get("https://echo.omjad.as/").send().await.unwrap();

    assert_eq!(res.status(), 200);
    assert_eq!(http_handler.request_counter.load(Ordering::Relaxed), 1);
    assert_eq!(http_handler.response_counter.load(Ordering::Relaxed), 1);

    stop_proxy.send(()).unwrap();
}

#[tokio::test]
async fn decodes_response() {
    let (proxy_addr, _http_handler, stop_proxy) = common::start_proxy(build_ca()).unwrap();
    let (server_addr, stop_server) = common::start_test_server().unwrap();
    let client = common::build_client(&proxy_addr.to_string());

    let res = client
        .get(&format!("http://{}/hello/gzip", server_addr))
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
    let (proxy_addr, stop_proxy) = common::start_noop_proxy(build_ca()).unwrap();
    let (server_addr, stop_server) = common::start_test_server().unwrap();
    let client = common::build_client(&proxy_addr.to_string());

    let res = client
        .get(&format!("http://{}/hello", server_addr))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    assert_eq!(res.bytes().await.unwrap(), common::HELLO_WORLD);

    stop_server.send(()).unwrap();
    stop_proxy.send(()).unwrap();
}
