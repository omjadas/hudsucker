use async_http_proxy::http_connect_tokio;
use futures::{SinkExt, StreamExt};
use hudsucker::{
    certificate_authority::RcgenAuthority, rustls, tokio_tungstenite::tungstenite::Message,
};
use rustls_pemfile as pemfile;
use std::sync::atomic::Ordering;
use tokio::net::TcpStream;

#[allow(unused)]
mod common;

fn build_ca() -> RcgenAuthority {
    let mut private_key_bytes: &[u8] = include_bytes!("../examples/ca/hudsucker.key");
    let mut ca_cert_bytes: &[u8] = include_bytes!("../examples/ca/hudsucker.cer");
    let private_key = rustls::PrivateKey(
        pemfile::pkcs8_private_keys(&mut private_key_bytes)
            .next()
            .unwrap()
            .expect("Failed to parse private key")
            .secret_pkcs8_der()
            .to_vec(),
    );
    let ca_cert = rustls::Certificate(
        pemfile::certs(&mut ca_cert_bytes)
            .next()
            .unwrap()
            .expect("Failed to parse CA certificate")
            .to_vec(),
    );

    RcgenAuthority::new(private_key, ca_cert, 1_000)
        .expect("Failed to create Certificate Authority")
}

#[tokio::test]
async fn http() {
    let (proxy_addr, handler, stop_proxy) = common::start_proxy(
        build_ca(),
        common::native_tls_client(),
        common::native_tls_websocket_connector(),
    )
    .unwrap();

    let (server_addr, stop_server) = common::start_http_server().unwrap();

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    http_connect_tokio(
        &mut stream,
        &server_addr.ip().to_string(),
        server_addr.port(),
    )
    .await
    .unwrap();

    let (mut ws, _) = tokio_tungstenite::client_async(format!("ws://{}", server_addr), stream)
        .await
        .unwrap();

    ws.send(Message::Text("hello".to_owned())).await.unwrap();

    let msg = ws.next().await.unwrap().unwrap();

    assert_eq!(msg.to_string(), common::WORLD);
    assert_eq!(handler.message_counter.load(Ordering::Relaxed), 2);

    stop_server.send(()).unwrap();
    stop_proxy.send(()).unwrap();
}

#[tokio::test]
async fn https_rustls() {
    let (proxy_addr, handler, stop_proxy) = common::start_proxy(
        build_ca(),
        common::rustls_client(),
        common::rustls_websocket_connector(),
    )
    .unwrap();

    let (server_addr, stop_server) = common::start_https_server(build_ca()).await.unwrap();

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    http_connect_tokio(&mut stream, "localhost", server_addr.port())
        .await
        .unwrap();

    let (mut ws, _) = tokio_tungstenite::client_async_tls_with_config(
        format!("wss://localhost:{}", server_addr.port()),
        stream,
        None,
        Some(common::rustls_websocket_connector()),
    )
    .await
    .unwrap();

    ws.send(Message::Text("hello".to_owned())).await.unwrap();

    let msg = ws.next().await.unwrap().unwrap();

    assert_eq!(msg.to_string(), common::WORLD);
    assert_eq!(handler.message_counter.load(Ordering::Relaxed), 2);

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
    .unwrap();

    let (server_addr, stop_server) = common::start_https_server(build_ca()).await.unwrap();

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    http_connect_tokio(&mut stream, "localhost", server_addr.port())
        .await
        .unwrap();

    let (mut ws, _) = tokio_tungstenite::client_async_tls_with_config(
        format!("wss://localhost:{}", server_addr.port()),
        stream,
        None,
        Some(common::native_tls_websocket_connector()),
    )
    .await
    .unwrap();

    ws.send(Message::Text("hello".to_owned())).await.unwrap();

    let msg = ws.next().await.unwrap().unwrap();

    assert_eq!(msg.to_string(), common::WORLD);
    assert_eq!(handler.message_counter.load(Ordering::Relaxed), 2);

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
    .unwrap();

    let (server_addr, stop_server) = common::start_http_server().unwrap();

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    http_connect_tokio(
        &mut stream,
        &server_addr.ip().to_string(),
        server_addr.port(),
    )
    .await
    .unwrap();

    let (mut ws, _) = tokio_tungstenite::client_async(format!("ws://{}", server_addr), stream)
        .await
        .unwrap();

    ws.send(Message::Text("hello".to_owned())).await.unwrap();

    let msg = ws.next().await.unwrap().unwrap();

    assert_eq!(msg.to_string(), common::WORLD);
    assert_eq!(handler.message_counter.load(Ordering::Relaxed), 0);

    stop_server.send(()).unwrap();
    stop_proxy.send(()).unwrap();
}

#[tokio::test]
async fn noop() {
    let (proxy_addr, stop_proxy) = common::start_noop_proxy(build_ca()).unwrap();
    let (server_addr, stop_server) = common::start_http_server().unwrap();

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    http_connect_tokio(
        &mut stream,
        &server_addr.ip().to_string(),
        server_addr.port(),
    )
    .await
    .unwrap();

    let (mut ws, _) = tokio_tungstenite::client_async(format!("ws://{}", server_addr), stream)
        .await
        .unwrap();

    ws.send(Message::Text("hello".to_owned())).await.unwrap();
    let msg = ws.next().await.unwrap().unwrap();

    assert_eq!(msg.to_string(), common::WORLD);

    stop_server.send(()).unwrap();
    stop_proxy.send(()).unwrap();
}
