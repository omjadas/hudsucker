#![cfg(unix)]

use hudsucker::{
    Body,
    HttpContext,
    HttpHandler,
    Proxy,
    RequestOrResponse,
    certificate_authority::RcgenAuthority,
    futures::{SinkExt, StreamExt},
    hyper::Request,
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
    tokio_tungstenite::{
        WebSocketStream,
        tungstenite::{Message, protocol::Role},
    },
};
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

#[allow(dead_code)]
mod common;

#[derive(Clone)]
struct Capture(Arc<Mutex<Option<std::net::SocketAddr>>>);
impl HttpHandler for Capture {
    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        *self.0.lock().unwrap() = Some(ctx.client_addr);
        req.into()
    }
}

#[tokio::test]
async fn unix_listener_forwards_and_shuts_down() {
    tokio::time::timeout(std::time::Duration::from_secs(10), exercise())
        .await
        .unwrap();
}

async fn exercise() {
    let path = std::env::temp_dir().join(format!("hudsucker-unix-{}.sock", std::process::id()));
    let listener = UnixListener::bind(&path).unwrap();
    let key = KeyPair::from_pem(include_str!("../examples/ca/hudsucker.key")).unwrap();
    let issuer =
        Issuer::from_ca_cert_pem(include_str!("../examples/ca/hudsucker.cer"), key).unwrap();
    let seen = Arc::new(Mutex::new(None));
    let (stop, done) = tokio::sync::oneshot::channel();
    let proxy = Proxy::builder()
        .with_unix_listener(listener)
        .with_ca(RcgenAuthority::new(
            issuer,
            1000,
            aws_lc_rs::default_provider(),
        ))
        .with_http_connector(common::http_connector())
        .with_websocket_connector(common::plain_websocket_connector())
        .with_http_handler(Capture(seen.clone()))
        .with_graceful_shutdown(async {
            done.await.unwrap_or_default();
        })
        .build()
        .unwrap();
    let proxy = tokio::spawn(proxy.start());
    let (upstream, stop_upstream) = common::start_http_server().await.unwrap();
    let mut stream = UnixStream::connect(&path).await.unwrap();
    stream.write_all(format!("GET http://{upstream}/hello HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.ends_with(common::HELLO_WORLD));
    assert_eq!(*seen.lock().unwrap(), Some(([0, 0, 0, 0], 0).into()));
    drop(stream);

    let mut stream = UnixStream::connect(&path).await.unwrap();
    stream.write_all(format!("GET http://{upstream}/ws HTTP/1.1\r\nHost: {upstream}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes()).await.unwrap();
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(stream.read_u8().await.unwrap());
    }
    assert!(
        String::from_utf8(headers)
            .unwrap()
            .starts_with("HTTP/1.1 101")
    );
    let mut ws = WebSocketStream::from_raw_socket(stream, Role::Client, None).await;
    ws.send(Message::text("hello")).await.unwrap();
    assert_eq!(
        ws.next().await.unwrap().unwrap(),
        Message::Text(common::WORLD)
    );
    ws.close(None).await.unwrap();
    drop(ws);
    stop.send(()).unwrap();
    proxy.await.unwrap().unwrap();
    assert!(tokio::net::UnixStream::connect(&path).await.is_err());
    stop_upstream.send(()).unwrap();
    // Socket path ownership and permissions belong to the caller.
    std::fs::remove_file(path).unwrap();
}
