use async_compression::tokio::bufread::GzipEncoder;
use futures::{SinkExt, StreamExt};
use hudsucker::{
    async_trait::async_trait,
    certificate_authority::CertificateAuthority,
    decode_request, decode_response,
    hyper::{
        client::connect::HttpConnector,
        header::CONTENT_ENCODING,
        server::conn::AddrStream,
        service::{make_service_fn, service_fn},
        Body, Method, Request, Response, Server, StatusCode,
    },
    tungstenite::Message,
    HttpContext, HttpHandler, MessageContext, MessageHandler, ProxyBuilder, RequestOrResponse,
};
use reqwest::tls::Certificate;
use std::{
    convert::Infallible,
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tls_listener::TlsListener;
use tokio::sync::oneshot::Sender;
use tokio_native_tls::{self, native_tls};
use tokio_util::io::ReaderStream;

pub const HELLO_WORLD: &str = "Hello, World!";
pub const WORLD: &str = "world";

async fn test_server(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    if hyper_tungstenite::is_upgrade_request(&req) {
        let (res, ws) = hyper_tungstenite::upgrade(req, None).unwrap();

        tokio::spawn(async move {
            let mut ws = ws.await.unwrap();

            while let Some(msg) = ws.next().await {
                let msg = msg.unwrap();
                if msg.is_close() {
                    break;
                }
                ws.send(Message::Text(WORLD.to_owned())).await.unwrap();
            }
        });

        return Ok(res);
    }

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/hello") => Ok(Response::new(Body::from(HELLO_WORLD))),
        (&Method::GET, "/hello/gzip") => Ok(Response::builder()
            .header(CONTENT_ENCODING, "gzip")
            .status(StatusCode::OK)
            .body(Body::wrap_stream(ReaderStream::new(GzipEncoder::new(
                HELLO_WORLD.as_bytes(),
            ))))
            .unwrap()),
        (&Method::POST, "/echo") => Ok(Response::new(req.into_body())),
        _ => Ok(Response::new(Body::empty())),
    }
}

pub fn start_http_server() -> Result<(SocketAddr, Sender<()>), Box<dyn std::error::Error>> {
    let make_svc = make_service_fn(|_conn: &AddrStream| async {
        Ok::<_, Infallible>(service_fn(test_server))
    });

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let addr = listener.local_addr()?;

    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(
        Server::from_tcp(listener)?
            .serve(make_svc)
            .with_graceful_shutdown(async { rx.await.unwrap_or_default() }),
    );

    Ok((addr, tx))
}

pub async fn start_https_server(
    ca: impl CertificateAuthority,
) -> Result<(SocketAddr, Sender<()>), Box<dyn std::error::Error>> {
    let make_svc = make_service_fn(|_| async { Ok::<_, Infallible>(service_fn(test_server)) });

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let acceptor: tokio_rustls::TlsAcceptor = ca
        .gen_server_config(&format!("localhost:{}", addr.port()).parse().unwrap())
        .await
        .into();
    let listener = TlsListener::new(acceptor, tokio::net::TcpListener::from_std(listener)?);

    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(
        Server::builder(listener)
            .serve(make_svc)
            .with_graceful_shutdown(async { rx.await.unwrap_or_default() }),
    );

    Ok((addr, tx))
}

fn native_tls_client() -> hyper::client::Client<hyper_tls::HttpsConnector<HttpConnector>> {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let ca_cert =
        native_tls::Certificate::from_pem(include_bytes!("../../examples/ca/hudsucker.cer"))
            .unwrap();

    let tls = native_tls::TlsConnector::builder()
        .add_root_certificate(ca_cert)
        .build()
        .unwrap()
        .into();

    let https: hyper_tls::HttpsConnector<HttpConnector> = (http, tls).into();

    hyper::Client::builder().build(https)
}

pub fn start_proxy(
    ca: impl CertificateAuthority,
) -> Result<(SocketAddr, TestHttpHandler, TestMessageHandler, Sender<()>), Box<dyn std::error::Error>>
{
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let addr = listener.local_addr()?;
    let (tx, rx) = tokio::sync::oneshot::channel();

    let http_handler = TestHttpHandler::new();
    let message_handler = TestMessageHandler::new();

    let proxy = ProxyBuilder::new()
        .with_listener(listener)
        .with_client(native_tls_client())
        .with_ca(ca)
        .with_http_handler(http_handler.clone())
        .with_incoming_message_handler(message_handler.clone())
        .with_outgoing_message_handler(message_handler.clone())
        .build();

    tokio::spawn(proxy.start(async {
        rx.await.unwrap_or_default();
    }));

    Ok((addr, http_handler, message_handler, tx))
}

pub fn start_noop_proxy(
    ca: impl CertificateAuthority,
) -> Result<(SocketAddr, Sender<()>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let addr = listener.local_addr()?;
    let (tx, rx) = tokio::sync::oneshot::channel();

    let proxy = ProxyBuilder::new()
        .with_listener(listener)
        .with_client(native_tls_client())
        .with_ca(ca)
        .build();

    tokio::spawn(proxy.start(async {
        rx.await.unwrap_or_default();
    }));

    Ok((addr, tx))
}

pub fn build_client(proxy: &str) -> reqwest::Client {
    let proxy = reqwest::Proxy::all(proxy).unwrap();
    let ca_cert = Certificate::from_pem(include_bytes!("../../examples/ca/hudsucker.cer")).unwrap();

    reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(ca_cert)
        .no_brotli()
        .no_deflate()
        .no_gzip()
        .build()
        .unwrap()
}

#[derive(Clone)]
pub struct TestHttpHandler {
    pub request_counter: Arc<AtomicUsize>,
    pub response_counter: Arc<AtomicUsize>,
}

impl TestHttpHandler {
    pub fn new() -> Self {
        Self {
            request_counter: Arc::new(AtomicUsize::new(0)),
            response_counter: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl HttpHandler for TestHttpHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        self.request_counter.fetch_add(1, Ordering::Relaxed);
        let req = decode_request(req).unwrap();
        RequestOrResponse::Request(req)
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        self.response_counter.fetch_add(1, Ordering::Relaxed);
        decode_response(res).unwrap()
    }
}

#[derive(Clone)]
pub struct TestMessageHandler {
    pub message_counter: Arc<AtomicUsize>,
}

impl TestMessageHandler {
    pub fn new() -> Self {
        Self {
            message_counter: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl MessageHandler for TestMessageHandler {
    async fn handle_message(&mut self, _ctx: &MessageContext, msg: Message) -> Option<Message> {
        self.message_counter.fetch_add(1, Ordering::Relaxed);
        Some(msg)
    }
}
