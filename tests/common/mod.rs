use async_compression::tokio::bufread::GzipEncoder;
use futures::{SinkExt, StreamExt};
use hudsucker::{
    async_trait::async_trait,
    certificate_authority::CertificateAuthority,
    decode_request, decode_response,
    hyper::{
        client::{
            connect::{Connect, HttpConnector},
            Client,
        },
        header::CONTENT_ENCODING,
        server::conn::AddrStream,
        service::{make_service_fn, service_fn},
        Body, Method, Request, Response, Server, StatusCode,
    },
    rustls,
    tokio_tungstenite::tungstenite::Message,
    HttpContext, HttpHandler, Proxy, RequestOrResponse, WebSocketContext, WebSocketHandler,
};
use reqwest::tls::Certificate;
use rustls_pemfile as pemfile;
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
        .gen_server_config(&"localhost".parse().unwrap())
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

pub fn http_client() -> Client<HttpConnector> {
    Client::new()
}

pub fn plain_websocket_connector() -> tokio_tungstenite::Connector {
    tokio_tungstenite::Connector::Plain
}

fn rustls_client_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();

    for cert in rustls_native_certs::load_native_certs().unwrap() {
        let cert = rustls::Certificate(cert.0);
        roots.add(&cert).unwrap();
    }

    let mut ca_cert_bytes: &[u8] = include_bytes!("../../examples/ca/hudsucker.cer");
    let ca_cert = rustls::Certificate(
        pemfile::certs(&mut ca_cert_bytes)
            .next()
            .unwrap()
            .expect("Failed to parse CA certificate")
            .to_vec(),
    );

    roots.add(&ca_cert).unwrap();

    rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

pub fn rustls_websocket_connector() -> tokio_tungstenite::Connector {
    tokio_tungstenite::Connector::Rustls(Arc::new(rustls_client_config()))
}

pub fn rustls_client() -> Client<hyper_rustls::HttpsConnector<HttpConnector>> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(rustls_client_config())
        .https_or_http()
        .enable_http1()
        .build();

    Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build(https)
}

fn native_tls_connector() -> native_tls::TlsConnector {
    let ca_cert =
        native_tls::Certificate::from_pem(include_bytes!("../../examples/ca/hudsucker.cer"))
            .unwrap();

    native_tls::TlsConnector::builder()
        .add_root_certificate(ca_cert)
        .build()
        .unwrap()
}

pub fn native_tls_websocket_connector() -> tokio_tungstenite::Connector {
    tokio_tungstenite::Connector::NativeTls(native_tls_connector())
}

pub fn native_tls_client() -> Client<hyper_tls::HttpsConnector<HttpConnector>> {
    let mut http = HttpConnector::new();
    http.enforce_http(false);

    let tls = native_tls_connector().into();
    let https: hyper_tls::HttpsConnector<HttpConnector> = (http, tls).into();

    Client::builder().build(https)
}

pub fn start_proxy<C>(
    ca: impl CertificateAuthority,
    client: Client<C>,
    websocket_connector: tokio_tungstenite::Connector,
) -> Result<(SocketAddr, TestHandler, Sender<()>), Box<dyn std::error::Error>>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    _start_proxy(ca, client, websocket_connector, true)
}

pub fn start_proxy_without_intercept<C>(
    ca: impl CertificateAuthority,
    client: Client<C>,
    websocket_connector: tokio_tungstenite::Connector,
) -> Result<(SocketAddr, TestHandler, Sender<()>), Box<dyn std::error::Error>>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    _start_proxy(ca, client, websocket_connector, false)
}

fn _start_proxy<C>(
    ca: impl CertificateAuthority,
    client: Client<C>,
    websocket_connector: tokio_tungstenite::Connector,
    should_intercept: bool,
) -> Result<(SocketAddr, TestHandler, Sender<()>), Box<dyn std::error::Error>>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let addr = listener.local_addr()?;
    let (tx, rx) = tokio::sync::oneshot::channel();

    let handler = TestHandler::new(should_intercept);

    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_client(client)
        .with_ca(ca)
        .with_http_handler(handler.clone())
        .with_websocket_handler(handler.clone())
        .with_websocket_connector(websocket_connector)
        .build();

    tokio::spawn(proxy.start(async {
        rx.await.unwrap_or_default();
    }));

    Ok((addr, handler, tx))
}

pub fn start_noop_proxy(
    ca: impl CertificateAuthority,
) -> Result<(SocketAddr, Sender<()>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let addr = listener.local_addr()?;
    let (tx, rx) = tokio::sync::oneshot::channel();

    let proxy = Proxy::builder()
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
pub struct TestHandler {
    pub request_counter: Arc<AtomicUsize>,
    pub response_counter: Arc<AtomicUsize>,
    pub message_counter: Arc<AtomicUsize>,
    pub should_intercept: bool,
}

impl TestHandler {
    pub fn new(should_intercept: bool) -> Self {
        Self {
            request_counter: Arc::new(AtomicUsize::new(0)),
            response_counter: Arc::new(AtomicUsize::new(0)),
            message_counter: Arc::new(AtomicUsize::new(0)),
            should_intercept,
        }
    }
}

#[async_trait]
impl HttpHandler for TestHandler {
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

    async fn should_intercept(&mut self, _ctx: &HttpContext, _req: &Request<Body>) -> bool {
        self.should_intercept
    }
}

#[async_trait]
impl WebSocketHandler for TestHandler {
    async fn handle_message(&mut self, _ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        self.message_counter.fetch_add(1, Ordering::Relaxed);
        Some(msg)
    }
}
