mod certificate_authority;
mod error;
mod rewind;

use futures::{sink::SinkExt, stream::StreamExt};
use http::uri::PathAndQuery;
use hyper::{
    client::HttpConnector,
    server::conn::Http,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Client, Method, Request, Response, Server,
};
use hyper_proxy::{Proxy as UpstreamProxy, ProxyConnector};
use hyper_rustls::HttpsConnector;
use log::*;
use rewind::Rewind;
use rustls::ClientConfig;
use std::{convert::Infallible, future::Future, net::SocketAddr, sync::Arc};
use tokio::io::AsyncReadExt;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{connect_async, tungstenite::Message, WebSocketStream};

pub use certificate_authority::CertificateAuthority;
pub use error::Error;
pub use http;
pub use hyper_proxy;
pub use rustls;
pub use tokio_tungstenite::tungstenite;

#[derive(Clone)]
enum MaybeProxyClient {
    Proxy(Client<ProxyConnector<HttpsConnector<HttpConnector>>>),
    Https(Client<HttpsConnector<HttpConnector>>),
}

/// Enum representing either an HTTP request or response
#[derive(Debug)]
pub enum RequestOrResponse {
    Request(Request<Body>),
    Response(Response<Body>),
}

/// Handler for HTTP requests
pub trait RequestHandler:
    FnMut(Request<Body>) -> RequestOrResponse + Send + Sync + Clone + 'static
{
}
impl<T> RequestHandler for T where
    T: FnMut(Request<Body>) -> RequestOrResponse + Send + Sync + Clone + 'static
{
}

/// Handler for HTTP responses
pub trait ResponseHandler:
    FnMut(Response<Body>) -> Response<Body> + Send + Sync + Clone + 'static
{
}
impl<T> ResponseHandler for T where
    T: FnMut(Response<Body>) -> Response<Body> + Send + Sync + Clone + 'static
{
}

/// Handler for websocket messages
pub trait MessageHandler: FnMut(Message) -> Message + Send + Sync + Clone + 'static {}
impl<T> MessageHandler for T where T: FnMut(Message) -> Message + Send + Sync + Clone + 'static {}

/// Configuration for the proxy server.
#[derive(Clone)]
pub struct ProxyConfig<F: Future<Output = ()>, R1, R2, W1, W2>
where
    R1: RequestHandler,
    R2: ResponseHandler,
    W1: MessageHandler,
    W2: MessageHandler,
{
    pub listen_addr: SocketAddr,
    pub shutdown_signal: F,
    pub ca: CertificateAuthority,
    pub request_handler: R1,
    pub response_handler: R2,
    pub incoming_message_handler: W1,
    pub outgoing_message_handler: W2,
    pub upstream_proxy: Option<UpstreamProxy>,
}

#[derive(Clone)]
struct ProxyState<R1, R2, W1, W2>
where
    R1: RequestHandler,
    R2: ResponseHandler,
    W1: MessageHandler,
    W2: MessageHandler,
{
    pub ca: CertificateAuthority,
    pub client: MaybeProxyClient,
    pub request_handler: R1,
    pub response_handler: R2,
    pub incoming_message_handler: W1,
    pub outgoing_message_handler: W2,
}

/// Start a proxy server on the given address. The proxy will run until the provided shutdown signal
/// resolves.
pub async fn start_proxy<F, R1, R2, W1, W2>(
    ProxyConfig {
        listen_addr,
        shutdown_signal,
        ca,
        request_handler,
        response_handler,
        incoming_message_handler,
        outgoing_message_handler,
        upstream_proxy,
    }: ProxyConfig<F, R1, R2, W1, W2>,
) -> Result<(), Error>
where
    F: Future<Output = ()>,
    R1: RequestHandler,
    R2: ResponseHandler,
    W1: MessageHandler,
    W2: MessageHandler,
{
    let client = gen_client(upstream_proxy);

    let make_service = make_service_fn(move |_| {
        let client = client.clone();
        let ca = ca.clone();
        let request_handler = request_handler.clone();
        let response_handler = response_handler.clone();
        let incoming_message_handler = incoming_message_handler.clone();
        let outgoing_message_handler = outgoing_message_handler.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                proxy(
                    ProxyState {
                        ca: ca.clone(),
                        client: client.clone(),
                        request_handler: request_handler.clone(),
                        response_handler: response_handler.clone(),
                        incoming_message_handler: incoming_message_handler.clone(),
                        outgoing_message_handler: outgoing_message_handler.clone(),
                    },
                    req,
                )
            }))
        }
    });

    Server::bind(&listen_addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .http1_only(true)
        .serve(make_service)
        .with_graceful_shutdown(shutdown_signal)
        .await
        .map_err(|err| err.into())
}

fn gen_client(upstream_proxy: Option<UpstreamProxy>) -> MaybeProxyClient {
    let mut http = HttpConnector::new();
    http.enforce_http(false);

    let mut config = ClientConfig::new();
    config.ct_logs = Some(&ct_logs::LOGS);
    config.set_protocols(&[b"http/1.1".to_vec()]);
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let https: HttpsConnector<HttpConnector> = (http, config).into();

    if let Some(proxy) = upstream_proxy {
        // The following can only panic when using the "rustls" hyper_proxy feature
        let connector = ProxyConnector::from_proxy(https, proxy)
            .expect("Failed to create upstream proxy connector");

        return MaybeProxyClient::Proxy(
            Client::builder()
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(connector),
        );
    } else {
        MaybeProxyClient::Https(
            Client::builder()
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(https),
        )
    }
}

async fn proxy<R1, R2, W1, W2>(
    state: ProxyState<R1, R2, W1, W2>,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error>
where
    R1: RequestHandler,
    R2: ResponseHandler,
    W1: MessageHandler,
    W2: MessageHandler,
{
    if req.method() == Method::CONNECT {
        process_connect(state, req).await
    } else {
        process_request(state, req).await
    }
}

async fn process_request<R1, R2, W1, W2>(
    mut state: ProxyState<R1, R2, W1, W2>,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error>
where
    R1: RequestHandler,
    R2: ResponseHandler,
    W1: MessageHandler,
    W2: MessageHandler,
{
    let req = match (state.request_handler)(req) {
        RequestOrResponse::Request(req) => req,
        RequestOrResponse::Response(res) => return Ok(res),
    };

    if hyper_tungstenite::is_upgrade_request(&req) {
        let scheme =
            if req.uri().scheme().unwrap_or(&http::uri::Scheme::HTTP) == &http::uri::Scheme::HTTP {
                "ws"
            } else {
                "wss"
            };

        let uri = http::uri::Builder::new()
            .scheme(scheme)
            .authority(
                req.uri()
                    .authority()
                    .expect("Authority not included in request")
                    .to_owned(),
            )
            .path_and_query(
                req.uri()
                    .path_and_query()
                    .unwrap_or(&PathAndQuery::from_static("/"))
                    .to_owned(),
            )
            .build()
            .expect("Failed to build URI for websocket connection");

        let (res, websocket) =
            hyper_tungstenite::upgrade(req, None).expect("Request has missing headers");

        tokio::spawn(async move {
            let server_socket = websocket
                .await
                .unwrap_or_else(|_| panic!("Failed to upgrade websocket connection for {}", uri));
            handle_websocket(state, server_socket, &uri).await;
        });

        return Ok(res);
    }

    let res = match state.client {
        MaybeProxyClient::Proxy(client) => client.request(req).await?,
        MaybeProxyClient::Https(client) => client.request(req).await?,
    };

    Ok((state.response_handler)(res))
}

async fn process_connect<R1, R2, W1, W2>(
    state: ProxyState<R1, R2, W1, W2>,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error>
where
    R1: RequestHandler,
    R2: ResponseHandler,
    W1: MessageHandler,
    W2: MessageHandler,
{
    tokio::task::spawn(async move {
        let authority = req
            .uri()
            .authority()
            .expect("URI does not contain authority");
        let server_config = Arc::new(state.ca.gen_server_config(authority).await);

        match hyper::upgrade::on(req).await {
            Ok(mut upgraded) => {
                let mut buffer = [0; 4];
                let bytes_read = upgraded
                    .read(&mut buffer)
                    .await
                    .expect("Failed to read from upgraded connection");

                let upgraded = Rewind::new_buffered(
                    upgraded,
                    bytes::Bytes::copy_from_slice(buffer[..bytes_read].as_ref()),
                );

                if bytes_read == 4 && buffer == *b"GET " {
                    if let Err(e) = serve_websocket(state, upgraded).await {
                        error!("websocket connect error: {}", e);
                    }
                } else {
                    let stream = TlsAcceptor::from(server_config)
                        .accept(upgraded)
                        .await
                        .expect("Failed to establish TLS connection with client");

                    if let Err(e) = serve_https(state, stream).await {
                        let e_string = e.to_string();
                        if !e_string.starts_with("error shutting down connection") {
                            error!("https connect error: {}", e);
                        }
                    }
                }
            }
            Err(e) => error!("upgrade error: {}", e),
        };
    });

    Ok(Response::new(Body::empty()))
}

async fn handle_websocket<R1, R2, W1, W2>(
    ProxyState {
        mut incoming_message_handler,
        mut outgoing_message_handler,
        ..
    }: ProxyState<R1, R2, W1, W2>,
    server_socket: WebSocketStream<Upgraded>,
    uri: &http::Uri,
) where
    R1: RequestHandler,
    R2: ResponseHandler,
    W1: MessageHandler,
    W2: MessageHandler,
{
    let (client_socket, _) = connect_async(uri)
        .await
        .unwrap_or_else(|_| panic!("Failed to open websocket connection to {}", uri));

    let (mut server_sink, mut server_stream) = server_socket.split();
    let (mut client_sink, mut client_stream) = client_socket.split();

    tokio::spawn(async move {
        while let Some(message) = server_stream.next().await {
            match message {
                Ok(message) => {
                    let message = incoming_message_handler(message);
                    match client_sink.send(message).await {
                        Err(tungstenite::Error::ConnectionClosed) => (),
                        Err(e) => error!("websocket send error: {}", e),
                        _ => (),
                    }
                }
                Err(e) => error!("websocket message error: {}", e),
            }
        }
    });

    tokio::spawn(async move {
        while let Some(message) = client_stream.next().await {
            match message {
                Ok(message) => {
                    let message = outgoing_message_handler(message);
                    match server_sink.send(message).await {
                        Err(tungstenite::Error::ConnectionClosed) => (),
                        Err(e) => error!("websocket send error: {}", e),
                        _ => (),
                    }
                }
                Err(e) => error!("websocket message error: {}", e),
            }
        }
    });
}

async fn serve_websocket<R1, R2, W1, W2>(
    state: ProxyState<R1, R2, W1, W2>,
    stream: Rewind<Upgraded>,
) -> Result<(), hyper::Error>
where
    R1: RequestHandler,
    R2: ResponseHandler,
    W1: MessageHandler,
    W2: MessageHandler,
{
    let service = service_fn(|req| {
        let authority = req
            .headers()
            .get(http::header::HOST)
            .expect("Host is a required header")
            .to_str()
            .expect("Failed to convert host to str");

        let uri = http::uri::Builder::new()
            .scheme(http::uri::Scheme::HTTP)
            .authority(authority)
            .path_and_query(
                req.uri()
                    .path_and_query()
                    .unwrap_or(&PathAndQuery::from_static("/"))
                    .to_owned(),
            )
            .build()
            .expect("Failed to build URI");

        let (mut parts, body) = req.into_parts();
        parts.uri = uri;
        let req = Request::from_parts(parts, body);
        process_request(state.clone(), req)
    });

    Http::new()
        .serve_connection(stream, service)
        .with_upgrades()
        .await
}

async fn serve_https<R1, R2, W1, W2>(
    state: ProxyState<R1, R2, W1, W2>,
    stream: tokio_rustls::server::TlsStream<Rewind<Upgraded>>,
) -> Result<(), hyper::Error>
where
    R1: RequestHandler,
    R2: ResponseHandler,
    W1: MessageHandler,
    W2: MessageHandler,
{
    let service = service_fn(|mut req| {
        if req.version() == http::Version::HTTP_11 {
            let authority = req
                .headers()
                .get(http::header::HOST)
                .expect("Host is a required header")
                .to_str()
                .expect("Failed to convert host to str");

            let uri = http::uri::Builder::new()
                .scheme(http::uri::Scheme::HTTPS)
                .authority(authority)
                .path_and_query(
                    req.uri()
                        .path_and_query()
                        .unwrap_or(&PathAndQuery::from_static("/"))
                        .to_owned(),
                )
                .build()
                .expect("Failed to build URI");

            let (mut parts, body) = req.into_parts();
            parts.uri = uri;
            req = Request::from_parts(parts, body)
        };

        process_request(state.clone(), req)
    });
    Http::new()
        .serve_connection(stream, service)
        .with_upgrades()
        .await
}
