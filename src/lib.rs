//! Hudsucker is a MITM HTTP/S proxy that allows you to:
//!
//! - Modify HTTP/S requests
//! - Modify HTTP/S responses
//! - Modify websocket messages

mod certificate_authority;
mod error;
mod proxy;
mod rewind;

use hyper::{
    client::HttpConnector,
    service::{make_service_fn, service_fn},
    Body, Client, Request, Response, Server,
};
use hyper_proxy::{Proxy as UpstreamProxy, ProxyConnector};
use hyper_rustls::HttpsConnector;
use proxy::Proxy;
use rustls::ClientConfig;
use std::{convert::Infallible, future::Future, net::SocketAddr};
use tokio_tungstenite::tungstenite::Message;

pub(crate) use rewind::Rewind;

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

/// Enum representing either an HTTP request or response.
#[derive(Debug)]
pub enum RequestOrResponse {
    Request(Request<Body>),
    Response(Response<Body>),
}

/// Handler for HTTP requests.
///
/// The handler will be called for each HTTP request. It can either return a modified request, or a
/// response. If a request is returned, it will be sent to the upstream server. If a response is
/// returned, it will be sent to the client.
pub trait RequestHandler:
    FnMut(Request<Body>) -> RequestOrResponse + Send + Sync + Clone + 'static
{
}
impl<T> RequestHandler for T where
    T: FnMut(Request<Body>) -> RequestOrResponse + Send + Sync + Clone + 'static
{
}

/// Handler for HTTP responses.
///
/// The handler will be called for each HTTP response. It can modify a response before it is
/// forwarded to the client.
pub trait ResponseHandler:
    FnMut(Response<Body>) -> Response<Body> + Send + Sync + Clone + 'static
{
}
impl<T> ResponseHandler for T where
    T: FnMut(Response<Body>) -> Response<Body> + Send + Sync + Clone + 'static
{
}

/// Handler for websocket messages.
///
/// The handler will be called for each websocket message. It can return an optional modified
/// message. If None is returned the message will not be forwarded.
pub trait MessageHandler:
    FnMut(Message) -> Option<Message> + Send + Sync + Clone + 'static
{
}
impl<T> MessageHandler for T where
    T: FnMut(Message) -> Option<Message> + Send + Sync + Clone + 'static
{
}

/// Configuration for the proxy server.
///
/// The proxy server can be configured with a number of options.
#[derive(Clone)]
pub struct ProxyConfig<F: Future<Output = ()>, R1, R2, W1, W2>
where
    R1: RequestHandler,
    R2: ResponseHandler,
    W1: MessageHandler,
    W2: MessageHandler,
{
    /// The address to listen on.
    pub listen_addr: SocketAddr,
    /// A future that once resolved will cause the proxy server to shut down.
    pub shutdown_signal: F,
    /// The certificate authority to use.
    pub ca: CertificateAuthority,
    /// A handler for HTTP requests.
    pub request_handler: R1,
    /// A handler for HTTP responses.
    pub response_handler: R2,
    /// A handler for websocket messages sent from the client to the upstream server.
    pub incoming_message_handler: W1,
    /// A handler for websocket messages sent from the upstream server to the client.
    pub outgoing_message_handler: W2,
    /// The upstream proxy to use.
    pub upstream_proxy: Option<UpstreamProxy>,
}

/// Attempts to start a proxy server using the provided configuration options.
///
/// This will fail if the proxy server is unable to be started.
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
                Proxy {
                    ca: ca.clone(),
                    client: client.clone(),
                    request_handler: request_handler.clone(),
                    response_handler: response_handler.clone(),
                    incoming_message_handler: incoming_message_handler.clone(),
                    outgoing_message_handler: outgoing_message_handler.clone(),
                }
                .proxy(req)
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
