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

pub use async_trait;
pub use certificate_authority::CertificateAuthority;
pub use error::Error;
pub use hyper;
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

/// Handler for HTTP requests and responses.
///
/// Each request/response pair is passed to the same instance of the handler.
#[async_trait::async_trait]
pub trait RequestResponseHandler: Send + Sync + Clone + 'static {
    /// The handler will be called for each HTTP request. It can either return a modified request,
    /// or a response. If a request is returned, it will be sent to the upstream server. If a
    /// response is returned, it will be sent to the client.
    async fn handle_request(&mut self, request: Request<Body>) -> RequestOrResponse;

    /// The handler will be called for each HTTP response. It can modify a response before it is
    /// forwarded to the client.
    async fn handle_response(&mut self, request: Response<Body>) -> Response<Body>;
}

/// Handler for websocket messages.
///
/// Messages sent over the same websocket stream are passed to the same instance of the handler.
#[async_trait::async_trait]
pub trait MessageHandler: Send + Sync + Clone + 'static {
    /// The handler will be called for each websocket message. It can return an optional modified
    /// message. If None is returned the message will not be forwarded.
    async fn handle_message(&mut self, message: Message) -> Option<Message>;
}

/// Configuration for the proxy server.
///
/// The proxy server can be configured with a number of options.
#[derive(Clone)]
pub struct ProxyConfig<F: Future<Output = ()>, R, M1, M2>
where
    R: RequestResponseHandler,
    M1: MessageHandler,
    M2: MessageHandler,
{
    /// The address to listen on.
    pub listen_addr: SocketAddr,
    /// A future that once resolved will cause the proxy server to shut down.
    pub shutdown_signal: F,
    /// The certificate authority to use.
    pub ca: CertificateAuthority,
    /// A handler for HTTP requests and responses.
    pub request_response_handler: R,
    /// A handler for websocket messages sent from the client to the upstream server.
    pub incoming_message_handler: M1,
    /// A handler for websocket messages sent from the upstream server to the client.
    pub outgoing_message_handler: M2,
    /// The upstream proxy to use.
    pub upstream_proxy: Option<UpstreamProxy>,
}

/// Attempts to start a proxy server using the provided configuration options.
///
/// This will fail if the proxy server is unable to be started.
pub async fn start_proxy<F, R, M1, M2>(
    ProxyConfig {
        listen_addr,
        shutdown_signal,
        ca,
        request_response_handler,
        incoming_message_handler,
        outgoing_message_handler,
        upstream_proxy,
    }: ProxyConfig<F, R, M1, M2>,
) -> Result<(), Error>
where
    F: Future<Output = ()>,
    R: RequestResponseHandler,
    M1: MessageHandler,
    M2: MessageHandler,
{
    let client = gen_client(upstream_proxy);

    let make_service = make_service_fn(move |_| {
        let client = client.clone();
        let ca = ca.clone();
        let request_response_handler = request_response_handler.clone();
        let incoming_message_handler = incoming_message_handler.clone();
        let outgoing_message_handler = outgoing_message_handler.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                Proxy {
                    ca: ca.clone(),
                    client: client.clone(),
                    request_response_handler: request_response_handler.clone(),
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
