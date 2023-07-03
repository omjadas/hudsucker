#![cfg_attr(docsrs, feature(doc_cfg))]

//! Hudsucker is a MITM HTTP/S proxy that allows you to:
//!
//! - Modify HTTP/S requests
//! - Modify HTTP/S responses
//! - Modify WebSocket messages
//!
//! ## Features
//!
//! - `decoder`: Enables [`decode_request`] and [`decode_response`] helpers (enabled by default).
//! - `full`: Enables all features.
//! - `http2`: Enables HTTP/2 support.
//! - `native-tls-client`: Enables [`ProxyBuilder::with_native_tls_client`].
//! - `openssl-ca`: Enables [`certificate_authority::OpensslAuthority`].
//! - `rcgen-ca`: Enables [`certificate_authority::RcgenAuthority`] (enabled by default).
//! - `rustls-client`: Enables [`ProxyBuilder::with_rustls_client`] (enabled by default).

#[cfg(feature = "decoder")]
mod decoder;
mod error;
mod noop;
mod proxy;
mod rewind;

pub mod certificate_authority;

use futures::{Sink, SinkExt, Stream, StreamExt};
use hyper::{Body, Request, Response, StatusCode, Uri};
use std::net::SocketAddr;
use tokio_tungstenite::tungstenite::{self, Message};
use tracing::error;

pub(crate) use rewind::Rewind;

pub use async_trait;
pub use futures;
pub use hyper;
#[cfg(feature = "openssl-ca")]
pub use openssl;
pub use tokio_rustls::rustls;
pub use tokio_tungstenite;

#[cfg(feature = "decoder")]
pub use decoder::{decode_request, decode_response};
pub use error::Error;
pub use noop::*;
pub use proxy::*;

/// Enum representing either an HTTP request or response.
#[derive(Debug)]
pub enum RequestOrResponse {
    /// HTTP Request
    Request(Request<Body>),
    /// HTTP Response
    Response(Response<Body>),
}

impl From<Request<Body>> for RequestOrResponse {
    fn from(req: Request<Body>) -> Self {
        Self::Request(req)
    }
}

impl From<Response<Body>> for RequestOrResponse {
    fn from(res: Response<Body>) -> Self {
        Self::Response(res)
    }
}

/// Context for HTTP requests and responses.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct HttpContext {
    /// Address of the client that is sending the request.
    pub client_addr: SocketAddr,
}

/// Context for websocket messages.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum WebSocketContext {
    #[non_exhaustive]
    ClientToServer {
        /// Address of the client.
        src: SocketAddr,
        /// URI of the server.
        dst: Uri,
    },
    #[non_exhaustive]
    ServerToClient {
        /// URI of the server.
        src: Uri,
        /// Address of the client.
        dst: SocketAddr,
    },
}

/// Handler for HTTP requests and responses.
///
/// Each request/response pair is passed to the same instance of the handler.
#[async_trait::async_trait]
pub trait HttpHandler: Clone + Send + Sync + 'static {
    /// This handler will be called for each HTTP request. It can either return a modified request,
    /// or a response. If a request is returned, it will be sent to the upstream server. If a
    /// response is returned, it will be sent to the client.
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        req.into()
    }

    /// This handler will be called for each HTTP response. It can modify a response before it is
    /// forwarded to the client.
    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        res
    }

    /// This handler will be called if a proxy request fails. Default response is a 502 Bad Gateway.
    async fn handle_error(&mut self, _ctx: &HttpContext, err: hyper::Error) -> Response<Body> {
        error!("Failed to forward request: {}", err);
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::empty())
            .expect("Failed to build response")
    }

    /// Whether a CONNECT request should be intercepted. Defaults to `true` for all requests.
    async fn should_intercept(&mut self, _ctx: &HttpContext, _req: &Request<Body>) -> bool {
        true
    }
}

/// Handler for WebSocket messages.
///
/// Messages sent over the same WebSocket Stream are passed to the same instance of the handler.
#[async_trait::async_trait]
pub trait WebSocketHandler: Clone + Send + Sync + 'static {
    /// This handler is responsible for forwarding WebSocket messages from a Stream to a Sink and
    /// recovering from any potential errors.
    async fn handle_websocket(
        mut self,
        ctx: WebSocketContext,
        mut stream: impl Stream<Item = Result<Message, tungstenite::Error>> + Unpin + Send + 'static,
        mut sink: impl Sink<Message, Error = tungstenite::Error> + Unpin + Send + 'static,
    ) {
        while let Some(message) = stream.next().await {
            match message {
                Ok(message) => {
                    let Some(message) = self.handle_message(&ctx, message).await else {
                        continue;
                    };

                    match sink.send(message).await {
                        Err(tungstenite::Error::ConnectionClosed) => (),
                        Err(e) => error!("WebSocket send error: {}", e),
                        _ => (),
                    }
                }
                Err(e) => {
                    error!("WebSocket message error: {}", e);

                    match sink.send(Message::Close(None)).await {
                        Err(tungstenite::Error::ConnectionClosed) => (),
                        Err(e) => error!("WebSocket close error: {}", e),
                        _ => (),
                    };

                    break;
                }
            }
        }
    }

    /// This handler will be called for each WebSocket message. It can return an optional modified
    /// message. If None is returned the message will not be forwarded.
    async fn handle_message(
        &mut self,
        _ctx: &WebSocketContext,
        message: Message,
    ) -> Option<Message> {
        Some(message)
    }
}
