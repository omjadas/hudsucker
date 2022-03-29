#![cfg_attr(docsrs, feature(doc_cfg))]

//! Hudsucker is a MITM HTTP/S proxy that allows you to:
//!
//! - Modify HTTP/S requests
//! - Modify HTTP/S responses
//! - Modify websocket messages
//!
//! ## Features
//!
//! - `full`: Enables all features.
//! - `http2`: Enables HTTP/2 support.
//! - `native-tls-client`: Enables [`ProxyBuilder::with_native_tls_client`].
//! - `openssl-certs`: Enables [`certificate_authority::OpensslAuthority`].
//! - `rcgen-certs`: Enables [`certificate_authority::RcgenAuthority`] (enabled by default).
//! - `rustls-client`: Enables [`ProxyBuilder::with_rustls_client`] (enabled by default).

mod decoder;
mod error;
mod noop;
mod proxy;
mod rewind;

pub mod certificate_authority;

use hyper::{Body, Request, Response, Uri};
use std::net::SocketAddr;
use tokio_tungstenite::tungstenite::Message;

pub(crate) use rewind::Rewind;

pub use async_trait;
pub use hyper;
#[cfg(feature = "openssl")]
pub use openssl;
pub use tokio_rustls::rustls;
pub use tokio_tungstenite::tungstenite;

pub use decoder::{decode_request, decode_response};
pub use error::Error;
pub use noop::*;
pub use proxy::*;

/// Enum representing either an HTTP request or response.
#[derive(Debug)]
pub enum RequestOrResponse {
    Request(Request<Body>),
    Response(Response<Body>),
}

/// Context for HTTP requests and responses.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HttpContext {
    /// Address of the client that is sending the request.
    pub client_addr: SocketAddr,
}

/// Context for websocket messages.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MessageContext {
    /// Address of the client.
    pub client_addr: SocketAddr,
    /// URI of the server.
    pub server_uri: Uri,
}

/// Handler for HTTP requests and responses.
///
/// Each request/response pair is passed to the same instance of the handler.
#[async_trait::async_trait]
pub trait HttpHandler: Clone + Send + Sync + 'static {
    /// The handler will be called for each HTTP request. It can either return a modified request,
    /// or a response. If a request is returned, it will be sent to the upstream server. If a
    /// response is returned, it will be sent to the client.
    async fn handle_request(
        &mut self,
        context: &HttpContext,
        request: Request<Body>,
    ) -> RequestOrResponse;

    /// The handler will be called for each HTTP response. It can modify a response before it is
    /// forwarded to the client.
    async fn handle_response(
        &mut self,
        context: &HttpContext,
        response: Response<Body>,
    ) -> Response<Body>;
}

/// Handler for websocket messages.
///
/// Messages sent over the same websocket stream are passed to the same instance of the handler.
#[async_trait::async_trait]
pub trait MessageHandler: Clone + Send + Sync + 'static {
    /// The handler will be called for each websocket message. It can return an optional modified
    /// message. If None is returned the message will not be forwarded.
    async fn handle_message(
        &mut self,
        context: &MessageContext,
        message: Message,
    ) -> Option<Message>;
}
