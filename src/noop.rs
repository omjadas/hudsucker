use crate::{HttpContext, HttpHandler, RequestOrResponse, WebSocketContext, WebSocketHandler};
use async_trait::async_trait;
use hyper::{Body, Request, Response};
use tokio_tungstenite::tungstenite::Message;

/// A No-op handler for HTTP.
///
/// When using this handler, requests and responses will not be modified.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct NoopHttpHandler(());

impl NoopHttpHandler {
    pub(crate) fn new() -> Self {
        NoopHttpHandler(())
    }
}

#[async_trait]
impl HttpHandler for NoopHttpHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        RequestOrResponse::Request(req)
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        res
    }
}

/// A No-op handler for websocket messages.
///
/// When using this handler, websocket messages will not be modified.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct NoopWebSocketHandler(());

impl NoopWebSocketHandler {
    pub(crate) fn new() -> Self {
        NoopWebSocketHandler(())
    }
}

#[async_trait]
impl WebSocketHandler for NoopWebSocketHandler {
    async fn handle_message(&mut self, _ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        Some(msg)
    }
}
