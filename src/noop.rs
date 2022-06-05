use crate::{HttpContext, HttpHandler, RequestOrResponse, WebSocketContext, WebSocketHandler};
use async_trait::async_trait;
use hyper::{Body, Request, Response};
use tokio_tungstenite::tungstenite::Message;

/// A No-op handler.
///
/// When using this handler, HTTP requests and responses and websocket messages will not be
/// modified.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct NoopHandler(());

impl NoopHandler {
    pub(crate) fn new() -> Self {
        NoopHandler(())
    }
}

#[async_trait]
impl HttpHandler for NoopHandler {
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

#[async_trait]
impl WebSocketHandler for NoopHandler {
    async fn handle_message(&mut self, _ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        Some(msg)
    }
}
