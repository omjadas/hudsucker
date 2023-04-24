use crate::{HttpHandler, WebSocketHandler};

/// A No-op handler.
///
/// When using this handler, HTTP requests and responses and WebSocket messages will not be
/// modified.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct NoopHandler(());

impl NoopHandler {
    pub(crate) fn new() -> Self {
        NoopHandler(())
    }
}

impl HttpHandler for NoopHandler {}
impl WebSocketHandler for NoopHandler {}
