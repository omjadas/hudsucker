mod internal;

pub mod builder;

use crate::{certificate_authority::CertificateAuthority, Error, HttpHandler, MessageHandler};
use builder::AddrOrListener;
use hyper::{
    client::connect::Connect,
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Client, Server,
};
use internal::InternalProxy;
use std::{convert::Infallible, future::Future, sync::Arc};

pub use builder::ProxyBuilder;

/// A proxy server. This must be constructed with a [`ProxyBuilder`].
#[derive(Debug)]
pub struct Proxy<C, CA, H, M1, M2>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    M1: MessageHandler,
    M2: MessageHandler,
{
    addr_or_listener: AddrOrListener,
    ca: Arc<CA>,
    client: Client<C>,
    http_handler: H,
    incoming_message_handler: M1,
    outgoing_message_handler: M2,
}

impl<C, CA, H, M1, M2> Proxy<C, CA, H, M1, M2>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    M1: MessageHandler,
    M2: MessageHandler,
{
    /// Attempts to start the proxy server.
    ///
    /// # Errors
    ///
    /// This will return an error if the proxy server is unable to be started.
    pub async fn start<F: Future<Output = ()>>(self, shutdown_signal: F) -> Result<(), Error> {
        let make_service = make_service_fn(move |conn: &AddrStream| {
            let client = self.client.clone();
            let ca = Arc::clone(&self.ca);
            let http_handler = self.http_handler.clone();
            let incoming_message_handler = self.incoming_message_handler.clone();
            let outgoing_message_handler = self.outgoing_message_handler.clone();
            let client_addr = conn.remote_addr();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    InternalProxy {
                        ca: Arc::clone(&ca),
                        client: client.clone(),
                        http_handler: http_handler.clone(),
                        incoming_message_handler: incoming_message_handler.clone(),
                        outgoing_message_handler: outgoing_message_handler.clone(),
                        client_addr,
                    }
                    .proxy(req)
                }))
            }
        });

        let server_builder = match self.addr_or_listener {
            AddrOrListener::Addr(addr) => Server::try_bind(&addr),
            AddrOrListener::Listener(listener) => Server::from_tcp(listener),
        }?;

        server_builder
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .serve(make_service)
            .with_graceful_shutdown(shutdown_signal)
            .await
            .map_err(Into::into)
    }
}
