mod internal;

pub mod builder;

use crate::{certificate_authority::CertificateAuthority, Error, HttpHandler, MessageHandler};
use hyper::{
    client::connect::Connect,
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Client, Server,
};
use internal::InternalProxy;
use std::{convert::Infallible, future::Future, net::SocketAddr, sync::Arc};

pub use builder::ProxyBuilder;

#[derive(Debug)]
pub struct Proxy<C, CA, H, M1, M2>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    M1: MessageHandler,
    M2: MessageHandler,
{
    listen_addr: SocketAddr,
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

        Server::bind(&self.listen_addr)
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .serve(make_service)
            .with_graceful_shutdown(shutdown_signal)
            .await
            .map_err(|err| err.into())
    }
}

impl<C, CA, H, M1, M2> Clone for Proxy<C, CA, H, M1, M2>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    M1: MessageHandler,
    M2: MessageHandler,
{
    fn clone(&self) -> Self {
        Proxy {
            listen_addr: self.listen_addr,
            ca: Arc::clone(&self.ca),
            client: self.client.clone(),
            http_handler: self.http_handler.clone(),
            incoming_message_handler: self.incoming_message_handler.clone(),
            outgoing_message_handler: self.outgoing_message_handler.clone(),
        }
    }
}
