mod internal;

pub mod builder;

use crate::{certificate_authority::CertificateAuthority, Error, HttpHandler, MessageHandler};
use builder::AddrListenerServer;
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
///
/// # Examples
///
/// ```rust
/// use hudsucker::ProxyBuilder;
/// # use hudsucker::certificate_authority::RcgenAuthority;
/// # use rustls_pemfile as pemfile;
/// # use tokio_rustls::rustls;
/// #
/// # #[tokio::main]
/// # async fn main() {
/// # let mut private_key_bytes: &[u8] = include_bytes!("../../examples/ca/hudsucker.key");
/// # let mut ca_cert_bytes: &[u8] = include_bytes!("../../examples/ca/hudsucker.cer");
/// # let private_key = rustls::PrivateKey(
/// #     pemfile::pkcs8_private_keys(&mut private_key_bytes)
/// #         .expect("Failed to parse private key")
/// #         .remove(0),
/// # );
/// # let ca_cert = rustls::Certificate(
/// #     pemfile::certs(&mut ca_cert_bytes)
/// #         .expect("Failed to parse CA certificate")
/// #         .remove(0),
/// # );
/// #
/// # let ca = RcgenAuthority::new(private_key, ca_cert, 1_000)
/// #     .expect("Failed to create Certificate Authority");
///
/// // let ca = ...;
///
/// let proxy = ProxyBuilder::new()
///     .with_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
///     .with_rustls_client()
///     .with_ca(ca)
///     .build();
///
/// let (stop, done) = tokio::sync::oneshot::channel();
///
/// tokio::spawn(proxy.start(async {
///     done.await.unwrap_or_default();
/// }));
///
/// // Do something else...
///
/// stop.send(()).unwrap();
/// # }
/// ```
#[derive(Debug)]
pub struct Proxy<C, CA, H, M1, M2>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    M1: MessageHandler,
    M2: MessageHandler,
{
    als: AddrListenerServer,
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

        let server_builder = match self.als {
            AddrListenerServer::Addr(addr) => Server::try_bind(&addr)?
                .http1_preserve_header_case(true)
                .http1_title_case_headers(true),
            AddrListenerServer::Listener(listener) => Server::from_tcp(listener)?
                .http1_preserve_header_case(true)
                .http1_title_case_headers(true),
            AddrListenerServer::Server(server) => *server,
        };

        server_builder
            .serve(make_service)
            .with_graceful_shutdown(shutdown_signal)
            .await
            .map_err(Into::into)
    }
}
