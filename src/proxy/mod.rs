mod internal;

pub mod builder;

use crate::{
    Error, HttpHandler, WebSocketHandler, builder::ProxyBuilder,
    certificate_authority::CertificateAuthority,
};
use builder::{AddrOrListener, WantsAddr};
use hyper::service::service_fn;
use hyper_util::{
    client::legacy::{Builder as ClientBuilder, Client, connect::Connect},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ServerBuilder,
};
use internal::InternalProxy;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_graceful::Shutdown;
use tokio_tungstenite::Connector;
use tracing::error;

/// A proxy server. This must be constructed with a [`ProxyBuilder`].
///
/// # Examples
///
/// ```rust
/// use hudsucker::Proxy;
/// # use hudsucker::{
/// #     certificate_authority::RcgenAuthority,
/// #     rcgen::{Issuer, KeyPair},
/// #     rustls::crypto::aws_lc_rs,
/// # };
/// #
/// # #[cfg(all(feature = "rcgen-ca", feature = "rustls-client"))]
/// # #[tokio::main]
/// # async fn main() {
/// # let key_pair = include_str!("../../examples/ca/hudsucker.key");
/// # let ca_cert = include_str!("../../examples/ca/hudsucker.cer");
/// # let key_pair = KeyPair::from_pem(key_pair).expect("Failed to parse private key");
/// # let issuer =
/// #     Issuer::from_ca_cert_pem(ca_cert, key_pair).expect("Failed to parse CA certificate");
/// #
/// # let ca = RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider());
///
/// // let ca = ...;
///
/// let (stop, done) = tokio::sync::oneshot::channel();
///
/// let proxy = Proxy::builder()
///     .with_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
///     .with_ca(ca)
///     .with_rustls_connector(aws_lc_rs::default_provider())
///     .with_graceful_shutdown(async {
///         done.await.unwrap_or_default();
///     })
///     .build()
///     .expect("Failed to create proxy");
///
/// tokio::spawn(proxy.start());
///
/// // Do something else...
///
/// stop.send(()).unwrap();
/// # }
/// #
/// # #[cfg(not(all(feature = "rcgen-ca", feature = "rustls-client")))]
/// # fn main() {}
/// ```
pub struct Proxy<C, CA, H, W, F> {
    al: AddrOrListener,
    ca: Arc<CA>,
    http_connector: C,
    client: Option<ClientBuilder>,
    http_handler: H,
    websocket_handler: W,
    websocket_connector: Option<Connector>,
    server: Option<ServerBuilder<TokioExecutor>>,
    graceful_shutdown: F,
}

impl Proxy<(), (), (), (), ()> {
    /// Create a new [`ProxyBuilder`].
    pub fn builder() -> ProxyBuilder<WantsAddr> {
        ProxyBuilder::new()
    }
}

impl<C, CA, H, W, F> Proxy<C, CA, H, W, F>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    W: WebSocketHandler,
    F: Future<Output = ()> + Send + 'static,
{
    /// Attempts to start the proxy server.
    ///
    /// # Errors
    ///
    /// This will return an error if the proxy server is unable to be started.
    pub async fn start(self) -> Result<(), Error> {
        let client = self
            .client
            .unwrap_or_else(|| {
                let mut builder = Client::builder(TokioExecutor::new());
                builder
                    .http1_title_case_headers(true)
                    .http1_preserve_header_case(true);
                builder
            })
            .build(self.http_connector);

        let server = self.server.unwrap_or_else(|| {
            let mut builder = ServerBuilder::new(TokioExecutor::new());
            builder
                .http1()
                .title_case_headers(true)
                .preserve_header_case(true);
            builder
        });

        let listener = match self.al {
            AddrOrListener::Addr(addr) => TcpListener::bind(addr).await?,
            AddrOrListener::Listener(listener) => listener,
        };

        let shutdown = Shutdown::new(self.graceful_shutdown);
        let guard = shutdown.guard_weak();

        loop {
            tokio::select! {
                res = listener.accept() => {
                    let (tcp, client_addr) = match res {
                        Ok((tcp, client_addr)) => (tcp, client_addr),
                        Err(e) => {
                            error!("Failed to accept incoming connection: {}", e);
                            continue;
                        }
                    };

                    let client = client.clone();
                    let server = server.clone();
                    let ca = Arc::clone(&self.ca);
                    let http_handler = self.http_handler.clone();
                    let websocket_handler = self.websocket_handler.clone();
                    let websocket_connector = self.websocket_connector.clone();

                    shutdown.spawn_task_fn(move |guard| async move {
                        let conn = server.serve_connection_with_upgrades(
                            TokioIo::new(tcp),
                            service_fn(|req| {
                                InternalProxy {
                                    ca: Arc::clone(&ca),
                                    client: client.clone(),
                                    server: server.clone(),
                                    http_handler: http_handler.clone(),
                                    websocket_handler: websocket_handler.clone(),
                                    websocket_connector: websocket_connector.clone(),
                                    client_addr,
                                }
                                .proxy(req)
                            }),
                        );

                        let mut conn = std::pin::pin!(conn);

                        if let Err(err) = tokio::select! {
                            conn = conn.as_mut() => conn,
                            _ = guard.cancelled() => {
                                conn.as_mut().graceful_shutdown();
                                conn.await
                            }
                        } {
                            error!("Error serving connection: {}", err);
                        }
                    });
                }
                _ = guard.cancelled() => {
                    break;
                }
            }
        }

        shutdown.shutdown().await;

        Ok(())
    }
}
