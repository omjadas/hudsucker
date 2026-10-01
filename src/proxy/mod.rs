mod internal;
mod listener;

pub mod builder;

use crate::{
    Error,
    HttpHandler,
    WebSocketHandler,
    builder::ProxyBuilder,
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
use listener::Listener;
use std::{error::Error as StdError, sync::Arc};
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

        let proxy = InternalProxy {
            ca: self.ca,
            client,
            server,
            http_handler: self.http_handler,
            websocket_handler: self.websocket_handler,
            websocket_connector: self.websocket_connector,
            client_addr: ([0, 0, 0, 0], 0).into(),
        };
        match self.al {
            AddrOrListener::Addr(addr) => {
                serve_listener(
                    TcpListener::bind(addr).await?,
                    proxy,
                    self.graceful_shutdown,
                )
                .await
            }
            AddrOrListener::Listener(listener) => {
                serve_listener(listener, proxy, self.graceful_shutdown).await
            }
            #[cfg(unix)]
            AddrOrListener::UnixListener(listener) => {
                serve_listener(listener, proxy, self.graceful_shutdown).await
            }
        }
    }
}

async fn serve_listener<L, C, CA, H, W, F>(
    listener: L,
    proxy: InternalProxy<C, CA, H, W>,
    graceful_shutdown: F,
) -> Result<(), Error>
where
    L: Listener,
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    W: WebSocketHandler,
    F: Future<Output = ()> + Send + 'static,
{
    let shutdown = Shutdown::new(graceful_shutdown);
    let guard = shutdown.guard_weak();
    loop {
        tokio::select! {
            res = listener.accept() => {
                let (stream, client_addr) = match res {
                    Ok(connection) => connection,
                    Err(e) => {
                        error!(error = &e as &dyn StdError, "Failed to accept incoming connection");
                        continue;
                    }
                };
                let mut proxy = proxy.clone();
                proxy.client_addr = client_addr;
                let server = proxy.server.clone();
                shutdown.spawn_task_fn(move |guard| async move {
                    let conn = server.serve_connection_with_upgrades(
                        TokioIo::new(stream),
                        service_fn(move |req| proxy.clone().proxy(req)),
                    );
                    let mut conn = std::pin::pin!(conn);
                    if let Err(err) = tokio::select! {
                        conn = conn.as_mut() => conn,
                        _ = guard.cancelled() => {
                            conn.as_mut().graceful_shutdown();
                            conn.await
                        }
                    } {
                        error!(error = &err, "Error serving connection");
                    }
                });
            }
            _ = guard.cancelled() => break,
        }
    }
    shutdown.shutdown().await;
    Ok(())
}
