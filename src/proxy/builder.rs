use crate::{
    Body, HttpHandler, NoopHandler, Proxy, WebSocketHandler,
    certificate_authority::CertificateAuthority,
};
use hyper_util::{
    client::legacy::{Client, connect::Connect},
    rt::TokioExecutor,
    server::conn::auto::Builder,
};
use std::{
    future::{Pending, pending},
    net::SocketAddr,
    sync::Arc,
};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_rustls::rustls::{ClientConfig, crypto::CryptoProvider};
use tokio_tungstenite::Connector;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[cfg(feature = "native-tls-client")]
    #[error("{0}")]
    NativeTls(#[from] hyper_tls::native_tls::Error),
    #[cfg(feature = "rustls-client")]
    #[error("{0}")]
    Rustls(#[from] tokio_rustls::rustls::Error),
}

/// A builder for creating a [`Proxy`].
///
/// # Examples
///
/// ```rust
/// # #[cfg(all(feature = "rcgen-ca", feature = "rustls-client"))]
/// # {
/// use hudsucker::Proxy;
/// # use hudsucker::{
/// #     certificate_authority::RcgenAuthority,
/// #     rcgen::{CertificateParams, KeyPair},
/// #     rustls::crypto::aws_lc_rs,
/// # };
/// #
/// # let key_pair = include_str!("../../examples/ca/hudsucker.key");
/// # let ca_cert = include_str!("../../examples/ca/hudsucker.cer");
/// # let key_pair = KeyPair::from_pem(key_pair).expect("Failed to parse private key");
/// # let ca_cert = CertificateParams::from_ca_cert_pem(ca_cert)
/// #     .expect("Failed to parse CA certificate")
/// #     .self_signed(&key_pair)
/// #     .expect("Failed to sign CA certificate");
/// #
/// # let ca = RcgenAuthority::new(key_pair, ca_cert, 1_000, aws_lc_rs::default_provider());
///
/// // let ca = ...;
///
/// let proxy = Proxy::builder()
///     .with_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
///     .with_ca(ca)
///     .with_rustls_client(aws_lc_rs::default_provider())
///     .build()
///     .expect("Failed to create proxy");
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProxyBuilder<T>(T);

/// Builder state that needs either an address or a TCP listener.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WantsAddr(());

#[derive(Debug)]
pub(crate) enum AddrOrListener {
    Addr(SocketAddr),
    Listener(TcpListener),
}

impl ProxyBuilder<WantsAddr> {
    /// Create a new [`ProxyBuilder`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the address to listen on.
    pub fn with_addr(self, addr: SocketAddr) -> ProxyBuilder<WantsCa> {
        ProxyBuilder(WantsCa {
            al: AddrOrListener::Addr(addr),
        })
    }

    /// Set a listener to use for the proxy server.
    pub fn with_listener(self, listener: TcpListener) -> ProxyBuilder<WantsCa> {
        ProxyBuilder(WantsCa {
            al: AddrOrListener::Listener(listener),
        })
    }
}

impl Default for ProxyBuilder<WantsAddr> {
    fn default() -> Self {
        ProxyBuilder(WantsAddr(()))
    }
}

/// Builder state that needs a certificate authority.
#[derive(Debug)]
pub struct WantsCa {
    al: AddrOrListener,
}

impl ProxyBuilder<WantsCa> {
    /// Set the certificate authority to use.
    pub fn with_ca<CA: CertificateAuthority>(self, ca: CA) -> ProxyBuilder<WantsClient<CA>> {
        ProxyBuilder(WantsClient { al: self.0.al, ca })
    }
}

/// Builder state that needs a client.
#[derive(Debug)]
pub struct WantsClient<CA> {
    al: AddrOrListener,
    ca: CA,
}

impl<CA> ProxyBuilder<WantsClient<CA>> {
    /// Use a hyper-rustls connector.
    #[cfg(feature = "rustls-client")]
    pub fn with_rustls_client(
        self,
        provider: CryptoProvider,
    ) -> ProxyBuilder<WantsHandlers<CA, impl Connect + Clone, NoopHandler, NoopHandler, Pending<()>>>
    {
        use hyper_rustls::ConfigBuilderExt;

        let rustls_config = match ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
        {
            Ok(config) => config.with_webpki_roots().with_no_client_auth(),
            Err(e) => {
                return ProxyBuilder(WantsHandlers {
                    al: self.0.al,
                    ca: self.0.ca,
                    client: Err(Error::from(e)),
                    http_handler: NoopHandler::new(),
                    websocket_handler: NoopHandler::new(),
                    websocket_connector: None,
                    server: None,
                    graceful_shutdown: pending(),
                });
            }
        };

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(rustls_config.clone())
            .https_or_http()
            .enable_http1();

        #[cfg(feature = "http2")]
        let https = https.enable_http2();

        let https = https.build();

        ProxyBuilder(WantsHandlers {
            al: self.0.al,
            ca: self.0.ca,
            client: Ok(Client::builder(TokioExecutor::new())
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(https)),
            http_handler: NoopHandler::new(),
            websocket_handler: NoopHandler::new(),
            websocket_connector: Some(Connector::Rustls(Arc::new(rustls_config))),
            server: None,
            graceful_shutdown: pending(),
        })
    }

    /// Use a hyper-tls connector.
    #[cfg(feature = "native-tls-client")]
    pub fn with_native_tls_client(
        self,
    ) -> ProxyBuilder<WantsHandlers<CA, impl Connect + Clone, NoopHandler, NoopHandler, Pending<()>>>
    {
        use hyper_util::client::legacy::connect::HttpConnector;

        let tls_connector = match hyper_tls::native_tls::TlsConnector::new() {
            Ok(tls_connector) => tls_connector,
            Err(e) => {
                return ProxyBuilder(WantsHandlers {
                    al: self.0.al,
                    ca: self.0.ca,
                    client: Err(Error::from(e)),
                    http_handler: NoopHandler::new(),
                    websocket_handler: NoopHandler::new(),
                    websocket_connector: None,
                    server: None,
                    graceful_shutdown: pending(),
                });
            }
        };

        let tokio_tls_connector = tokio_native_tls::TlsConnector::from(tls_connector.clone());
        let https = hyper_tls::HttpsConnector::from((HttpConnector::new(), tokio_tls_connector));

        ProxyBuilder(WantsHandlers {
            al: self.0.al,
            ca: self.0.ca,
            client: Ok(Client::builder(TokioExecutor::new())
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(https)),
            http_handler: NoopHandler::new(),
            websocket_handler: NoopHandler::new(),
            websocket_connector: Some(Connector::NativeTls(tls_connector)),
            server: None,
            graceful_shutdown: pending(),
        })
    }

    /// Use a custom client.
    pub fn with_client<C>(
        self,
        client: Client<C, Body>,
    ) -> ProxyBuilder<WantsHandlers<CA, C, NoopHandler, NoopHandler, Pending<()>>>
    where
        C: Connect + Clone + Send + Sync + 'static,
    {
        ProxyBuilder(WantsHandlers {
            al: self.0.al,
            ca: self.0.ca,
            client: Ok(client),
            http_handler: NoopHandler::new(),
            websocket_handler: NoopHandler::new(),
            websocket_connector: None,
            server: None,
            graceful_shutdown: pending(),
        })
    }
}

/// Builder state that can take additional handlers.
pub struct WantsHandlers<CA, C, H, W, F> {
    al: AddrOrListener,
    ca: CA,
    client: Result<Client<C, Body>, Error>,
    http_handler: H,
    websocket_handler: W,
    websocket_connector: Option<Connector>,
    server: Option<Builder<TokioExecutor>>,
    graceful_shutdown: F,
}

impl<CA, C, H, W, F> ProxyBuilder<WantsHandlers<CA, C, H, W, F>> {
    /// Set the HTTP handler.
    pub fn with_http_handler<H2: HttpHandler>(
        self,
        http_handler: H2,
    ) -> ProxyBuilder<WantsHandlers<CA, C, H2, W, F>> {
        ProxyBuilder(WantsHandlers {
            al: self.0.al,
            ca: self.0.ca,
            client: self.0.client,
            http_handler,
            websocket_handler: self.0.websocket_handler,
            websocket_connector: self.0.websocket_connector,
            server: self.0.server,
            graceful_shutdown: self.0.graceful_shutdown,
        })
    }

    /// Set the WebSocket handler.
    pub fn with_websocket_handler<W2: WebSocketHandler>(
        self,
        websocket_handler: W2,
    ) -> ProxyBuilder<WantsHandlers<CA, C, H, W2, F>> {
        ProxyBuilder(WantsHandlers {
            al: self.0.al,
            ca: self.0.ca,
            client: self.0.client,
            http_handler: self.0.http_handler,
            websocket_handler,
            websocket_connector: self.0.websocket_connector,
            server: self.0.server,
            graceful_shutdown: self.0.graceful_shutdown,
        })
    }

    /// Set the connector to use when connecting to WebSocket servers.
    pub fn with_websocket_connector(self, connector: Connector) -> Self {
        ProxyBuilder(WantsHandlers {
            websocket_connector: Some(connector),
            ..self.0
        })
    }

    /// Set a custom server builder to use for the proxy server.
    pub fn with_server(self, server: Builder<TokioExecutor>) -> Self {
        ProxyBuilder(WantsHandlers {
            server: Some(server),
            ..self.0
        })
    }

    /// Set a future that when ready will gracefully shutdown the proxy server.
    pub fn with_graceful_shutdown<F2: Future<Output = ()> + Send + 'static>(
        self,
        graceful_shutdown: F2,
    ) -> ProxyBuilder<WantsHandlers<CA, C, H, W, F2>> {
        ProxyBuilder(WantsHandlers {
            al: self.0.al,
            ca: self.0.ca,
            client: self.0.client,
            http_handler: self.0.http_handler,
            websocket_handler: self.0.websocket_handler,
            websocket_connector: self.0.websocket_connector,
            server: self.0.server,
            graceful_shutdown,
        })
    }

    /// Build the proxy.
    pub fn build(self) -> Result<Proxy<C, CA, H, W, F>, crate::Error> {
        Ok(Proxy {
            al: self.0.al,
            ca: Arc::new(self.0.ca),
            client: self.0.client?,
            http_handler: self.0.http_handler,
            websocket_handler: self.0.websocket_handler,
            websocket_connector: self.0.websocket_connector,
            server: self.0.server,
            graceful_shutdown: self.0.graceful_shutdown,
        })
    }
}
