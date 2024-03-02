use crate::{
    certificate_authority::CertificateAuthority, Body, HttpHandler, NoopHandler, Proxy,
    WebSocketHandler,
};
#[cfg(feature = "rustls-client")]
use hyper_rustls::{HttpsConnector as RustlsConnector, HttpsConnectorBuilder};
#[cfg(feature = "native-tls-client")]
use hyper_tls::HttpsConnector as NativeTlsConnector;
use hyper_util::{
    client::legacy::{
        connect::{Connect, HttpConnector},
        Client,
    },
    rt::TokioExecutor,
    server::conn::auto::Builder,
};
use std::{
    future::{pending, Future, Pending},
    net::SocketAddr,
    sync::Arc,
};
use tokio::net::TcpListener;
use tokio_tungstenite::Connector;

/// A builder for creating a [`Proxy`].
///
/// # Examples
///
/// ```rust
/// # #[cfg(all(feature = "rcgen-ca", feature = "rustls-client"))]
/// # {
/// use hudsucker::Proxy;
/// # use hudsucker::certificate_authority::RcgenAuthority;
/// # use rustls_pemfile as pemfile;
/// # use tokio_rustls::rustls;
/// #
/// # let mut private_key_bytes: &[u8] = include_bytes!("../../examples/ca/hudsucker.key");
/// # let mut ca_cert_bytes: &[u8] = include_bytes!("../../examples/ca/hudsucker.cer");
/// # let private_key = rustls::PrivateKey(
/// #     pemfile::pkcs8_private_keys(&mut private_key_bytes)
/// #         .next()
/// #         .unwrap()
/// #         .expect("Failed to parse private key")
/// #         .secret_pkcs8_der()
/// #         .to_vec(),
/// # );
/// # let ca_cert = rustls::Certificate(
/// #     pemfile::certs(&mut ca_cert_bytes)
/// #         .next()
/// #         .unwrap()
/// #         .expect("Failed to parse CA certificate")
/// #         .to_vec(),
/// # );
/// #
/// # let ca = RcgenAuthority::new(private_key, ca_cert, 1_000)
/// #     .expect("Failed to create Certificate Authority");
///
/// // let ca = ...;
///
/// let proxy = Proxy::builder()
///     .with_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
///     .with_rustls_client()
///     .with_ca(ca)
///     .build();
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
    pub fn with_addr(self, addr: SocketAddr) -> ProxyBuilder<WantsClient> {
        ProxyBuilder(WantsClient {
            al: AddrOrListener::Addr(addr),
        })
    }

    /// Set a listener to use for the proxy server.
    pub fn with_listener(self, listener: TcpListener) -> ProxyBuilder<WantsClient> {
        ProxyBuilder(WantsClient {
            al: AddrOrListener::Listener(listener),
        })
    }
}

impl Default for ProxyBuilder<WantsAddr> {
    fn default() -> Self {
        ProxyBuilder(WantsAddr(()))
    }
}

/// Builder state that needs a client.
#[derive(Debug)]
pub struct WantsClient {
    al: AddrOrListener,
}

impl ProxyBuilder<WantsClient> {
    /// Use a hyper-rustls connector.
    // #[cfg(feature = "rustls-client")]
    // #[cfg_attr(docsrs, doc(cfg(feature = "rustls-client")))]
    // pub fn with_rustls_client(self) -> ProxyBuilder<WantsCa<RustlsConnector<HttpConnector>>> {
    //     let https = HttpsConnectorBuilder::new()
    //         .with_webpki_roots()
    //         .https_or_http()
    //         .enable_http1();

    //     #[cfg(feature = "http2")]
    //     let https = https.enable_http2();

    //     let https = https.build();

    //     ProxyBuilder(WantsCa {
    //         al: self.0.al,
    //         client: Client::builder(TokioExecutor::new())
    //             .http1_title_case_headers(true)
    //             .http1_preserve_header_case(true)
    //             .build(https),
    //     })
    // }

    /// Use a hyper-tls connector.
    #[cfg(feature = "native-tls-client")]
    #[cfg_attr(docsrs, doc(cfg(feature = "native-tls-client")))]
    pub fn with_native_tls_client(
        self,
    ) -> ProxyBuilder<WantsCa<NativeTlsConnector<HttpConnector>>> {
        let https = NativeTlsConnector::new();

        ProxyBuilder(WantsCa {
            al: self.0.al,
            client: Client::builder(TokioExecutor::new())
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(https),
        })
    }

    /// Use a custom client.
    pub fn with_client<C>(self, client: Client<C, Body>) -> ProxyBuilder<WantsCa<C>>
    where
        C: Connect + Clone + Send + Sync + 'static,
    {
        ProxyBuilder(WantsCa {
            al: self.0.al,
            client,
        })
    }
}

/// Builder state that needs a certificate authority.
#[derive(Debug)]
pub struct WantsCa<C> {
    al: AddrOrListener,
    client: Client<C, Body>,
}

impl<C> ProxyBuilder<WantsCa<C>> {
    /// Set the certificate authority to use.
    pub fn with_ca<CA: CertificateAuthority>(
        self,
        ca: CA,
    ) -> ProxyBuilder<WantsHandlers<C, CA, NoopHandler, NoopHandler, Pending<()>>> {
        ProxyBuilder(WantsHandlers {
            al: self.0.al,
            client: self.0.client,
            ca,
            http_handler: NoopHandler::new(),
            websocket_handler: NoopHandler::new(),
            websocket_connector: None,
            server: None,
            graceful_shutdown: pending(),
        })
    }
}

/// Builder state that can take additional handlers.
pub struct WantsHandlers<C, CA, H, W, F> {
    al: AddrOrListener,
    client: Client<C, Body>,
    ca: CA,
    http_handler: H,
    websocket_handler: W,
    websocket_connector: Option<Connector>,
    server: Option<Builder<TokioExecutor>>,
    graceful_shutdown: F,
}

impl<C, CA, H, W, F> ProxyBuilder<WantsHandlers<C, CA, H, W, F>> {
    /// Set the HTTP handler.
    pub fn with_http_handler<H2: HttpHandler>(
        self,
        http_handler: H2,
    ) -> ProxyBuilder<WantsHandlers<C, CA, H2, W, F>> {
        ProxyBuilder(WantsHandlers {
            al: self.0.al,
            client: self.0.client,
            ca: self.0.ca,
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
    ) -> ProxyBuilder<WantsHandlers<C, CA, H, W2, F>> {
        ProxyBuilder(WantsHandlers {
            al: self.0.al,
            client: self.0.client,
            ca: self.0.ca,
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
    ) -> ProxyBuilder<WantsHandlers<C, CA, H, W, F2>> {
        ProxyBuilder(WantsHandlers {
            al: self.0.al,
            client: self.0.client,
            ca: self.0.ca,
            http_handler: self.0.http_handler,
            websocket_handler: self.0.websocket_handler,
            websocket_connector: self.0.websocket_connector,
            server: self.0.server,
            graceful_shutdown,
        })
    }

    /// Build the proxy.
    pub fn build(self) -> Proxy<C, CA, H, W, F> {
        Proxy {
            al: self.0.al,
            client: self.0.client,
            ca: Arc::new(self.0.ca),
            http_handler: self.0.http_handler,
            websocket_handler: self.0.websocket_handler,
            websocket_connector: self.0.websocket_connector,
            server: self.0.server,
            graceful_shutdown: self.0.graceful_shutdown,
        }
    }
}
