use crate::{
    certificate_authority::CertificateAuthority, HttpHandler, NoopHttpHandler,
    NoopWebSocketHandler, Proxy, WebSocketHandler,
};
use hyper::{
    client::{connect::Connect, Client, HttpConnector},
    server::conn::AddrIncoming,
};
#[cfg(feature = "rustls-client")]
use hyper_rustls::{HttpsConnector as RustlsConnector, HttpsConnectorBuilder};
#[cfg(feature = "native-tls-client")]
use hyper_tls::HttpsConnector as NativeTlsConnector;
use std::{
    net::{SocketAddr, TcpListener},
    sync::Arc,
};
use tokio_tungstenite::Connector;

/// A builder for creating a [`Proxy`].
///
/// # Examples
///
/// ```rust
/// # #[cfg(all(feature = "rcgen-ca", feature = "rustls-client"))]
/// # {
/// use hudsucker::ProxyBuilder;
/// # use hudsucker::certificate_authority::RcgenAuthority;
/// # use rustls_pemfile as pemfile;
/// # use tokio_rustls::rustls;
/// #
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
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProxyBuilder<T>(T);

/// Builder state that needs either an address or a TCP listener.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WantsAddr(());

#[derive(Debug)]
pub(crate) enum AddrListenerServer {
    Addr(SocketAddr),
    Listener(TcpListener),
    Server(Box<hyper::server::Builder<AddrIncoming>>),
}

impl ProxyBuilder<WantsAddr> {
    /// Create a new [`ProxyBuilder`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the address to listen on.
    pub fn with_addr(self, addr: SocketAddr) -> ProxyBuilder<WantsClient> {
        ProxyBuilder(WantsClient {
            als: AddrListenerServer::Addr(addr),
        })
    }

    /// Set a listener to use for the proxy server.
    pub fn with_listener(self, listener: TcpListener) -> ProxyBuilder<WantsClient> {
        ProxyBuilder(WantsClient {
            als: AddrListenerServer::Listener(listener),
        })
    }

    /// Set a custom server builder to use for the proxy server.
    pub fn with_server(
        self,
        server: hyper::server::Builder<AddrIncoming>,
    ) -> ProxyBuilder<WantsClient> {
        ProxyBuilder(WantsClient {
            als: AddrListenerServer::Server(Box::new(server)),
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
    als: AddrListenerServer,
}

impl ProxyBuilder<WantsClient> {
    /// Use a hyper-rustls connector.
    #[cfg(feature = "rustls-client")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls-client")))]
    pub fn with_rustls_client(self) -> ProxyBuilder<WantsCa<RustlsConnector<HttpConnector>>> {
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1();

        #[cfg(feature = "http2")]
        let https = https.enable_http2();

        let https = https.build();

        ProxyBuilder(WantsCa {
            als: self.0.als,
            client: Client::builder()
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(https),
        })
    }

    /// Use a hyper-tls connector.
    #[cfg(feature = "native-tls-client")]
    #[cfg_attr(docsrs, doc(cfg(feature = "native-tls-client")))]
    pub fn with_native_tls_client(
        self,
    ) -> ProxyBuilder<WantsCa<NativeTlsConnector<HttpConnector>>> {
        let https = NativeTlsConnector::new();

        ProxyBuilder(WantsCa {
            als: self.0.als,
            client: Client::builder()
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(https),
        })
    }

    /// Use a custom client.
    pub fn with_client<C>(self, client: Client<C>) -> ProxyBuilder<WantsCa<C>>
    where
        C: Connect + Clone + Send + Sync + 'static,
    {
        ProxyBuilder(WantsCa {
            als: self.0.als,
            client,
        })
    }
}

/// Builder state that needs a certificate authority.
#[derive(Debug)]
pub struct WantsCa<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    als: AddrListenerServer,
    client: Client<C>,
}

impl<C> ProxyBuilder<WantsCa<C>>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    /// Set the certificate authority to use.
    pub fn with_ca<CA: CertificateAuthority>(
        self,
        ca: CA,
    ) -> ProxyBuilder<WantsHandlers<C, CA, NoopHttpHandler, NoopWebSocketHandler>> {
        ProxyBuilder(WantsHandlers {
            als: self.0.als,
            client: self.0.client,
            ca,
            http_handler: NoopHttpHandler::new(),
            websocket_handler: NoopWebSocketHandler::new(),
            websocket_connector: None,
        })
    }
}

/// Builder state that can take additional handlers.
pub struct WantsHandlers<C, CA, H, W>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    W: WebSocketHandler,
{
    als: AddrListenerServer,
    client: Client<C>,
    ca: CA,
    http_handler: H,
    websocket_handler: W,
    websocket_connector: Option<Connector>,
}

impl<C, CA, H, W> ProxyBuilder<WantsHandlers<C, CA, H, W>>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    W: WebSocketHandler,
{
    /// Set the HTTP handler.
    pub fn with_http_handler<H2: HttpHandler>(
        self,
        http_handler: H2,
    ) -> ProxyBuilder<WantsHandlers<C, CA, H2, W>> {
        ProxyBuilder(WantsHandlers {
            als: self.0.als,
            client: self.0.client,
            ca: self.0.ca,
            http_handler,
            websocket_handler: self.0.websocket_handler,
            websocket_connector: self.0.websocket_connector,
        })
    }

    /// Set the WebSocket handler.
    pub fn with_websocket_handler<W2: WebSocketHandler>(
        self,
        websocket_handler: W2,
    ) -> ProxyBuilder<WantsHandlers<C, CA, H, W2>> {
        ProxyBuilder(WantsHandlers {
            als: self.0.als,
            client: self.0.client,
            ca: self.0.ca,
            http_handler: self.0.http_handler,
            websocket_handler,
            websocket_connector: self.0.websocket_connector,
        })
    }

    /// Set the connector to use when connecting to WebSocket servers.
    pub fn with_websocket_connector(self, connector: Connector) -> Self {
        ProxyBuilder(WantsHandlers {
            websocket_connector: Some(connector),
            ..self.0
        })
    }

    /// Build the proxy.
    pub fn build(self) -> Proxy<C, CA, H, W> {
        Proxy {
            als: self.0.als,
            client: self.0.client,
            ca: Arc::new(self.0.ca),
            http_handler: self.0.http_handler,
            websocket_handler: self.0.websocket_handler,
            websocket_connector: self.0.websocket_connector,
        }
    }
}
