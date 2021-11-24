use crate::{
    certificate_authority::CertificateAuthority, proxy::Proxy, HttpHandler, MessageHandler,
    NoopHttpHandler, NoopMessageHandler,
};
use hyper::client::{connect::Connect, Client, HttpConnector};
#[cfg(feature = "rustls-client")]
use hyper_rustls::{HttpsConnector as RustlsConnector, HttpsConnectorBuilder};
#[cfg(feature = "native-tls-client")]
use hyper_tls::HttpsConnector as NativeTlsConnector;
use std::{net::SocketAddr, sync::Arc};

/// A builder for creating a proxy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProxyBuilder<T>(T);

/// Builder state that needs an address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WantsAddr(());

impl ProxyBuilder<WantsAddr> {
    /// Create a new ProxyBuilder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the address to listen on.
    pub fn with_addr(self, addr: SocketAddr) -> ProxyBuilder<WantsClient> {
        ProxyBuilder(WantsClient { addr })
    }
}

impl Default for ProxyBuilder<WantsAddr> {
    fn default() -> Self {
        ProxyBuilder(WantsAddr(()))
    }
}

/// Builder state that needs a client.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WantsClient {
    addr: SocketAddr,
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
            addr: self.0.addr,
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
            addr: self.0.addr,
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
            addr: self.0.addr,
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
    addr: SocketAddr,
    client: Client<C>,
}

impl<C> ProxyBuilder<WantsCa<C>>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    /// Set the certificate authority to use.
    pub fn with_ca<CA>(self, ca: CA) -> ProxyBuilder<WantsHandlers1<C, CA>>
    where
        CA: CertificateAuthority,
    {
        ProxyBuilder(WantsHandlers1 {
            addr: self.0.addr,
            client: self.0.client,
            ca,
        })
    }
}

/// Builder state that can take additional handlers.
#[derive(Debug)]
pub struct WantsHandlers1<C, CA>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
{
    addr: SocketAddr,
    client: Client<C>,
    ca: CA,
}

impl<C, CA> ProxyBuilder<WantsHandlers1<C, CA>>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
{
    /// Set the HTTP handler to use.
    pub fn with_http_handler<H>(self, http_handler: H) -> ProxyBuilder<WantsHandlers2<C, CA, H>>
    where
        H: HttpHandler,
    {
        ProxyBuilder(WantsHandlers2 {
            addr: self.0.addr,
            client: self.0.client,
            ca: self.0.ca,
            http_handler,
        })
    }

    /// Set the message handler to use.
    pub fn with_incoming_message_handler<M1>(
        self,
        incoming_message_handler: M1,
    ) -> ProxyBuilder<WantsHandlers3<C, CA, M1>>
    where
        M1: MessageHandler,
    {
        ProxyBuilder(WantsHandlers3 {
            addr: self.0.addr,
            client: self.0.client,
            ca: self.0.ca,
            incoming_message_handler,
        })
    }

    /// Set the message handler to use.
    pub fn with_outgoing_message_handler<M2>(
        self,
        outgoing_message_handler: M2,
    ) -> ProxyBuilder<WantsHandlers4<C, CA, M2>>
    where
        M2: MessageHandler,
    {
        ProxyBuilder(WantsHandlers4 {
            addr: self.0.addr,
            client: self.0.client,
            ca: self.0.ca,
            outgoing_message_handler,
        })
    }

    /// Build the proxy.
    pub fn build(self) -> Proxy<C, CA, NoopHttpHandler, NoopMessageHandler, NoopMessageHandler> {
        Proxy {
            listen_addr: self.0.addr,
            client: self.0.client,
            ca: Arc::new(self.0.ca),
            http_handler: NoopHttpHandler::new(),
            incoming_message_handler: NoopMessageHandler::new(),
            outgoing_message_handler: NoopMessageHandler::new(),
        }
    }
}

/// Builder state that can take additional handlers.
#[derive(Debug)]
pub struct WantsHandlers2<C, CA, H>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
{
    addr: SocketAddr,
    client: Client<C>,
    ca: CA,
    http_handler: H,
}

impl<C, CA, H> ProxyBuilder<WantsHandlers2<C, CA, H>>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
{
    pub fn with_incoming_message_handler<M1>(
        self,
        incoming_message_handler: M1,
    ) -> ProxyBuilder<WantsHandlers5<C, CA, H, M1>>
    where
        M1: MessageHandler,
    {
        ProxyBuilder(WantsHandlers5 {
            addr: self.0.addr,
            client: self.0.client,
            ca: self.0.ca,
            http_handler: self.0.http_handler,
            incoming_message_handler,
        })
    }

    pub fn with_outgoing_message_handler<M2>(
        self,
        outgoing_message_handler: M2,
    ) -> ProxyBuilder<WantsHandlers6<C, CA, H, M2>>
    where
        M2: MessageHandler,
    {
        ProxyBuilder(WantsHandlers6 {
            addr: self.0.addr,
            client: self.0.client,
            ca: self.0.ca,
            http_handler: self.0.http_handler,
            outgoing_message_handler,
        })
    }

    pub fn build(self) -> Proxy<C, CA, H, NoopMessageHandler, NoopMessageHandler> {
        Proxy {
            listen_addr: self.0.addr,
            client: self.0.client,
            ca: Arc::new(self.0.ca),
            http_handler: self.0.http_handler,
            incoming_message_handler: NoopMessageHandler::new(),
            outgoing_message_handler: NoopMessageHandler::new(),
        }
    }
}

/// Builder state that can take additional handlers.
#[derive(Debug)]
pub struct WantsHandlers3<C, CA, M1>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    M1: MessageHandler,
{
    addr: SocketAddr,
    client: Client<C>,
    ca: CA,
    incoming_message_handler: M1,
}

impl<C, CA, M1> ProxyBuilder<WantsHandlers3<C, CA, M1>>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    M1: MessageHandler,
{
    pub fn with_http_handler<H>(self, http_handler: H) -> ProxyBuilder<WantsHandlers5<C, CA, H, M1>>
    where
        H: HttpHandler,
    {
        ProxyBuilder(WantsHandlers5 {
            addr: self.0.addr,
            client: self.0.client,
            ca: self.0.ca,
            http_handler,
            incoming_message_handler: self.0.incoming_message_handler,
        })
    }

    pub fn with_outgoing_message_handler<M2>(
        self,
        outgoing_message_handler: M2,
    ) -> ProxyBuilder<WantsHandlers7<C, CA, M1, M2>>
    where
        M2: MessageHandler,
    {
        ProxyBuilder(WantsHandlers7 {
            addr: self.0.addr,
            client: self.0.client,
            ca: self.0.ca,
            incoming_message_handler: self.0.incoming_message_handler,
            outgoing_message_handler,
        })
    }

    pub fn build(self) -> Proxy<C, CA, NoopHttpHandler, M1, NoopMessageHandler> {
        Proxy {
            listen_addr: self.0.addr,
            client: self.0.client,
            ca: Arc::new(self.0.ca),
            http_handler: NoopHttpHandler::new(),
            incoming_message_handler: self.0.incoming_message_handler,
            outgoing_message_handler: NoopMessageHandler::new(),
        }
    }
}

/// Builder state that can take additional handlers.
#[derive(Debug)]
pub struct WantsHandlers4<C, CA, M2>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    M2: MessageHandler,
{
    addr: SocketAddr,
    client: Client<C>,
    ca: CA,
    outgoing_message_handler: M2,
}

impl<C, CA, M2> ProxyBuilder<WantsHandlers4<C, CA, M2>>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    M2: MessageHandler,
{
    pub fn with_http_handler<H>(
        self,
        http_handler: H,
    ) -> ProxyBuilder<WantsHandlers5<C, CA, H, NoopMessageHandler>>
    where
        H: HttpHandler,
    {
        ProxyBuilder(WantsHandlers5 {
            addr: self.0.addr,
            client: self.0.client,
            ca: self.0.ca,
            http_handler,
            incoming_message_handler: NoopMessageHandler::new(),
        })
    }

    pub fn with_incoming_message_handler<M1>(
        self,
        incoming_message_handler: M1,
    ) -> ProxyBuilder<WantsHandlers7<C, CA, M1, M2>>
    where
        M1: MessageHandler,
    {
        ProxyBuilder(WantsHandlers7 {
            addr: self.0.addr,
            client: self.0.client,
            ca: self.0.ca,
            incoming_message_handler,
            outgoing_message_handler: self.0.outgoing_message_handler,
        })
    }

    pub fn build(self) -> Proxy<C, CA, NoopHttpHandler, NoopMessageHandler, M2> {
        Proxy {
            listen_addr: self.0.addr,
            client: self.0.client,
            ca: Arc::new(self.0.ca),
            http_handler: NoopHttpHandler::new(),
            incoming_message_handler: NoopMessageHandler::new(),
            outgoing_message_handler: self.0.outgoing_message_handler,
        }
    }
}

/// Builder state that can take additional handlers.
#[derive(Debug)]
pub struct WantsHandlers5<C, CA, H, M1>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    M1: MessageHandler,
{
    addr: SocketAddr,
    client: Client<C>,
    ca: CA,
    http_handler: H,
    incoming_message_handler: M1,
}

impl<C, CA, H, M1> ProxyBuilder<WantsHandlers5<C, CA, H, M1>>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    M1: MessageHandler,
{
    pub fn with_outgoing_message_handler<M2>(
        self,
        outgoing_message_handler: M2,
    ) -> Proxy<C, CA, H, M1, M2>
    where
        M2: MessageHandler,
    {
        Proxy {
            listen_addr: self.0.addr,
            client: self.0.client,
            ca: Arc::new(self.0.ca),
            http_handler: self.0.http_handler,
            incoming_message_handler: self.0.incoming_message_handler,
            outgoing_message_handler,
        }
    }

    pub fn build(self) -> Proxy<C, CA, H, M1, NoopMessageHandler> {
        Proxy {
            listen_addr: self.0.addr,
            client: self.0.client,
            ca: Arc::new(self.0.ca),
            http_handler: self.0.http_handler,
            incoming_message_handler: self.0.incoming_message_handler,
            outgoing_message_handler: NoopMessageHandler::new(),
        }
    }
}

/// Builder state that can take additional handlers.
#[derive(Debug)]
pub struct WantsHandlers6<C, CA, H, M2>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    M2: MessageHandler,
{
    addr: SocketAddr,
    client: Client<C>,
    ca: CA,
    http_handler: H,
    outgoing_message_handler: M2,
}

impl<C, CA, H, M2> ProxyBuilder<WantsHandlers6<C, CA, H, M2>>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    M2: MessageHandler,
{
    pub fn with_incoming_message_handler<M1>(
        self,
        incoming_message_handler: M1,
    ) -> Proxy<C, CA, H, M1, M2>
    where
        M1: MessageHandler,
    {
        Proxy {
            listen_addr: self.0.addr,
            client: self.0.client,
            ca: Arc::new(self.0.ca),
            http_handler: self.0.http_handler,
            incoming_message_handler,
            outgoing_message_handler: self.0.outgoing_message_handler,
        }
    }

    pub fn build(self) -> Proxy<C, CA, H, NoopMessageHandler, M2> {
        Proxy {
            listen_addr: self.0.addr,
            client: self.0.client,
            ca: Arc::new(self.0.ca),
            http_handler: self.0.http_handler,
            incoming_message_handler: NoopMessageHandler::new(),
            outgoing_message_handler: self.0.outgoing_message_handler,
        }
    }
}

/// Builder state that can take additional handlers.
#[derive(Debug)]
pub struct WantsHandlers7<C, CA, M1, M2>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    M1: MessageHandler,
    M2: MessageHandler,
{
    addr: SocketAddr,
    client: Client<C>,
    ca: CA,
    incoming_message_handler: M1,
    outgoing_message_handler: M2,
}

impl<C, CA, M1, M2> ProxyBuilder<WantsHandlers7<C, CA, M1, M2>>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    M1: MessageHandler,
    M2: MessageHandler,
{
    pub fn with_http_handler<H>(self, http_handler: H) -> Proxy<C, CA, H, M1, M2>
    where
        H: HttpHandler,
    {
        Proxy {
            listen_addr: self.0.addr,
            client: self.0.client,
            ca: Arc::new(self.0.ca),
            http_handler,
            incoming_message_handler: self.0.incoming_message_handler,
            outgoing_message_handler: self.0.outgoing_message_handler,
        }
    }

    pub fn build(self) -> Proxy<C, CA, NoopHttpHandler, M1, M2> {
        Proxy {
            listen_addr: self.0.addr,
            client: self.0.client,
            ca: Arc::new(self.0.ca),
            http_handler: NoopHttpHandler::new(),
            incoming_message_handler: self.0.incoming_message_handler,
            outgoing_message_handler: self.0.outgoing_message_handler,
        }
    }
}
