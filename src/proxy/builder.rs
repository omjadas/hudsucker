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
    pub fn with_ca<CA: CertificateAuthority>(
        self,
        ca: CA,
    ) -> ProxyBuilder<WantsHandlers<C, CA, NoopHttpHandler, NoopMessageHandler, NoopMessageHandler>>
    {
        ProxyBuilder(WantsHandlers {
            addr: self.0.addr,
            client: self.0.client,
            ca,
            http_handler: NoopHttpHandler {},
            incoming_message_handler: NoopMessageHandler {},
            outgoing_message_handler: NoopMessageHandler {},
        })
    }
}

/// Builder state that can take additional handlers.
#[derive(Debug)]
pub struct WantsHandlers<C, CA, H, M1, M2>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    M1: MessageHandler,
    M2: MessageHandler,
{
    addr: SocketAddr,
    client: Client<C>,
    ca: CA,
    http_handler: H,
    incoming_message_handler: M1,
    outgoing_message_handler: M2,
}

impl<C, CA, H, M1, M2> ProxyBuilder<WantsHandlers<C, CA, H, M1, M2>>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    M1: MessageHandler,
    M2: MessageHandler,
{
    /// Set the HTTP handler.
    pub fn with_http_handler<H2: HttpHandler>(
        self,
        http_handler: H2,
    ) -> ProxyBuilder<WantsHandlers<C, CA, H2, M1, M2>> {
        ProxyBuilder(WantsHandlers {
            addr: self.0.addr,
            client: self.0.client,
            ca: self.0.ca,
            http_handler,
            incoming_message_handler: self.0.incoming_message_handler,
            outgoing_message_handler: self.0.outgoing_message_handler,
        })
    }

    /// Set the incoming message handler.
    pub fn with_incoming_message_handler<M: MessageHandler>(
        self,
        incoming_message_handler: M,
    ) -> ProxyBuilder<WantsHandlers<C, CA, H, M, M2>> {
        ProxyBuilder(WantsHandlers {
            addr: self.0.addr,
            client: self.0.client,
            ca: self.0.ca,
            http_handler: self.0.http_handler,
            incoming_message_handler,
            outgoing_message_handler: self.0.outgoing_message_handler,
        })
    }

    /// Set the outgoing message handler.
    pub fn with_outgoing_message_handler<M: MessageHandler>(
        self,
        outgoing_message_handler: M,
    ) -> ProxyBuilder<WantsHandlers<C, CA, H, M1, M>> {
        ProxyBuilder(WantsHandlers {
            addr: self.0.addr,
            client: self.0.client,
            ca: self.0.ca,
            http_handler: self.0.http_handler,
            incoming_message_handler: self.0.incoming_message_handler,
            outgoing_message_handler,
        })
    }

    /// Build the proxy.
    pub fn build(self) -> Proxy<C, CA, H, M1, M2> {
        Proxy {
            listen_addr: self.0.addr,
            client: self.0.client,
            ca: Arc::new(self.0.ca),
            http_handler: self.0.http_handler,
            incoming_message_handler: self.0.incoming_message_handler,
            outgoing_message_handler: self.0.outgoing_message_handler,
        }
    }
}