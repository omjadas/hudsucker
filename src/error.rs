use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BuilderError {
    #[error("{0}")]
    NativeTls(#[from] hyper_tls::native_tls::Error),
    #[error("{0}")]
    Rustls(#[from] tokio_rustls::rustls::Error),
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("network error")]
    Network(#[from] hyper::Error),
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("unable to decode body")]
    Decode,
    #[error("builder error")]
    Builder(#[from] BuilderError),
    #[error("unknown error")]
    Unknown,
}
