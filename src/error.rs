use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[cfg(feature = "rcgen-ca")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rcgen-ca")))]
    #[error("invalid CA")]
    Tls(#[from] rcgen::Error),
    #[error("network error")]
    Network(#[from] hyper::Error),
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("unable to decode body")]
    Decode,
    #[error("unknown error")]
    Unknown,
}
