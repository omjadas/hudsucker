#[cfg(feature = "rcgen-ca")]
use rcgen::RcgenError;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[cfg(feature = "rcgen-ca")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rcgen-ca")))]
    #[error("invalid CA")]
    Tls(#[from] RcgenError),
    #[error("network error")]
    Network(#[from] hyper::Error),
    #[error("unable to decode body")]
    Decode,
    #[error("unknown error")]
    Unknown,
}
