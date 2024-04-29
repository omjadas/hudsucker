use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("network error")]
    Network(#[from] hyper::Error),
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("unable to decode body")]
    Decode,
    #[error("unknown error")]
    Unknown,
}
