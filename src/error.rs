use rcgen::RcgenError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid CA")]
    Tls(#[from] RcgenError),
    #[error("network error")]
    Network(#[from] hyper::Error),
    #[error("unknown error")]
    Unknown,
}
