use std::{io, net::SocketAddr};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};

pub(super) trait Listener: Send + Sync {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn accept(&self) -> impl Future<Output = io::Result<(Self::Stream, SocketAddr)>> + Send;
}

impl Listener for TcpListener {
    type Stream = TcpStream;
    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        TcpListener::accept(self).await
    }
}

#[cfg(unix)]
impl Listener for tokio::net::UnixListener {
    type Stream = tokio::net::UnixStream;
    async fn accept(&self) -> io::Result<(Self::Stream, SocketAddr)> {
        let (stream, _) = tokio::net::UnixListener::accept(self).await?;
        Ok((stream, ([0, 0, 0, 0], 0).into()))
    }
}
