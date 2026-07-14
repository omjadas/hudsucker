use crate::rewind::Rewind;
use std::{
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct Tee<T> {
    prefix: Vec<u8>,
    inner: T,
}

impl<T> Tee<T> {
    pub(crate) fn new(io: T) -> Self {
        Tee {
            prefix: Vec::new(),
            inner: io,
        }
    }

    pub(crate) fn into_inner(self) -> T {
        self.inner
    }

    pub(crate) fn rewind(self) -> Rewind<Vec<u8>, T> {
        Rewind::new(self.prefix, self.inner)
    }
}

impl<T> AsyncRead for Tee<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled_before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);

        if res.is_ready() {
            self.prefix
                .extend_from_slice(&buf.filled()[filled_before..]);
        }

        res
    }
}

impl<T> AsyncWrite for Tee<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
