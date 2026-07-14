// adapted from https://github.com/hyperium/hyper/blob/master/src/common/io/rewind.rs

use std::{
    cmp,
    io::{self, IoSlice},
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Combine a buffer with an IO, rewinding reads to use the buffer.
pub(crate) struct Rewind<T, U> {
    prefix: T,
    prefix_pos: usize,
    inner: U,
}

impl<T, U> Rewind<T, U> {
    pub(crate) fn new(prefix: T, inner: U) -> Self {
        Rewind {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }
}

impl<T, U> AsyncRead for Rewind<T, U>
where
    T: Deref<Target = [u8]> + Unpin,
    U: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix_pos < self.prefix.len() {
            let copy_len = cmp::min(self.prefix.len() - self.prefix_pos, buf.remaining());
            buf.put_slice(&self.prefix[self.prefix_pos..(self.prefix_pos + copy_len)]);
            self.prefix_pos += copy_len;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T, U> AsyncWrite for Rewind<T, U>
where
    T: Unpin,
    U: AsyncWrite + Unpin,
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

pub(crate) struct ArrayPrefix<const N: usize> {
    inner: [u8; N],
    len: usize,
}

impl<const N: usize> ArrayPrefix<N> {
    pub(crate) fn new(inner: [u8; N], len: usize) -> Self {
        ArrayPrefix { inner, len }
    }
}

impl<const N: usize> Deref for ArrayPrefix<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner[..self.len]
    }
}
