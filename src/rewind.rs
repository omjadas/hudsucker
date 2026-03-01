// adapted from https://github.com/hyperium/hyper/blob/master/src/common/io/rewind.rs

use std::{
    cmp,
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Combine a buffer with an IO, rewinding reads to use the buffer.
pub(crate) struct Rewind<T, const N: usize> {
    prefix: [u8; N],
    prefix_pos: usize,
    prefix_len: usize,
    inner: T,
}

impl<T, const N: usize> Rewind<T, N> {
    pub(crate) fn new(io: T, prefix: [u8; N], prefix_len: usize) -> Self {
        Rewind {
            prefix,
            prefix_pos: 0,
            prefix_len,
            inner: io,
        }
    }
}

impl<T, const N: usize> AsyncRead for Rewind<T, N>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix_pos < self.prefix_len {
            let copy_len = cmp::min(self.prefix_len - self.prefix_pos, buf.remaining());
            buf.put_slice(&self.prefix[self.prefix_pos..(self.prefix_pos + copy_len)]);
            self.prefix_pos += copy_len;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T, const N: usize> AsyncWrite for Rewind<T, N>
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
