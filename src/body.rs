use crate::Error;
use futures::{Stream, StreamExt};
use http_body_util::{combinators::BoxBody, Collected, Empty, Full, StreamBody};
use hyper::body::{Body as HttpBody, Bytes, Frame, Incoming, SizeHint};
use std::pin::Pin;

#[derive(Debug)]
enum Internal {
    BoxBody(BoxBody<Bytes, crate::Error>),
    Collected(Collected<Bytes>),
    Empty(Empty<Bytes>),
    Full(Full<Bytes>),
    Incoming(Incoming),
    String(String),
}

#[derive(Debug)]
pub struct Body {
    inner: Internal,
}

impl Body {
    pub fn wrap_stream<S, O, E>(stream: S) -> Self
    where
        S: Stream<Item = Result<O, E>> + Send + Sync + 'static,
        O: Into<Bytes>,
        E: Into<Error>,
    {
        Self {
            inner: Internal::BoxBody(BoxBody::new(StreamBody::new(
                stream.map(|res| res.map(Into::into).map(Frame::data).map_err(Into::into)),
            ))),
        }
    }
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = crate::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match &mut self.inner {
            Internal::BoxBody(body) => Pin::new(body).poll_frame(cx),
            Internal::Collected(body) => Pin::new(body).poll_frame(cx).map_err(|e| match e {}),
            Internal::Empty(body) => Pin::new(body).poll_frame(cx).map_err(|e| match e {}),
            Internal::Full(body) => Pin::new(body).poll_frame(cx).map_err(|e| match e {}),
            Internal::Incoming(body) => Pin::new(body).poll_frame(cx).map_err(Error::from),
            Internal::String(body) => Pin::new(body).poll_frame(cx).map_err(|e| match e {}),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            Internal::BoxBody(body) => body.is_end_stream(),
            Internal::Collected(body) => body.is_end_stream(),
            Internal::Empty(body) => body.is_end_stream(),
            Internal::Full(body) => body.is_end_stream(),
            Internal::Incoming(body) => body.is_end_stream(),
            Internal::String(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            Internal::BoxBody(body) => body.size_hint(),
            Internal::Collected(body) => body.size_hint(),
            Internal::Empty(body) => body.size_hint(),
            Internal::Full(body) => body.size_hint(),
            Internal::Incoming(body) => body.size_hint(),
            Internal::String(body) => body.size_hint(),
        }
    }
}

impl From<BoxBody<Bytes, crate::Error>> for Body {
    fn from(value: BoxBody<Bytes, crate::Error>) -> Self {
        Self {
            inner: Internal::BoxBody(value),
        }
    }
}

impl From<Collected<Bytes>> for Body {
    fn from(value: Collected<Bytes>) -> Self {
        Self {
            inner: Internal::Collected(value),
        }
    }
}

impl From<Empty<Bytes>> for Body {
    fn from(value: Empty<Bytes>) -> Self {
        Self {
            inner: Internal::Empty(value),
        }
    }
}

impl From<Full<Bytes>> for Body {
    fn from(value: Full<Bytes>) -> Self {
        Self {
            inner: Internal::Full(value),
        }
    }
}

impl From<Incoming> for Body {
    fn from(value: Incoming) -> Self {
        Self {
            inner: Internal::Incoming(value),
        }
    }
}

impl<S> From<StreamBody<S>> for Body
where
    S: Stream<Item = Result<Frame<Bytes>, Error>> + Send + Sync + 'static,
{
    fn from(value: StreamBody<S>) -> Self {
        Self {
            inner: Internal::BoxBody(BoxBody::new(value)),
        }
    }
}

impl From<String> for Body {
    fn from(value: String) -> Self {
        Self {
            inner: Internal::String(value),
        }
    }
}

impl From<&'static str> for Body {
    fn from(value: &'static str) -> Self {
        Self {
            inner: Internal::Full(Full::new(Bytes::from_static(value.as_bytes()))),
        }
    }
}

impl From<&'static [u8]> for Body {
    fn from(value: &'static [u8]) -> Self {
        Self {
            inner: Internal::Full(Full::new(Bytes::from_static(value))),
        }
    }
}
