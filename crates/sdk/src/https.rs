//! HTTPS for evidence, E2EE and the dashboard. Connections open through the SDK's [`Network`],
//! which is how a proxy and the onion address apply to these requests too.

use crate::network::Network;
use bytes::Bytes;
use futures_util::{Stream, TryStreamExt as _};
use http::{
    HeaderMap, HeaderValue, Method, Request, StatusCode, Uri,
    header::{ACCEPT_ENCODING, CONTENT_ENCODING},
};
use http_body_util::{BodyExt as _, Empty, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::body::{Frame, Incoming};
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connected, Connection},
    },
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use rustls::pki_types::ServerName;
use std::{
    error::Error as StdError,
    future::Future,
    io::{self, Write as _},
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use url::Url;

type BoxError = Box<dyn StdError + Send + Sync>;

/// A request body.
pub type Body = UnsyncBoxBody<Bytes, BoxError>;

#[must_use]
pub fn empty() -> Body {
    Empty::new().map_err(|never| match never {}).boxed_unsync()
}

#[must_use]
pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// A body sent as `stream` produces it.
pub fn stream<S, E>(stream: S) -> Body
where
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: Into<BoxError> + 'static,
{
    StreamBody::new(stream.map_ok(Frame::data).map_err(Into::into)).boxed_unsync()
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{}", chain(.0))]
    Request(#[from] hyper_util::client::legacy::Error),
    #[error("response body failed: {}", chain(.0))]
    Body(#[from] hyper::Error),
    #[error("invalid request: {0}")]
    Invalid(#[from] http::Error),
    #[error("invalid request URL")]
    Url,
    #[error("response exceeds {0} bytes")]
    TooLarge(usize),
    #[error("response uses an unsupported content encoding")]
    Encoding,
    #[error("response body is corrupt: {0}")]
    Decode(io::Error),
}

/// Displays an error with its causes, which hyper keeps out of its own messages.
fn chain(error: &dyn StdError) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

/// A pooled HTTP/1.1 and HTTP/2 client that follows no redirects and sends no cookies.
#[derive(Clone)]
pub struct HttpsClient {
    client: Client<Connector, Body>,
    network: Network,
}

impl HttpsClient {
    /// Uses `tls` for every HTTPS connection; ALPN selects HTTP/2 or HTTP/1.1.
    #[must_use]
    pub fn new(network: Network, tls: rustls::ClientConfig) -> Self {
        let connector = Connector {
            network: network.clone(),
            tls: TlsConnector::from(Arc::new(tls)),
        };
        Self {
            client: Client::builder(TokioExecutor::new())
                .timer(TokioTimer::new())
                .pool_timer(TokioTimer::new())
                .build(connector),
            network,
        }
    }

    /// Checks servers against the Mozilla roots, over TLS 1.3 or 1.2.
    ///
    /// # Errors
    /// Fails if the TLS library cannot provide these protocol versions.
    pub fn public(network: Network) -> Result<Self, rustls::Error> {
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_root_certificates(rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self::new(network, tls))
    }

    #[must_use]
    pub const fn network(&self) -> &Network {
        &self.network
    }

    /// Sends `request` as it is.
    ///
    /// # Errors
    /// Fails when the connection or the exchange fails.
    pub async fn send(&self, request: Request<Body>) -> Result<Response, Error> {
        Ok(Response(self.client.request(request).await?))
    }

    /// Sends `method` to `url` with `headers` and `body`.
    ///
    /// # Errors
    /// Fails when the request is invalid or the exchange fails.
    pub async fn fetch(
        &self,
        method: Method,
        url: &Url,
        headers: HeaderMap,
        body: Body,
    ) -> Result<Response, Error> {
        let mut request = Request::builder()
            .method(method)
            .uri(Uri::try_from(url.as_str()).map_err(|_| Error::Url)?)
            .body(body)?;
        *request.headers_mut() = headers;
        self.send(request).await
    }

    /// Gets `url`, accepting gzip or Brotli for [`Response::decoded`].
    ///
    /// # Errors
    /// Fails when the request is invalid or the exchange fails.
    pub async fn get(&self, url: &Url, mut headers: HeaderMap) -> Result<Response, Error> {
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("br, gzip"));
        self.fetch(Method::GET, url, headers, empty()).await
    }
}

pub struct Response(http::Response<Incoming>);

impl Response {
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.0.status()
    }

    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        self.0.headers()
    }

    /// The length that the response declared, before any decoding.
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        hyper::body::Body::size_hint(self.0.body()).exact()
    }

    /// The next bytes of the body as they arrive, or `None` at its end.
    ///
    /// # Errors
    /// Fails when the connection fails before the body ends.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, Error> {
        while let Some(frame) = self.0.body_mut().frame().await {
            if let Ok(data) = frame?.into_data()
                && !data.is_empty()
            {
                return Ok(Some(data));
            }
        }
        Ok(None)
    }

    /// The whole body, decoded from the gzip or Brotli that [`HttpsClient::get`] accepts. Stops at
    /// `limit` decoded bytes, so a small compressed body cannot expand without bound.
    ///
    /// # Errors
    /// Fails for a larger body, an unknown or corrupt encoding, or a failed connection.
    pub async fn decoded(mut self, limit: usize) -> Result<Vec<u8>, Error> {
        let encoding = match self.headers().get(CONTENT_ENCODING) {
            None => None,
            Some(value) => Some(
                value
                    .to_str()
                    .map_err(|_| Error::Encoding)?
                    .trim()
                    .to_ascii_lowercase(),
            ),
        };
        let output = Limited {
            bytes: Vec::new(),
            limit,
            exceeded: false,
        };
        let mut decoder = match encoding.as_deref() {
            None | Some("identity") => Decoder::Identity(output),
            Some("gzip") => Decoder::Gzip(flate2::write::GzDecoder::new(output)),
            Some("br") => Decoder::Brotli(Box::new(brotli_decompressor::DecompressorWriter::new(
                output, 4096,
            ))),
            Some(_) => return Err(Error::Encoding),
        };
        while let Some(chunk) = self.chunk().await? {
            decoder.write(&chunk)?;
        }
        decoder.finish()
    }
}

/// Collects decoded bytes up to a limit.
struct Limited {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}
impl io::Write for Limited {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > self.limit - self.bytes.len() {
            self.exceeded = true;
            return Err(io::Error::other("decoded body exceeds its limit"));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum Decoder {
    Identity(Limited),
    Gzip(flate2::write::GzDecoder<Limited>),
    Brotli(Box<brotli_decompressor::DecompressorWriter<Limited>>),
}
impl Decoder {
    fn output(&self) -> &Limited {
        match self {
            Self::Identity(output) => output,
            Self::Gzip(decoder) => decoder.get_ref(),
            Self::Brotli(decoder) => decoder.get_ref(),
        }
    }
    fn failure(&self, error: io::Error) -> Error {
        if self.output().exceeded {
            Error::TooLarge(self.output().limit)
        } else {
            Error::Decode(error)
        }
    }
    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        let written = match self {
            Self::Identity(output) => output.write_all(data),
            Self::Gzip(decoder) => decoder.write_all(data),
            Self::Brotli(decoder) => decoder.write_all(data),
        };
        written.map_err(|error| self.failure(error))
    }
    /// Requires a complete stream, so a truncated body fails instead of returning a prefix.
    fn finish(mut self) -> Result<Vec<u8>, Error> {
        let finished = match &mut self {
            Self::Identity(_) => Ok(()),
            Self::Gzip(decoder) => decoder.try_finish(),
            Self::Brotli(decoder) => decoder.close(),
        };
        finished.map_err(|error| self.failure(error))?;
        match self {
            Self::Identity(output) => Ok(output.bytes),
            Self::Gzip(decoder) => decoder
                .finish()
                .map(|output| output.bytes)
                .map_err(Error::Decode),
            Self::Brotli(decoder) => decoder
                .into_inner()
                .map(|output| output.bytes)
                .map_err(|_| Error::Decode(io::Error::other("incomplete Brotli stream"))),
        }
    }
}

#[derive(Clone)]
struct Connector {
    network: Network,
    tls: TlsConnector,
}

impl tower_service::Service<Uri> for Connector {
    type Response = Socket;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Socket>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connector = self.clone();
        Box::pin(async move {
            let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
            let host = uri.host().ok_or_else(|| invalid("URL has no host"))?;
            let name = host.trim_start_matches('[').trim_end_matches(']');
            let tls = match uri.scheme_str() {
                Some("https") => true,
                Some("http")
                    if name == "localhost"
                        || name
                            .parse::<IpAddr>()
                            .is_ok_and(|address| address.is_loopback()) =>
                {
                    false
                }
                _ => return Err(invalid("URL scheme must be https")),
            };
            let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
            let tcp = connector.network.connect(host, port).await?;
            if !tls {
                return Ok(Socket::Plain(TokioIo::new(tcp)));
            }
            let name = ServerName::try_from(name)
                .map_err(|_| invalid("invalid server name"))?
                .to_owned();
            Ok(Socket::Tls(Box::new(TokioIo::new(
                connector.tls.connect(name, tcp).await?,
            ))))
        })
    }
}

/// A connection the pool can reuse. Plain HTTP reaches only loopback test servers; every compiled
/// origin is HTTPS.
enum Socket {
    Plain(TokioIo<TcpStream>),
    Tls(Box<TokioIo<TlsStream<TcpStream>>>),
}

impl Connection for Socket {
    fn connected(&self) -> Connected {
        match self {
            Self::Tls(stream) if stream.inner().get_ref().1.alpn_protocol() == Some(b"h2") => {
                Connected::new().negotiated_h2()
            }
            _ => Connected::new(),
        }
    }
}

impl hyper::rt::Read for Socket {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(context, buffer),
        }
    }
}

impl hyper::rt::Write for Socket {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(context, data),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(context, data),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write_vectored(context, data),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write_vectored(context, data),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(stream) => stream.is_write_vectored(),
            Self::Tls(stream) => stream.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(context),
        }
    }
}

#[cfg(test)]
mod tests;
