//! The listener and connection type under every mock server.
//!
//! Each accepted TCP stream is wrapped in a shared slot. The HTTP server reads and writes through
//! the slot as usual; a fault that needs control over the bytes on the wire (a dropped connection, a
//! truncated body, slow headers) takes the stream out of the slot and writes to it directly. From
//! then on the HTTP server sees a connection that never becomes readable and refuses every write,
//! so it gives up the connection without sending anything of its own.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::extract::connect_info::Connected;
use axum::serve::{IncomingStream, Listener};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

/// A loopback listener that counts accepted connections.
pub(crate) struct MockListener {
    inner: TcpListener,
    connections: Arc<AtomicUsize>,
}

impl MockListener {
    pub(crate) fn new(inner: TcpListener, connections: Arc<AtomicUsize>) -> Self {
        Self { inner, connections }
    }
}

impl Listener for MockListener {
    type Io = ConnIo;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => {
                    self.connections.fetch_add(1, Ordering::SeqCst);
                    let _ = stream.set_nodelay(true);
                    return (ConnIo(Conn(Arc::new(Mutex::new(Some(stream))))), addr);
                }
                // Loopback accept errors are transient (a reset before accept, a full descriptor
                // table); wait briefly instead of spinning.
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// A handle to the stream of one connection, handed to the harness middleware as connect info.
#[derive(Clone)]
pub(crate) struct Conn(Arc<Mutex<Option<TcpStream>>>);

impl Conn {
    /// Takes the stream away from the HTTP server. Returns `None` if it was already taken.
    pub(crate) fn take(&self) -> Option<TcpStream> {
        self.0.lock().expect("connection slot poisoned").take()
    }
}

impl Connected<IncomingStream<'_, MockListener>> for Conn {
    fn connect_info(stream: IncomingStream<'_, MockListener>) -> Self {
        stream.io().0.clone()
    }
}

/// The IO type the HTTP server drives.
pub(crate) struct ConnIo(Conn);

impl AsyncRead for ConnIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut slot = self.0.0.lock().expect("connection slot poisoned");
        match slot.as_mut() {
            Some(stream) => Pin::new(stream).poll_read(cx, buf),
            // Taken by a fault: never readable. Reporting EOF instead would make the server drop
            // the request future while the fault is still writing.
            None => Poll::Pending,
        }
    }
}

impl AsyncWrite for ConnIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut slot = self.0.0.lock().expect("connection slot poisoned");
        match slot.as_mut() {
            Some(stream) => Pin::new(stream).poll_write(cx, buf),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut slot = self.0.0.lock().expect("connection slot poisoned");
        match slot.as_mut() {
            Some(stream) => Pin::new(stream).poll_flush(cx),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut slot = self.0.0.lock().expect("connection slot poisoned");
        match slot.as_mut() {
            Some(stream) => Pin::new(stream).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}
