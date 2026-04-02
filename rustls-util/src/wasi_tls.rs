use std::error::Error as StdError;
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::Arc;

use rustls::{ClientConfig, ClientConnection, Connection, pki_types::ServerName};

use crate::complete_io;

/// Supported wasi-tls draft version for this adapter.
pub const WASI_TLS_DRAFT_VERSION: &str = "0.3.0-draft";

/// Supported primary compilation target for this adapter.
pub const WASI_TLS_PRIMARY_TARGET: &str = "wasm32-wasip2";

/// Runtime model this adapter is designed for.
pub const WASI_TLS_RUNTIME_MODEL: &str =
    "single-threaded capability-oriented networking (client-first)";

/// Operation classes used to classify adapter outcomes for wasi-tls style APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterOutcome {
    Fatal,
    Retryable,
    EndOfStream,
}

/// Adapter error kind mapped from rustls + IO behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterErrorKind {
    TlsProtocol,
    IoWouldBlock,
    IoInterrupted,
    UnexpectedEof,
    EndOfStream,
    Io,
}

/// Deterministic adapter error type that carries wasi-tls style outcome semantics.
#[derive(Debug)]
pub struct AdapterError {
    pub kind: AdapterErrorKind,
    pub outcome: AdapterOutcome,
    pub message: String,
}

impl AdapterError {
    fn from_tls(err: rustls::Error) -> Self {
        Self {
            kind: AdapterErrorKind::TlsProtocol,
            outcome: AdapterOutcome::Fatal,
            message: err.to_string(),
        }
    }

    fn from_io(err: io::Error) -> Self {
        if let Some(tls_error) = find_rustls_error_in_chain(&err) {
            return Self::from_tls(tls_error.clone());
        }

        let (kind, outcome) = match err.kind() {
            io::ErrorKind::WouldBlock => {
                (AdapterErrorKind::IoWouldBlock, AdapterOutcome::Retryable)
            }
            io::ErrorKind::Interrupted => {
                (AdapterErrorKind::IoInterrupted, AdapterOutcome::Retryable)
            }
            io::ErrorKind::UnexpectedEof => {
                (AdapterErrorKind::UnexpectedEof, AdapterOutcome::EndOfStream)
            }
            io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected => {
                (AdapterErrorKind::EndOfStream, AdapterOutcome::EndOfStream)
            }
            _ => (AdapterErrorKind::Io, AdapterOutcome::Fatal),
        };

        Self {
            kind,
            outcome,
            message: err.to_string(),
        }
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for AdapterError {}

fn find_rustls_error_in_chain(err: &io::Error) -> Option<&rustls::Error> {
    if let Some(current) = err.get_ref() {
        if let Some(tls_error) = current.downcast_ref::<rustls::Error>() {
            return Some(tls_error);
        }
    }

    let mut source = err.source();
    while let Some(current) = source {
        if let Some(tls_error) = current.downcast_ref::<rustls::Error>() {
            return Some(tls_error);
        }
        source = current.source();
    }
    None
}

/// Lightweight observability hooks for adapter boundaries.
pub trait AdapterObserver {
    fn on_state_change(&mut self, _from: ClientSessionState, _to: ClientSessionState) {}
    fn on_handshake_complete(&mut self) {}
    fn on_tls_io(&mut self, _read_bytes: usize, _written_bytes: usize) {}
    fn on_plaintext_send(&mut self, _bytes: usize) {}
    fn on_plaintext_recv(&mut self, _bytes: usize) {}
    fn on_error(&mut self, _error: &AdapterError) {}
}

/// Default no-op observer.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopObserver;

impl AdapterObserver for NoopObserver {}

/// Session state used by the client-first wasi-tls adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientSessionState {
    Handshaking,
    Open,
    Closing,
    Closed,
    Faulted,
}

impl ClientSessionState {
    fn begin_close(self) -> (Self, bool) {
        match self {
            Self::Closed => (Self::Closed, false),
            Self::Closing => (Self::Closing, false),
            Self::Faulted => (Self::Faulted, false),
            Self::Handshaking | Self::Open => (Self::Closing, true),
        }
    }
}

/// Configuration resource corresponding to a wasi-tls client connector.
#[derive(Debug, Clone)]
pub struct WasiTlsClientConnector {
    config: Arc<ClientConfig>,
    buffer_limit: Option<usize>,
    plaintext_buffer_limit: Option<usize>,
}

impl WasiTlsClientConnector {
    /// Create a connector from an existing rustls client config.
    pub fn new(config: Arc<ClientConfig>) -> Self {
        Self {
            config,
            buffer_limit: None,
            plaintext_buffer_limit: None,
        }
    }

    /// Configure limits mirrored to rustls internal buffering controls.
    pub fn with_buffer_limits(
        mut self,
        tls_buffer_limit: Option<usize>,
        plaintext_buffer_limit: Option<usize>,
    ) -> Self {
        self.buffer_limit = tls_buffer_limit;
        self.plaintext_buffer_limit = plaintext_buffer_limit;
        self
    }

    /// Connect to a server name over an existing capability/transport.
    ///
    /// WIT-to-rustls mapping:
    /// - `client.connector` => this type
    /// - `send(cleartext: stream)` => [`WasiTlsClientSession::send`]
    /// - TLS pumping uses `write_tls/read_tls/process_new_packets` through [`crate::complete_io`]
    /// - cleartext close uses `send_close_notify` + encrypted drain via repeated pumping
    pub fn connect<T: Read + Write>(
        &self,
        server_name: ServerName<'static>,
        transport: T,
    ) -> Result<WasiTlsClientSession<T>, AdapterError> {
        let server_name_for_error = server_name.clone();
        let mut conn = self
            .config
            .connect(server_name)
            .build()
            .map_err(|err| {
                let mut mapped = AdapterError::from_tls(err);
                mapped.message =
                    format!("{} (server_name={server_name_for_error:?})", mapped.message);
                mapped
            })?;

        conn.set_buffer_limit(self.buffer_limit);
        conn.set_plaintext_buffer_limit(self.plaintext_buffer_limit);

        Ok(WasiTlsClientSession {
            conn,
            transport,
            state: ClientSessionState::Handshaking,
            observer: NoopObserver,
            sent_plaintext: 0,
            recv_plaintext: 0,
        })
    }
}

/// Result from a pump cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PumpReport {
    pub tls_read: usize,
    pub tls_written: usize,
}

/// Active client resource mapping a rustls connection plus transport capability.
#[derive(Debug)]
pub struct WasiTlsClientSession<T, O = NoopObserver> {
    conn: ClientConnection,
    transport: T,
    state: ClientSessionState,
    observer: O,
    sent_plaintext: usize,
    recv_plaintext: usize,
}

impl<T: Read + Write, O: AdapterObserver> WasiTlsClientSession<T, O> {
    /// Replace the observer for metrics/tracing hooks.
    pub fn with_observer<O2: AdapterObserver>(self, observer: O2) -> WasiTlsClientSession<T, O2> {
        WasiTlsClientSession {
            conn: self.conn,
            transport: self.transport,
            state: self.state,
            observer,
            sent_plaintext: self.sent_plaintext,
            recv_plaintext: self.recv_plaintext,
        }
    }

    /// Returns current session state.
    pub fn state(&self) -> ClientSessionState {
        self.state
    }

    /// Returns cumulative plaintext sent bytes accepted by rustls.
    pub fn sent_plaintext(&self) -> usize {
        self.sent_plaintext
    }

    /// Returns cumulative plaintext received bytes read from rustls.
    pub fn recv_plaintext(&self) -> usize {
        self.recv_plaintext
    }

    fn transition_state(&mut self, to: ClientSessionState) {
        if self.state != to {
            let from = self.state;
            self.state = to;
            self.observer.on_state_change(from, to);
        }
    }

    fn pump_internal(&mut self) -> Result<PumpReport, AdapterError> {
        let (tls_read, tls_written) =
            complete_io(&mut self.transport, &mut self.conn).map_err(AdapterError::from_io)?;
        self.observer
            .on_tls_io(tls_read, tls_written);

        if self.state == ClientSessionState::Handshaking && !self.conn.is_handshaking() {
            self.transition_state(ClientSessionState::Open);
            self.observer.on_handshake_complete();
        }

        if self.state == ClientSessionState::Closing && !self.conn.wants_write() {
            self.transition_state(ClientSessionState::Closed);
        }

        Ok(PumpReport {
            tls_read,
            tls_written,
        })
    }

    /// Pump handshake/control traffic and pending encrypted payloads.
    pub fn pump(&mut self) -> Result<PumpReport, AdapterError> {
        let result = self.pump_internal();
        if let Err(error) = &result {
            self.transition_state(ClientSessionState::Faulted);
            self.observer.on_error(error);
        }
        result
    }

    /// Send cleartext application bytes into the TLS stream.
    ///
    /// If the plaintext write succeeds but a subsequent TLS pump fails,
    /// this method returns `Ok(written)` for `written > 0` and leaves the
    /// session in `Faulted` state; callers should check [`Self::state`]
    /// before further use.
    pub fn send(&mut self, cleartext: &[u8]) -> Result<usize, AdapterError> {
        if matches!(
            self.state,
            ClientSessionState::Closed | ClientSessionState::Faulted
        ) {
            let error = AdapterError {
                kind: AdapterErrorKind::Io,
                outcome: AdapterOutcome::Fatal,
                message: "cannot send on closed/faulted session".to_string(),
            };
            self.observer.on_error(&error);
            return Err(error);
        }

        let written = self
            .conn
            .writer()
            .write(cleartext)
            .map_err(AdapterError::from_io)?;
        self.sent_plaintext += written;
        self.observer.on_plaintext_send(written);

        if let Err(error) = self.pump() {
            // We intentionally preserve partial-send semantics: once plaintext is
            // accepted by rustls, callers observe success for that consumed prefix.
            if written == 0 {
                return Err(error);
            }
        }
        Ok(written)
    }

    /// Receive decrypted cleartext bytes from the TLS stream.
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, AdapterError> {
        if self.conn.wants_read() {
            self.pump()?;
        }

        let read = self
            .conn
            .reader()
            .read(buf)
            .map_err(AdapterError::from_io)?;
        if read == 0 {
            if self.conn.wants_read() {
                return Err(AdapterError {
                    kind: AdapterErrorKind::IoWouldBlock,
                    outcome: AdapterOutcome::Retryable,
                    message: "no plaintext available yet".to_string(),
                });
            }

            return Err(AdapterError {
                kind: AdapterErrorKind::EndOfStream,
                outcome: AdapterOutcome::EndOfStream,
                message: "peer closed stream".to_string(),
            });
        }

        self.recv_plaintext += read;
        self.observer.on_plaintext_recv(read);
        Ok(read)
    }

    /// Initiate cleartext close and flush TLS close_notify to the transport.
    ///
    /// This operation is idempotent.
    pub fn close_cleartext(&mut self) -> Result<(), AdapterError> {
        // Prevent pathological non-progress loops while still allowing many
        // backpressured iterations to drain close_notify.
        const MAX_CLOSE_PUMP_ITERS: usize = 1024;

        let (next_state, should_emit_close_notify) = self.state.begin_close();
        self.transition_state(next_state);

        if should_emit_close_notify {
            self.conn.send_close_notify();
        }

        for _ in 0..MAX_CLOSE_PUMP_ITERS {
            if !self.conn.wants_write() {
                break;
            }
            let report = self.pump()?;
            if report.tls_written == 0 {
                break;
            }
        }

        if self.conn.wants_write() {
            return Err(AdapterError {
                kind: AdapterErrorKind::Io,
                outcome: AdapterOutcome::Fatal,
                message: "close_notify drain did not complete within iteration limit".to_string(),
            });
        }
        self.transition_state(ClientSessionState::Closed);

        Ok(())
    }

    /// Consume the adapter and return owned connection + transport resources.
    pub fn into_parts(self) -> (ClientConnection, T) {
        (self.conn, self.transport)
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use rustls::Error;

    use super::{
        AdapterError, AdapterErrorKind, AdapterOutcome, ClientSessionState, WASI_TLS_DRAFT_VERSION,
    };

    #[test]
    fn draft_version_locked_to_0_3_0() {
        assert_eq!(WASI_TLS_DRAFT_VERSION, "0.3.0-draft");
    }

    #[test]
    fn classify_would_block_as_retryable() {
        let error = AdapterError::from_io(io::Error::from(io::ErrorKind::WouldBlock));
        assert_eq!(error.kind, AdapterErrorKind::IoWouldBlock);
        assert_eq!(error.outcome, AdapterOutcome::Retryable);
    }

    #[test]
    fn classify_tls_error_as_fatal_protocol() {
        let io_error = io::Error::new(io::ErrorKind::InvalidData, Error::General("boom".into()));
        let error = AdapterError::from_io(io_error);
        assert_eq!(error.kind, AdapterErrorKind::TlsProtocol);
        assert_eq!(error.outcome, AdapterOutcome::Fatal);
    }

    #[test]
    fn close_transition_is_idempotent() {
        let (state, first) = ClientSessionState::Open.begin_close();
        assert_eq!(state, ClientSessionState::Closing);
        assert!(first);

        let (state, second) = state.begin_close();
        assert_eq!(state, ClientSessionState::Closing);
        assert!(!second);
    }
}
