//! Pool transport: plain TCP or TLS (rustls, webpki roots), one connection
//! owned by one thread. Lines in, lines out.
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

pub trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// SHA-256 of the pool's certificate, hex. Pools commonly serve a
    /// self-signed certificate (unMineable's runs to 2123), so CA validation
    /// can't be required; with a pin, the certificate must match it, and
    /// without one any certificate is accepted (XMRig's `--tls` behaviour)
    /// and its fingerprint logged.
    pub fingerprint: Option<String>,
}

/// `host:port` is plain TCP; `tls://host:port` (or `stratum+ssl://`) is TLS.
pub fn parse_endpoint(s: &str) -> Option<Endpoint> {
    let (tls, rest) = match s.split_once("://") {
        Some((scheme, rest)) => (scheme.contains("tls") || scheme.contains("ssl"), rest),
        None => (false, s),
    };
    let (host, port) = rest.rsplit_once(':')?;
    Some(Endpoint { host: host.to_string(), port: port.parse().ok()?, tls, fingerprint: None })
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let scheme = if self.tls { "tls://" } else { "" };
        write!(f, "{scheme}{}:{}", self.host, self.port)
    }
}

pub struct Conn {
    stream: Box<dyn Stream>,
    buf: Vec<u8>,
}

impl Conn {
    pub fn connect(ep: &Endpoint) -> Result<Conn, String> {
        let tcp = TcpStream::connect((ep.host.as_str(), ep.port)).map_err(|e| e.to_string())?;
        tcp.set_nodelay(true).ok();
        // Short reads so the owning thread can interleave submits and pings.
        tcp.set_read_timeout(Some(Duration::from_millis(250))).ok();
        let stream: Box<dyn Stream> = if ep.tls {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let webpki = rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                provider.clone(),
            )
            .build()
            .map_err(|e| e.to_string())?;
            let verifier = Arc::new(PoolVerifier {
                webpki,
                pin: ep.fingerprint.as_ref().map(|f| f.replace(':', "").to_lowercase()),
                provider: provider.clone(),
            });
            let cfg = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            let name = rustls::pki_types::ServerName::try_from(ep.host.clone())
                .map_err(|e| e.to_string())?;
            let tls = rustls::ClientConnection::new(Arc::new(cfg), name).map_err(|e| e.to_string())?;
            Box::new(rustls::StreamOwned::new(tls, tcp))
        } else {
            Box::new(tcp)
        };
        Ok(Conn { stream, buf: Vec::new() })
    }

    pub fn send_line(&mut self, line: &str) -> Result<(), String> {
        self.stream.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
        self.stream.write_all(b"\n").map_err(|e| e.to_string())?;
        self.stream.flush().map_err(|e| e.to_string())
    }

    /// Next complete line, or None if nothing arrived within the read timeout.
    pub fn read_line(&mut self) -> Result<Option<String>, String> {
        loop {
            if let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=i).collect();
                return Ok(Some(String::from_utf8_lossy(&line).trim().to_string()));
            }
            if self.buf.len() > 1 << 20 {
                return Err("pool sent an over-long line".into());
            }
            let mut chunk = [0u8; 8192];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err("pool closed the connection".into()),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Ok(None)
                }
                Err(e) => return Err(e.to_string()),
            }
        }
    }
}

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

#[derive(Debug)]
struct PoolVerifier {
    webpki: Arc<rustls::client::WebPkiServerVerifier>,
    pin: Option<String>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

fn sha256_hex(der: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, der)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl ServerCertVerifier for PoolVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = sha256_hex(end_entity);
        if let Some(pin) = &self.pin {
            return if &fp == pin {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::General(format!("certificate {fp} does not match the pin")))
            };
        }
        if self.webpki.verify_server_cert(end_entity, intermediates, server_name, ocsp, now).is_err() {
            eprintln!("tls: unverified pool certificate sha256={fp}");
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
