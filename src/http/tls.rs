use hyper::error::{Error as HyperError, Result as HyperResult};
use hyper::net::{HttpStream, NetworkStream, SslClient};
use openssl::pkcs12::{ParsedPkcs12, Pkcs12 as OpensslPkcs12};
use openssl::pkey::PKey;
use openssl::ssl::{Error as SslError, SslConnectorBuilder, SslConnector,
                   SslMethod, SslStream, ShutdownResult};
use openssl::x509::X509;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;


lazy_static! {
    static ref CONNECTOR: Mutex<Option<Arc<TlsConnector>>> = Mutex::new(None);
}

#[derive(Default)]
pub struct TlsData<'f> {
    pub ca_file:   Option<&'f str>,
    pub cert_file: Option<&'f str>,
    pub pkey_file: Option<&'f str>,
}


/// Encapsulates a parsed PKCS#12 file.
pub struct Pkcs12(ParsedPkcs12);

impl Pkcs12 {
    /// Parse a PKCS#12 file.
    pub fn from_file(p12_path: &str, p12_pass: &str) -> Pkcs12 {
        let mut file = File::open(p12_path).expect("couldn't open p12 file");
        let mut buf = Vec::new();
        let _ = file.read_to_end(&mut buf).expect("couldn't read p12 file");
        Pkcs12::from_der(&buf, p12_pass)
    }

    /// Parse a PKCS#12 bundle.
    pub fn from_der(buf: &[u8], p12_pass: &str) -> Pkcs12 {
        let pkcs = OpensslPkcs12::from_der(&buf).expect("couldn't decode p12 file");
        Pkcs12(pkcs.parse(p12_pass).expect("couldn't parse p12 file"))
    }

    /// Write the PKCS#12 root CA certificate chain to a file.
    pub fn write_chain(&self, ca_file: &str) {
        let x509  = self.0.chain.get(0).expect("couldn't get CA chain");
        let chain = x509.to_pem().expect("couldn't convert CA chain");
        Self::write_file(ca_file, &chain);
    }

    /// Write the PKCS#12 certificate to a file.
    pub fn write_cert(&self, cert_file: &str) {
        let cert = self.0.cert.to_pem().expect("couldn't get certificate");
        Self::write_file(cert_file, &cert);
    }

    /// Write the PKCS#12 private key to a file.
    pub fn write_pkey(&self, pkey_file: &str) {
        let pkey = self.0.pkey.private_key_to_pem().expect("couldn't get private key");
        Self::write_file(pkey_file, &pkey);
    }

    fn write_file(path: &str, buf: &[u8]) {
        let mut file = File::create(path)
            .unwrap_or_else(|err| panic!("couldn't open {} for writing: {}", path, err));
        file.write_all(buf).unwrap_or_else(|err| panic!("couldn't write to {}: {}", path, err));
        file.flush().unwrap_or_else(|err| panic!("couldn't flush {}: {}", path, err));
    }
}


/// TLS client for HTTPS communication.
pub struct TlsClient(Arc<TlsConnector>);

impl TlsClient {
    /// This function *must* be called before `TlsClient::new()`.
    pub fn init(tls: TlsData) {
        *CONNECTOR.lock().unwrap() = Some(Arc::new(TlsConnector::new(tls)));
    }

    pub fn new() -> TlsClient {
        match *CONNECTOR.lock().unwrap() {
            Some(ref connector) => TlsClient(connector.clone()),
            None => panic!("TlsClient::init not called")
        }
    }
}

impl SslClient for TlsClient {
    type Stream = TlsStream<HttpStream>;

    fn wrap_client(&self, stream: HttpStream, host: &str) -> HyperResult<Self::Stream> {
        self.0.connect(host, stream)
    }
}

impl Debug for TlsClient {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_tuple("TlsClient").field(&"_").finish()
    }
}


struct TlsConnector(SslConnector);

impl TlsConnector {
    pub fn new(tls: TlsData) -> TlsConnector {
        let mut builder = SslConnectorBuilder::new(SslMethod::tls())
            .expect("couldn't create SslConnectorBuilder");

        tls.ca_file.map(|path| {
            info!("Setting CA certificates to {}.", path);
            let context = builder.builder_mut();
            context.set_ca_file(path).expect("couldn't set CA certificates");
        });

        tls.cert_file.map(|path| {
            info!("Setting TLS certificate to {}.", path);
            let x509 = X509::from_pem(&Self::read_file(path))
                .expect("couldn't read TLS certificate");
            let context = builder.builder_mut();
            context.set_certificate(&x509).expect("couldn't set TLS certificate");
        });

        tls.pkey_file.map(|path| {
            info!("Setting TLS private key to {}.", path);
            let pkey = PKey::private_key_from_pem(&Self::read_file(path))
                .expect("couldn't read private key");
            let context = builder.builder_mut();
            context.set_private_key(&pkey).expect("couldn't set private key");
            context.check_private_key().expect("couldn't validate private key");
        });

        TlsConnector(builder.build())
    }

    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, HyperError>
        where S: NetworkStream + Send + Sync + Debug
    {
        self.0.connect(domain, stream).map(TlsStream).map_err(|err| HyperError::Ssl(Box::new(err)))
    }

    fn read_file(path: &str) -> Vec<u8> {
        let mut file = File::open(path).unwrap_or_else(|err| panic!("couldn't open {}: {}", path, err));
        let mut buf  = Vec::new();
        let _ = file.read_to_end(&mut buf).unwrap_or_else(|err| panic!("couldn't read {}: {}", path, err));
        buf
    }
}


pub struct TlsStream<S>(SslStream<S>);

impl<S: Debug> Debug for TlsStream<S> {
    fn fmt(&self, fmt: &mut Formatter) -> FmtResult {
        Debug::fmt(&self.0, fmt)
    }
}

impl<S: Read + Write> TlsStream<S> {
    pub fn buffered_read_size(&self) -> Result<usize, ()> {
        Ok(self.0.ssl().pending())
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        loop {
            match self.0.shutdown() {
                Ok(ShutdownResult::Sent)     => {},
                Ok(ShutdownResult::Received) => break,
                Err(SslError::ZeroReturn)    => break,
                Err(SslError::Stream(e))     => return Err(e),
                Err(SslError::WantRead(e))   => return Err(e),
                Err(SslError::WantWrite(e))  => return Err(e),
                Err(err) => return Err(io::Error::new(io::ErrorKind::Other, err)),
            }
        }

        Ok(())
    }

    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<S> Clone for TlsStream<S> {
    fn clone(&self) -> TlsStream<S> {
        unreachable!("TlsStream::clone not used")
    }
}

impl<S: NetworkStream> NetworkStream for TlsStream<S> {
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.0.get_mut().peer_addr()
    }

    fn set_read_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        self.0.get_ref().set_read_timeout(duration)
    }

    fn set_write_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        self.0.get_ref().set_write_timeout(duration)
    }
}
