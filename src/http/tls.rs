use hyper::error::{Error as HyperError, Result as HyperResult};
use hyper::net::{HttpStream, NetworkStream, SslClient};
use openssl::pkcs12::{ParsedPkcs12, Pkcs12};
use openssl::ssl::{Error as SslError, SslConnectorBuilder, SslConnector,
                   SslMethod, SslStream, ShutdownResult};
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;


lazy_static! {
    static ref CONNECTOR: Mutex<Option<Arc<TlsConnector>>> = Mutex::new(None);
}


pub struct TlsData<'p> {
    pub ca_file:  Option<&'p str>,
    pub p12_path: Option<&'p str>,
    pub p12_pass: Option<&'p str>
}

impl<'p> Default for TlsData<'p> {
    fn default() -> Self {
        TlsData { ca_file: None, p12_path: None, p12_pass: None }
    }
}

/// This function *must* be called before `TlsClient::new()`.
pub fn init_tls_client(tls: TlsData) {
    *CONNECTOR.lock().unwrap() = Some(Arc::new(TlsConnector::new(tls)));
}

fn load_p12(p12_path: &str, p12_pass: &str) -> ParsedPkcs12 {
    let mut file = File::open(p12_path).unwrap_or_else(|err| panic!("couldn't open p12 file: {}", err));
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf).unwrap_or_else(|err| panic!("couldn't read p12 file: {}", err));
    let pkcs = Pkcs12::from_der(&buf).unwrap_or_else(|err| panic!("couldn't decode p12 file: {}", err));
    pkcs.parse(p12_pass).unwrap_or_else(|err| panic!("couldn't parse p12 file: {}", err))
}

pub fn write_p12_chain(write_path: &str, p12_path: &str, p12_pass: &str) {
    let p12 = load_p12(p12_path, p12_pass);
    let x509 = p12.chain.get(0).expect("couldn't get CA").to_pem().expect("couldn't convert CA");
    let mut file = File::create(write_path)
        .unwrap_or_else(|err| panic!("couldn't open x509 file {} for writing: {}", write_path, err));
    let _ = file.write_all(&x509).map_err(|err| panic!("couldn't write x509 file {}: {}", write_path, err));
    let _ = file.flush().map_err(|err| panic!("couldn't flush x509 file {}: {}", write_path, err));
}


/// TLS client for HTTPS communication.
pub struct TlsClient(Arc<TlsConnector>);

impl TlsClient {
    pub fn new() -> TlsClient {
        match *CONNECTOR.lock().unwrap() {
            Some(ref connector) => TlsClient(connector.clone()),
            None => panic!("set_certificates not called")
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
            .unwrap_or_else(|err| panic!("couldn't create new SslConnectorBuilder: {}", err));

        tls.ca_file.map(|path| {
            info!("Setting CA certificates to {}.", path);
            let context = builder.builder_mut();
            context.set_ca_file(path).map_err(|err| panic!("couldn't set CA certificates: {}", err))
        });

        tls.p12_path.map(|path| {
            info!("Setting PKCS#12 file to {}.", path);
            let parsed  = load_p12(path, tls.p12_pass.unwrap_or(""));
            let context = builder.builder_mut();
            let _ = context.set_certificate(&parsed.cert)
                .map_err(|err| panic!("couldn't set pkcs12 certificate: {}", err));
            let _ = context.set_private_key(&parsed.pkey)
                .map_err(|err| panic!("couldn't set private key: {}", err));
            let _ = context.check_private_key()
                .map_err(|err| panic!("couldn't validate private key: {}", err));
            debug!("parsed.chain.len(): {}", parsed.chain.len());
            for cert in parsed.chain {
                context.add_extra_chain_cert(cert).expect("Adding extra cert failed");
            }
        });

        TlsConnector(builder.build())
    }

    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, HyperError>
        where S: NetworkStream + Send + Sync + Debug
    {
        self.0.connect(domain, stream).map(TlsStream).map_err(|err| HyperError::Ssl(Box::new(err)))
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
