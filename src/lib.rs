use quinn::{Connection, Endpoint, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{error::Error, net::SocketAddr, sync::Arc};

pub struct StitcherServer {
    endpoint: Endpoint,
    accepting_connections: bool,
}

impl StitcherServer {
    pub fn new(addr: String) -> Self {
        let addr: SocketAddr = addr.parse().unwrap();
        let (certs, key) = generate_self_signed_cert().unwrap();
        let server_config =
            quinn::ServerConfig::with_single_cert(vec![certs], PrivateKeyDer::Pkcs8(key)).unwrap();
        let endpoint = Endpoint::server(server_config, addr).unwrap();
        Self {
            endpoint,
            accepting_connections: false,
        }
    }

    pub async fn accept_connections<F>(&mut self, mut connection_handler: F)
    where
        F: FnMut(Connection),
    {
        self.accepting_connections = true;

        while self.accepting_connections {
            match self.endpoint.accept().await {
                Some(incoming) => {
                    match incoming.await {
                        Ok(connection) => {
                            connection_handler(connection);
                            println!("New connection created");
                        }
                        Err(e) => {
                            println!("New connection failed: {}", e);
                        }
                    };
                }
                None => {}
            }
        }
    }

    pub async fn stop_accepting_connections(&mut self) {
        self.accepting_connections = false;
    }

    pub async fn shutdown(&mut self) {
        self.stop_accepting_connections().await;
        self.endpoint
            .close(VarInt::from_u32(0), b"Shutdown method called.");
    }
}

pub struct StitcherClient {
    endpoint: Endpoint,
    connection: Option<Connection>,
}

impl StitcherClient {
    pub fn new(addr: String) -> Self {
        let addr: SocketAddr = addr.parse().unwrap();

        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();

        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        ));

        let mut endpoint = Endpoint::client(addr).unwrap();
        endpoint.set_default_client_config(client_config);

        Self {
            endpoint,
            connection: None,
        }
    }

    pub async fn connect(&mut self, addr: String) {
        let addr: SocketAddr = addr.parse().unwrap();
        let connection = self
            .endpoint
            .connect(addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        self.connection = Some(connection);
    }

    pub async fn disconnect(&mut self) {
        if let Some(conn) = self.connection.take() {
            conn.close(VarInt::from_u32(0), b"Disconnect method called.");
            self.connection = None;
        }
    }
}

fn generate_self_signed_cert()
-> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>), Box<dyn Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    Ok((cert_der, key))
}

// Custom certificate verifier that accepts any certificate (for testing only!)
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        tokio::spawn(async {
            let mut server = StitcherServer::new("127.0.0.1:3000".into());
            server
                .accept_connections(|c| println!("server got a connection!"))
                .await;
        });

        // Give server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let mut client = StitcherClient::new("127.0.0.1:3001".into());
        client.connect("127.0.0.1:3000".into()).await;
        println!("connected client to server!");
        client.disconnect().await;
        println!("disconnected client from server!");
    }
}
