/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::Arc,
};

use quinn::{ClientConfig, EndpointConfig, ServerConfig};

use crate::{application::IdentityCanonicalizer, socket::Identity};

/// Required information correspondent uses to verify the identity of peers
pub struct SocketCertificate {
    /// Private key the socket to be created should use.
    pub priv_key: rustls::PrivateKey,

    /// The certificate chain the socket to be created should advertize.
    pub chain: Vec<rustls::Certificate>,

    /// The authority certificates peers must be signed by to be trusted.
    pub authority: rustls::RootCertStore,
}

impl SocketCertificate {
    /// Deserialize a SocketCertificate from PEM and DER formats.
    ///
    /// PEM is used for certificate data and DER is used for private key data.
    pub fn from_data(
        priv_key_der: Vec<u8>,
        chain_pem: String,
        authority_pem: String,
    ) -> std::io::Result<Self> {
        let priv_key = rustls::PrivateKey(priv_key_der);
        let chain = rustls_pemfile::certs(&mut chain_pem.as_bytes())
            .map(|r| r.map(|cert| rustls::Certificate(cert.to_vec())))
            .collect::<Result<_, _>>()?;
        let mut authority = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut authority_pem.as_bytes()) {
            let cert = cert?;
            let _ = authority.add(&rustls::Certificate(cert.to_vec()));
        }
        Ok(Self {
            priv_key,
            chain,
            authority,
        })
    }

    /// Get the DER-formatted version of the private key
    pub fn serialize_private_key_der(&self) -> &Vec<u8> {
        &self.priv_key.0
    }

    /// Get the PEM-formatted version of the certificate chain
    pub fn serialize_chain_pem(&self) -> String {
        let mut chain_pem = String::new();
        for cert in self.chain.iter().cloned() {
            chain_pem += &pem::encode(&pem::Pem {
                tag: "CERTIFICATE".to_string(),
                contents: cert.0,
            });
        }
        chain_pem
    }
}

/// Options for configuring the creation of a socket.
///
/// The builder exposes the ability to configure the socket's identity, the
/// DNS-SD service, and the quic endpoint.
#[non_exhaustive]
pub struct SocketBuilder<
    Id,
    ServiceName,
    UdpSocket,
    EndpointConfig,
    ClientConfig,
    ServerConfig,
> {
    pub(crate) identity: Id,
    pub(crate) service_name: ServiceName,
    pub(crate) socket: UdpSocket,
    pub(crate) discovery_addr: Option<IpAddr>,
    pub(crate) endpoint_cfg: EndpointConfig,

    /// [`ClientConfig`], if available, after configured by `with_certificate`
    /// or `with_new_certificate`
    pub client_cfg: ClientConfig,

    /// [`ServerConfig`], if available, after configured by `with_certificate`
    /// or `with_new_certificate`
    pub server_cfg: ServerConfig,
}

pub type SocketBuilderComplete<T, EC = EndpointConfig> = SocketBuilder<
    Identity<T>,
    ServiceName,
    UdpSocket,
    EC,
    ClientConfig,
    ServerConfig,
>;

impl<T, EC> SocketBuilderComplete<T, EC>
where
    T: IdentityCanonicalizer,
    EC: Into<EndpointConfig>,
{
    /// Finishs building a socket and starts both the DNS-SD service and
    /// quic Endpoint.
    pub fn start(
        self,
    ) -> io::Result<(crate::Socket<T>, crate::Events<T::Identity>)> {
        crate::Socket::start(SocketBuilder {
            identity: self.identity,
            service_name: self.service_name,
            socket: self.socket,
            discovery_addr: self.discovery_addr,
            endpoint_cfg: self.endpoint_cfg.into(),
            client_cfg: self.client_cfg,
            server_cfg: self.server_cfg,
        })
    }
}

impl
    SocketBuilder<
        NoIdentity,
        NoServiceName,
        NoUdpSocket,
        DefaultEndpointConfig,
        NoClientConfig,
        NoServerConfig,
    >
{
    /// Creates blank SocketBuilder ready for configuration
    ///
    /// All options must be specified before calling [`start`](SocketBuilder::start).
    pub fn new() -> Self {
        SocketBuilder {
            identity: NoIdentity,
            service_name: NoServiceName,
            socket: NoUdpSocket,
            discovery_addr: None,
            endpoint_cfg: DefaultEndpointConfig,
            client_cfg: NoClientConfig,
            server_cfg: NoServerConfig,
        }
    }
}

impl Default
    for SocketBuilder<
        NoIdentity,
        NoServiceName,
        NoUdpSocket,
        DefaultEndpointConfig,
        NoClientConfig,
        NoServerConfig,
    >
{
    fn default() -> Self {
        Self::new()
    }
}

impl<SN, US, EC, CC, SC> SocketBuilder<NoIdentity, SN, US, EC, CC, SC> {
    /// Sets the identity the socket will have and the canonicalizer used
    /// to convert identities to the network format(s).
    pub fn with_identity<T: IdentityCanonicalizer>(
        self,
        identity: T::Identity,
        canonicalizer: T,
    ) -> SocketBuilder<Identity<T>, SN, US, EC, CC, SC> {
        let identity_txt = canonicalizer.to_txt(&identity);
        SocketBuilder {
            identity: Identity {
                identity,
                identity_txt,
                canonicalizer,
            },
            service_name: self.service_name,
            socket: self.socket,
            discovery_addr: self.discovery_addr,
            endpoint_cfg: self.endpoint_cfg,
            client_cfg: self.client_cfg,
            server_cfg: self.server_cfg,
        }
    }
}

impl<Id, US, EC, CC, SC> SocketBuilder<Id, NoServiceName, US, EC, CC, SC> {
    /// Sets the DNS-SD service name used by the socket to advertize itself
    /// on the local network.
    pub fn with_service_name(
        self,
        name: String,
    ) -> SocketBuilder<Id, ServiceName, US, EC, CC, SC> {
        SocketBuilder {
            identity: self.identity,
            service_name: ServiceName(name),
            socket: self.socket,
            discovery_addr: self.discovery_addr,
            endpoint_cfg: self.endpoint_cfg,
            client_cfg: self.client_cfg,
            server_cfg: self.server_cfg,
        }
    }
}

impl<Id, SN, EC, CC, SC> SocketBuilder<Id, SN, NoUdpSocket, EC, CC, SC> {
    /// Manually specifies a socket to use for the quic endpoint.
    ///
    /// This socket can be pre-configured with a crate like socket2, although
    /// for correct async behavior it may be required to set the socket to
    /// nonblocking mode.
    ///
    /// `discovery_addr` is the address advertized on the DNS-SD service, or
    /// None to advertize all local ip addresses.
    pub fn with_socket(
        self,
        socket: UdpSocket,
        discovery_addr: Option<IpAddr>,
    ) -> SocketBuilder<Id, SN, UdpSocket, EC, CC, SC> {
        SocketBuilder {
            identity: self.identity,
            service_name: self.service_name,
            socket,
            discovery_addr,
            endpoint_cfg: self.endpoint_cfg,
            client_cfg: self.client_cfg,
            server_cfg: self.server_cfg,
        }
    }

    /// Sets up the socket with the recomended settings.
    pub fn with_recommended_socket(
        self,
    ) -> io::Result<SocketBuilder<Id, SN, UdpSocket, EC, CC, SC>> {
        use socket2::{Domain, Protocol, Socket, Type};
        let addr: SocketAddr = "[::]:0"
            .parse()
            .expect("failed to parse known valid socket address");
        let socket =
            Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        socket.set_only_v6(false)?;
        socket.bind(&addr.into())?;
        Ok(SocketBuilder {
            identity: self.identity,
            service_name: self.service_name,
            socket: socket.into(),
            discovery_addr: None,
            endpoint_cfg: self.endpoint_cfg,
            client_cfg: self.client_cfg,
            server_cfg: self.server_cfg,
        })
    }
}

impl<Id, SN, US, CC, SC>
    SocketBuilder<Id, SN, US, DefaultEndpointConfig, CC, SC>
{
    /// Specifies the config for the quic endpoint.
    pub fn with_endpoint_cfg(
        self,
        endpoint_cfg: EndpointConfig,
    ) -> SocketBuilder<Id, SN, US, EndpointConfig, CC, SC> {
        SocketBuilder {
            identity: self.identity,
            service_name: self.service_name,
            socket: self.socket,
            discovery_addr: self.discovery_addr,
            endpoint_cfg,
            client_cfg: self.client_cfg,
            server_cfg: self.server_cfg,
        }
    }
}

impl<Id, SN, US, EC>
    SocketBuilder<Id, SN, US, EC, NoClientConfig, NoServerConfig>
{
    /// Specifies the socket should use the provided certificate and authority
    /// for authenticating with peers.
    pub fn with_certificate(
        self,
        cert: SocketCertificate,
    ) -> Result<
        SocketBuilder<Id, SN, US, EC, ClientConfig, ServerConfig>,
        rustls::Error,
    > {
        let client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(cert.authority.clone())
            .with_single_cert(cert.chain.clone(), cert.priv_key.clone())?;
        let server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(
                rustls::server::AllowAnyAuthenticatedClient::new(
                    cert.authority,
                ),
            )
            .with_single_cert(cert.chain, cert.priv_key)?;
        let client_cfg = ClientConfig::new(Arc::new(client_crypto));
        let server_cfg = ServerConfig::with_crypto(Arc::new(server_crypto));
        Ok(SocketBuilder {
            identity: self.identity,
            service_name: self.service_name,
            socket: self.socket,
            discovery_addr: self.discovery_addr,
            endpoint_cfg: self.endpoint_cfg,
            client_cfg,
            server_cfg,
        })
    }
}

impl<T, SN, US, EC>
    SocketBuilder<Identity<T>, SN, US, EC, NoClientConfig, NoServerConfig>
where
    T: IdentityCanonicalizer,
{
    /// Generate a new certificate and use it for authenticating with peers.
    pub async fn with_new_certificate<S>(
        self,
        valid_for: std::time::Duration,
        mut signer: S,
    ) -> Result<
        SocketBuilder<Identity<T>, SN, US, EC, ClientConfig, ServerConfig>,
        CertificateGenerationError<S::SigningError>,
    >
    where
        S: CertificateSigner,
    {
        use CertificateGenerationError as Err;
        let hostname =
            self.identity.canonicalizer.to_dns(&self.identity.identity);
        let mut params = rcgen::CertificateParams::new([hostname]);
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + valid_for;
        let new_cert = rcgen::Certificate::from_params(params)
            .map_err(Err::Generation)?;
        let csr = new_cert.serialize_request_pem().map_err(Err::Generation)?;
        let resp =
            signer.sign_certificate(&csr).await.map_err(Err::Signing)?;
        let CertificateResponse {
            chain_pem,
            authority_pem,
        } = resp;
        let priv_key_der = new_cert.serialize_private_key_der();
        signer.save_private_key(&priv_key_der);
        self.with_certificate(
            SocketCertificate::from_data(
                priv_key_der,
                chain_pem,
                authority_pem,
            )
            .map_err(Err::Parsing)?,
        )
        .map_err(Err::Config)
    }
}

#[derive(Debug)]
pub enum CertificateGenerationError<T> {
    Generation(rcgen::RcgenError),
    Signing(T),
    Parsing(io::Error),
    Config(rustls::Error),
}

/// Type to return from [`CertificateSigner::sign_certificate`].
#[derive(Clone, Debug)]
pub struct CertificateResponse {
    /// PEM-formatted signed certificate chain.
    pub chain_pem: String,

    /// PEM-formatted certificate authority to validate peer certificates
    /// against.
    pub authority_pem: String,
}

/// Used by [`SocketBuilder::with_new_certificate`] to sign the newly generated
/// certificate.
pub trait CertificateSigner {
    /// Error type if signing failed.
    type SigningError;

    /// Future for signing certificate.
    type SigningFuture: Future<
        Output = Result<CertificateResponse, Self::SigningError>,
    >;

    /// Sign a certificate based on a PEM-formatted certificate signing
    /// request.
    fn sign_certificate(&mut self, csr_pem: &str) -> Self::SigningFuture;

    /// Save the private key (e.g. to disk) so it can be used to create future
    /// sockets. Saving private keys to a public place may compromise security.
    fn save_private_key(&mut self, key: &[u8]) {
        let _ = key;
    }
}

impl<Func, Fut, Err> CertificateSigner for Func
where
    Func: FnMut(&str) -> Fut,
    Fut: Future<Output = Result<CertificateResponse, Err>>,
{
    type SigningError = Err;
    type SigningFuture = Fut;
    fn sign_certificate(&mut self, csr_pem: &str) -> Self::SigningFuture {
        (self)(csr_pem)
    }
}

pub struct NoIdentity;
pub struct NoServiceName;
pub struct NoUdpSocket;
pub struct DefaultEndpointConfig;
pub struct NoClientConfig;
pub struct NoServerConfig;
pub struct ServiceName(pub(crate) String);

impl From<DefaultEndpointConfig> for EndpointConfig
where
    EndpointConfig: Default,
{
    fn from(_: DefaultEndpointConfig) -> Self {
        EndpointConfig::default()
    }
}
