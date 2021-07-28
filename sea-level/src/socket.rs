use std::{
    collections::HashSet, error::Error, future::Future, net::SocketAddr,
    path::Path, sync::Arc, time::Duration,
};

use {
    futures_util::StreamExt,
    quinn::{
        Certificate, CertificateChain, ClientConfig, ClientConfigBuilder,
        Connecting, Connection, Endpoint, NewConnection, PrivateKey,
        ServerConfig, ServerConfigBuilder, TransportConfig,
    },
    tokio::{sync::Mutex, time::timeout},
};

use crate::{
    application::{Application, CertificateResponse},
    util::{send_buf, ConnectionSet},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId<T>(pub T, usize);

type PeerList<T> = Arc<Mutex<ConnectionSet<T>>>;
type ActiveConnections = Arc<Mutex<HashSet<ConnectionIdentity>>>;

#[derive(Debug)]
pub struct Socket<App: Application> {
    app: Arc<App>,
    endpoint: Endpoint,
    peers: PeerList<App::Identity>,
    active_connections: ActiveConnections,
}

impl<App: Application> Clone for Socket<App> {
    fn clone(&self) -> Self {
        Self {
            app: self.app.clone(),
            endpoint: self.endpoint.clone(),
            peers: self.peers.clone(),
            active_connections: self.active_connections.clone(),
        }
    }
}

macro_rules! send_to_many {
    ($connections:expr, $buf:expr $(,)?) => {{
        use ::futures_util::stream::{FuturesUnordered, StreamExt};
        let mut set = FuturesUnordered::new();
        for conn in Iterator::cloned($connections) {
            set.push($crate::util::send_buf(conn, $buf));
        }
        async move { while let Some(()) = set.next().await {} }
    }};
}

impl<App: Application> Socket<App> {
    pub async fn start(app: Arc<App>) -> Result<Self, Box<dyn Error>> {
        let certificate = SocketCertificate::get(&*app).await?;
        let client_cfg = configure_client(&certificate);
        let server_cfg = configure_server(&certificate).unwrap();
        let mut builder = Endpoint::builder();
        builder.default_client_config(client_cfg).listen(server_cfg);
        let (endpoint, incoming) =
            builder.bind(&"[::]:0".parse().unwrap()).unwrap();
        let app2 = Arc::clone(&app);
        let peers = PeerList::default();
        let peers2 = Arc::clone(&peers);
        let active_connections = ActiveConnections::default();
        let active_connections2 = Arc::clone(&active_connections);
        tokio::spawn(async move {
            let mut incoming = incoming;
            while let Some(connecting) = incoming.next().await {
                tokio::spawn(Peer::start(
                    connecting,
                    Arc::clone(&app2),
                    Arc::clone(&peers2),
                    Arc::clone(&active_connections2),
                ));
            }
        });
        Ok(Self {
            app,
            endpoint,
            peers,
            active_connections,
        })
    }

    pub fn port(&self) -> Option<u16> {
        self.endpoint.local_addr().ok().map(|addr| addr.port())
    }

    pub(crate) fn app(&self) -> &Arc<App> {
        &self.app
    }

    pub async fn connect(
        &self,
        addr: SocketAddr,
        identity: App::Identity,
    ) -> Result<(), PeerNotConnected> {
        let hostname = self.app.identity_to_dns(&identity);
        if let Ok(connecting) = self.endpoint.connect(&addr, &hostname) {
            Peer::start(
                connecting,
                Arc::clone(&self.app),
                Arc::clone(&self.peers),
                Arc::clone(&self.active_connections),
            )
            .await
        } else {
            Err(PeerNotConnected)
        }
    }

    pub async fn connect_local(
        &self,
        peer: crate::nsd::PeerEntry<App::Identity>,
    ) -> Result<(), PeerNotConnected> {
        let maybe_self = self.port() == Some(peer.port);
        for ip in peer.addresses {
            let addr = (ip, peer.port).into();
            if maybe_self && tokio::net::UdpSocket::bind((ip, 0)).await.is_ok()
            {
                // the udp bind succeeded, so it's extremely likely this
                // is ourself
                return Ok(());
            }
            if self.connect(addr, peer.identity.clone()).await.is_ok() {
                return Ok(());
            }
        }
        Err(PeerNotConnected)
    }

    pub fn send_to(&self, target: App::Identity, msg: Vec<u8>) {
        let peers = self.peers.clone();
        tokio::spawn(async move {
            let sending;
            {
                let guard = peers.lock().await;
                sending = send_to_many!(guard.connections(target), &msg);
            }
            sending.await;
        });
    }

    pub fn send_to_all(&self, msg: Vec<u8>) {
        let peers = self.peers.clone();
        tokio::spawn(async move {
            let sending;
            {
                let guard = peers.lock().await;
                sending = send_to_many!(guard.iter(), &msg);
            }
            sending.await;
        });
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerNotConnected;

pub struct Peer {
    conn: Connection,
}

impl Peer {
    pub fn send(&self, msg: Vec<u8>) {
        let conn = self.conn.clone();
        tokio::spawn(async move {
            send_buf(conn, &msg).await;
        });
    }

    async fn start<App: Application>(
        connecting: Connecting,
        app: Arc<App>,
        peer_list: PeerList<App::Identity>,
        active_connections: ActiveConnections,
    ) -> Result<(), PeerNotConnected> {
        println!("Peer::start");
        let NewConnection {
            connection,
            mut uni_streams,
            ..
        } = connecting.await.map_err(|e| {
            eprintln!("connecting failed: {}", e);
            PeerNotConnected
        })?;
        if !active_connections
            .lock()
            .await
            .insert(ConnectionIdentity(connection.clone()))
        {
            // this might be vulnerable to a race condition where peers resolve
            // connections in the opposite order and both get closed, but idk
            // if that will happen often enough in practice to matter
            println!(concat!(
                "cancelling connection: already have a connection",
                " with the same identity",
            ));
            return Ok(());
        }
        let peer_port = connection.remote_address().port();
        async fn hello_timeout<T>(
            fut: impl Future<Output = Result<T, PeerNotConnected>>,
        ) -> Result<T, PeerNotConnected> {
            match timeout(Duration::from_secs(5), fut).await {
                Ok(Ok(val)) => Ok(val),
                _ => Err(PeerNotConnected),
            }
        }
        let sending_hello = hello_timeout(async {
            let mut first_stream =
                connection.open_uni().await.map_err(|_| PeerNotConnected)?;
            let buf = app.identity_to_txt(&app.identity());
            first_stream
                .write_all(&buf)
                .await
                .map_err(|_| PeerNotConnected)?;
            Ok(())
        });
        let recving_hello = hello_timeout(async {
            let first_stream = match uni_streams.next().await {
                Some(Ok(stream)) => stream,
                _ => return Err(PeerNotConnected),
            };
            let buf = first_stream
                .read_to_end(app.max_message_size())
                .await
                .map_err(|_| PeerNotConnected)?;
            let hello = app.identity_from_txt(&buf).ok_or(PeerNotConnected)?;
            Ok(hello)
        });
        let ((), hello) = tokio::try_join!(sending_hello, recving_hello)?;
        verify_peer(&connection, &*app, &hello).ok_or_else(|| {
            println!("failed to verify peer");
            PeerNotConnected
        })?;
        let peer_id = PeerId(hello.clone(), connection.stable_id());
        let peer = Self {
            conn: connection.clone(),
        };
        app.handle_new_peer(&peer_id, &peer);
        peer_list
            .lock()
            .await
            .insert(hello.clone(), connection.clone());
        while let Some(Ok(stream)) = uni_streams.next().await {
            println!("message stream recieved");
            let app = Arc::clone(&app);
            let peer_id = peer_id.clone();
            tokio::spawn(async move {
                if let Ok(msg) =
                    stream.read_to_end(app.max_message_size()).await
                {
                    app.handle_message(&peer_id, msg);
                }
            });
        }
        peer_list.lock().await.remove(hello, &connection);
        if !active_connections
            .lock()
            .await
            .remove(&ConnectionIdentity(connection.clone()))
        {
            eprintln!("failed to remove connection from active_connections");
        }
        println!("disconnected from {}", peer_port);
        app.handle_peer_gone(&peer_id);
        std::mem::drop(connection);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionIdentity(Connection);

impl PartialEq for ConnectionIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.0
            .peer_identity()
            .as_ref()
            .and_then(|chain| chain.iter().next())
            .map(AsRef::<[u8]>::as_ref)
            == other
                .0
                .peer_identity()
                .as_ref()
                .and_then(|chain| chain.iter().next())
                .map(AsRef::<[u8]>::as_ref)
    }
}

impl Eq for ConnectionIdentity {}

impl std::hash::Hash for ConnectionIdentity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0
            .peer_identity()
            .as_ref()
            .and_then(|chain| chain.iter().next())
            .map(AsRef::<[u8]>::as_ref)
            .hash(state);
    }
}

pub struct SocketCertificate {
    pub priv_key_der: Vec<u8>,
    pub chain_pem: String,
    pub authority_pem: String,
}

impl SocketCertificate {
    pub async fn get<App: Application>(
        app: &App,
    ) -> Result<Self, Box<dyn Error>> {
        let mut data_dir = app.application_data_dir();
        data_dir.push("instance-certificate");
        if let Some(cert) = Self::load(&data_dir).await? {
            return Ok(cert);
        }
        let new = socket_certificate::<App>(app);
        let CertificateResponse {
            client_chain_pem,
            authority_pem,
        } = app.sign_certificate(&new.serialize_request_pem()?).await?;
        let priv_key_der = new.serialize_private_key_der();
        let this = Self {
            priv_key_der,
            chain_pem: client_chain_pem,
            authority_pem,
        };
        let _ = this.save(&data_dir);
        Ok(this)
    }

    pub async fn load(path: &Path) -> std::io::Result<Option<Self>> {
        use {
            std::io::ErrorKind::NotFound,
            tokio::fs::{read, read_to_string},
        };
        let mut path_key = path.to_path_buf();
        path_key.set_extension("pk8");
        let mut path_chain = path.to_path_buf();
        path_chain.set_extension("pem");
        let mut path_ca = path.to_path_buf();
        path_ca.set_extension("ca.pem");
        match tokio::try_join!(
            read(&path_key),
            read_to_string(&path_chain),
            read_to_string(&path_ca)
        ) {
            Ok((priv_key_der, chain_pem, authority_pem)) => Ok(Some(Self {
                priv_key_der,
                chain_pem,
                authority_pem,
            })),
            Err(e) if e.kind() == NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn save(&self, path: &Path) -> std::io::Result<()> {
        use crate::util::write;
        let mut path_key = path.to_path_buf();
        path_key.set_extension("pk8");
        let mut path_chain = path.to_path_buf();
        path_chain.set_extension("pem");
        let mut path_ca = path.to_path_buf();
        path_ca.set_extension("ca.pem");
        tokio::try_join!(
            write(&path_key, &self.priv_key_der),
            write(&path_chain, self.chain_pem.as_ref()),
            write(&path_ca, self.authority_pem.as_ref()),
        )
        .map(|_| ())
    }
}

fn configure_client(cert: &SocketCertificate) -> ClientConfig {
    let priv_key = rustls::PrivateKey(cert.priv_key_der.clone());
    let chain = CertificateChain::from_pem(cert.chain_pem.as_ref()).unwrap();
    let ca_cert =
        Certificate::from_pem(cert.authority_pem.as_bytes()).unwrap();
    let mut cfg = ClientConfigBuilder::default().build();
    let crypto_cfg = Arc::get_mut(&mut cfg.crypto).unwrap();
    crypto_cfg.root_store.roots.clear();
    crypto_cfg
        .set_single_client_cert(chain.iter().cloned().collect(), priv_key)
        .unwrap();
    cfg.add_certificate_authority(ca_cert).unwrap();
    let trans_cfg = Arc::get_mut(&mut cfg.transport).unwrap();
    trans_cfg
        .keep_alive_interval(Some(Duration::from_secs(1)))
        .max_concurrent_bidi_streams(0)
        .unwrap();
    cfg
}

fn configure_server(
    cert: &SocketCertificate,
) -> Result<ServerConfig, Box<dyn Error>> {
    let priv_key = PrivateKey::from_der(&cert.priv_key_der)?;
    let chain = CertificateChain::from_pem(cert.chain_pem.as_ref()).unwrap();
    let mut transport_config = TransportConfig::default();
    transport_config.max_concurrent_bidi_streams(0).unwrap();
    let mut server_config = ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut allowed_client_signers = rustls::RootCertStore::empty();
    allowed_client_signers
        .add_pem_file(&mut cert.authority_pem.as_ref())
        .unwrap();
    let crypto = Arc::get_mut(&mut server_config.crypto).unwrap();
    crypto.set_client_certificate_verifier(
        rustls::AllowAnyAuthenticatedClient::new(allowed_client_signers),
    );
    let mut cfg_builder = ServerConfigBuilder::new(server_config);
    cfg_builder.certificate(chain, priv_key)?;

    Ok(cfg_builder.build())
}

pub fn socket_certificate<App: Application>(app: &App) -> rcgen::Certificate {
    let hostname = app.identity_to_dns(app.identity());
    let mut params = rcgen::CertificateParams::new([hostname]);
    let now = chrono::Utc::now();
    params.not_before = now;
    params.not_after = now + chrono::Duration::days(30);
    rcgen::Certificate::from_params(params).unwrap()
}

#[derive(Clone, Copy, Debug, Default)]
struct PeerVerified;

#[must_use]
fn verify_peer<App: Application>(
    connection: &Connection,
    app: &App,
    identity: &App::Identity,
) -> Option<PeerVerified> {
    let chain = connection.peer_identity()?;
    let cert = chain.iter().next()?;
    let pki_cert = webpki::EndEntityCert::from(cert.as_ref()).ok()?;
    let hostname = app.identity_to_dns(identity);
    let pki_name = webpki::DNSNameRef::try_from_ascii_str(&hostname).unwrap();
    pki_cert.verify_is_valid_for_dns_name(pki_name).ok()?;
    Some(PeerVerified)
}
