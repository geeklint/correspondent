/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{
    collections::HashMap, error::Error, future::Future, net::SocketAddr,
    path::Path, sync::Arc, time::Duration,
};

use {
    futures_util::{Stream, StreamExt},
    quinn::{
        Certificate, CertificateChain, ClientConfig, ClientConfigBuilder,
        Connecting, Connection, Endpoint, NewConnection, PrivateKey,
        ServerConfig, ServerConfigBuilder, TransportConfig,
    },
    tokio::{sync::Mutex, time::timeout},
};

use crate::{
    application::{Application, CertificateResponse},
    nsd::NsdManager,
    util::{send_buf, ConnectionSet},
};

/// Unique identifier for a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId<T> {
    /// Identity advertised by the peer
    pub identity: T,

    /// A unique identifier for the connection
    pub unique: usize,
}

type PeerList<T> = Arc<Mutex<ConnectionSet<T>>>;
type ActiveConnections<T> = Arc<Mutex<HashMap<(T, u64), Connection>>>;

/// A socket handles connections and messages.
pub struct Socket<App: Application> {
    instance_id: u64,
    app: Arc<App>,
    endpoint: Endpoint,
    peers: PeerList<App::Identity>,
    active_connections: ActiveConnections<App::Identity>,
    runtime: tokio::runtime::Handle,
    post_event:
        tokio::sync::mpsc::UnboundedSender<InternalEvent<App::Identity>>,
    nsd_manager: Arc<NsdManager>,
}

impl<App: Application> Clone for Socket<App> {
    fn clone(&self) -> Self {
        Self {
            instance_id: self.instance_id,
            app: Arc::clone(&self.app),
            endpoint: self.endpoint.clone(),
            peers: Arc::clone(&self.peers),
            active_connections: Arc::clone(&self.active_connections),
            runtime: self.runtime.clone(),
            post_event: self.post_event.clone(),
            nsd_manager: Arc::clone(&self.nsd_manager),
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
    /// Start running the socket, listening for incoming connections.
    pub async fn start(
        app: Arc<App>,
    ) -> Result<(Self, Events<App::Identity>), Box<dyn Error>> {
        let instance_id = rand::Rng::gen(&mut rand::thread_rng());
        let certificate = SocketCertificate::get(&*app).await?;
        let client_cfg = configure_client(&certificate)?;
        let server_cfg = configure_server(&certificate)?;
        let mut builder = Endpoint::builder();
        builder.default_client_config(client_cfg).listen(server_cfg);
        let bind_addr = if cfg!(windows) {
            "0.0.0.0:0".parse()
        } else {
            "[::]:0".parse()
        };
        let (endpoint, incoming) = builder
            .bind(&bind_addr.expect("Failed to parse known valid SockAddr"))?;
        let app2 = Arc::clone(&app);
        let peers = PeerList::default();
        let peers2 = Arc::clone(&peers);
        let active_connections = ActiveConnections::default();
        let active_connections2 = Arc::clone(&active_connections);
        let (post_event, mut recv_event) =
            tokio::sync::mpsc::unbounded_channel();
        let mut events = Events::<App::Identity> {
            streams: futures_util::stream::SelectAll::new(),
        };
        events.streams.push(Box::pin(futures_util::stream::poll_fn(
            move |cx| recv_event.poll_recv(cx),
        )));
        events.streams.push(
            incoming
                .filter_map(move |connecting| {
                    let app2 = Arc::clone(&app2);
                    let peers2 = Arc::clone(&peers2);
                    let active_connections2 = Arc::clone(&active_connections2);
                    async move {
                        Peer::start(
                            connecting,
                            instance_id,
                            app2,
                            peers2,
                            active_connections2,
                        )
                        .await
                        .ok()
                        .map(|(_pid, stream)| InternalEvent::NewStream(stream))
                    }
                })
                .boxed(),
        );
        let temp = Self {
            instance_id,
            app,
            endpoint,
            peers,
            active_connections,
            runtime: tokio::runtime::Handle::current(),
            post_event,
            // pass a socket with an empty nsd mananger into the nsd mananger,
            // so as to avoid circular references
            nsd_manager: Arc::new(NsdManager::empty()),
        };
        let nsd_manager = Arc::new(NsdManager::new(temp.clone()));
        // return a version with a real NsdManager
        Ok((
            Self {
                nsd_manager,
                ..temp
            },
            events,
        ))
    }

    /// Access the internal endpoint object.
    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }

    /// Try to get the port this socket is operating on.
    pub fn port(&self) -> Option<u16> {
        self.endpoint.local_addr().ok().map(|addr| addr.port())
    }

    /// Get a reference to the application stored in this socket
    pub fn app(&self) -> &Arc<App> {
        &self.app
    }

    pub(crate) fn instance_id(&self) -> u64 {
        self.instance_id
    }

    /// Manually connect to a specific peer
    pub async fn connect(
        &self,
        addr: SocketAddr,
        identity: App::Identity,
    ) -> Result<PeerId<App::Identity>, PeerNotConnected> {
        self.connect2(addr, identity, None).await
    }

    async fn connect2(
        &self,
        addr: SocketAddr,
        mut identity: App::Identity,
        instance_id: Option<u64>,
    ) -> Result<PeerId<App::Identity>, PeerNotConnected> {
        if let Some(ins_id) = instance_id {
            let guard = self.active_connections.lock().await;
            let key = (identity, ins_id);
            if let Some(existing_conn) = guard.get(&key) {
                return Ok(PeerId {
                    identity: key.0,
                    unique: existing_conn.stable_id(),
                });
            }
            identity = key.0;
        }
        let hostname = self.app.identity_to_dns(&identity);
        if let Ok(connecting) = self.endpoint.connect(&addr, &hostname) {
            let (peer_id, stream) = Peer::start(
                connecting,
                self.instance_id,
                Arc::clone(&self.app),
                Arc::clone(&self.peers),
                Arc::clone(&self.active_connections),
            )
            .await?;
            let _ = self.post_event.send(InternalEvent::NewStream(stream));
            Ok(peer_id)
        } else {
            Err(PeerNotConnected)
        }
    }

    pub(crate) async fn connect_local(
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
            if self
                .connect2(addr, peer.identity.clone(), Some(peer.instance_id))
                .await
                .is_ok()
            {
                return Ok(());
            }
        }
        Err(PeerNotConnected)
    }

    /// Open a unidirectional stream to a specific peer
    pub async fn open_uni(
        &self,
        target: PeerId<App::Identity>,
    ) -> Result<quinn::SendStream, PeerNotConnected> {
        let peers = Arc::clone(&self.peers);
        let connection = {
            let guard = peers.lock().await;
            guard
                .get_connection(target.identity, target.unique)
                .ok_or(PeerNotConnected)?
        };
        connection.open_uni().await.map_err(|_e| PeerNotConnected)
    }

    /// Open a bidirectional stream to a specific peer
    pub async fn open_bi(
        &self,
        target: PeerId<App::Identity>,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), PeerNotConnected> {
        let peers = Arc::clone(&self.peers);
        let connection = {
            let guard = peers.lock().await;
            guard
                .get_connection(target.identity, target.unique)
                .ok_or(PeerNotConnected)?
        };
        connection.open_bi().await.map_err(|_e| PeerNotConnected)
    }

    /// Send a message to all connected peers with the specified identity
    pub fn send_to(&self, target: App::Identity, msg: Vec<u8>) {
        let peers = Arc::clone(&self.peers);
        self.runtime.spawn(async move {
            let sending;
            {
                let guard = peers.lock().await;
                sending = send_to_many!(guard.connections(target), &msg);
            }
            sending.await;
        });
    }

    /// Send a message to a specific peer with the given id
    pub fn send_to_id(&self, target: PeerId<App::Identity>, msg: Vec<u8>) {
        let peers = Arc::clone(&self.peers);
        self.runtime.spawn(async move {
            let sending;
            {
                let guard = peers.lock().await;
                sending = match guard
                    .get_connection(target.identity, target.unique)
                {
                    Some(conn) => send_buf(conn, &msg),
                    None => return,
                };
            }
            sending.await;
        });
    }

    /// Send a message to all connected peers.
    pub fn send_to_all(&self, msg: Vec<u8>) {
        let peers = Arc::clone(&self.peers);
        self.runtime.spawn(async move {
            let sending;
            {
                let guard = peers.lock().await;
                sending = send_to_many!(guard.iter(), &msg);
            }
            sending.await;
        });
    }
}

/// A network event on the correspondent Socket
pub enum Event<Id> {
    /// Fired when a new peer has connected
    NewPeer(PeerId<Id>, quinn::Connection),
    /// Fired when a peer has disconnected
    PeerGone(PeerId<Id>),
    /// Fired when a peer opens a new unidirectional stream
    UniStream(PeerId<Id>, quinn::RecvStream),
    /// Fired when a peer opens a new bidirectional stream
    BiStream(PeerId<Id>, quinn::SendStream, quinn::RecvStream),
}

type InternalEventStream<Id> =
    futures_util::stream::BoxStream<'static, InternalEvent<Id>>;

enum InternalEvent<Id> {
    Event(Event<Id>),
    NewStream(InternalEventStream<Id>),
}

/// Stream of events happening on the correspondent Socket
pub struct Events<Id> {
    streams: futures_util::stream::SelectAll<InternalEventStream<Id>>,
}

impl<Id> Stream for Events<Id> {
    type Item = Event<Id>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll::*;
        let this = self.get_mut();
        loop {
            match std::pin::Pin::new(&mut this.streams).poll_next(cx) {
                Pending => return Pending,
                Ready(None) => return Ready(None),
                Ready(Some(InternalEvent::Event(event))) => {
                    return Ready(Some(event));
                }
                Ready(Some(InternalEvent::NewStream(stream))) => {
                    this.streams.push(stream);
                }
            }
        }
    }
}

/// Error returned by Socket::connect if an error happens when connecting to
/// a peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerNotConnected;

/// A reference to a specific peer connection.
pub struct Peer {
    conn: Connection,
}

impl Peer {
    /// Send a message to this peer.
    pub fn send(&self, msg: Vec<u8>) {
        let conn = self.conn.clone();
        tokio::spawn(async move {
            send_buf(conn, &msg).await;
        });
    }

    async fn start<App: Application>(
        connecting: Connecting,
        our_instance_id: u64,
        app: Arc<App>,
        peer_list: PeerList<App::Identity>,
        active_connections: ActiveConnections<App::Identity>,
    ) -> Result<
        (PeerId<App::Identity>, InternalEventStream<App::Identity>),
        PeerNotConnected,
    > {
        let NewConnection {
            connection,
            mut uni_streams,
            bi_streams,
            ..
        } = connecting.await.map_err(|_e| PeerNotConnected)?;
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
            let buf = app.identity_to_txt(app.identity());
            first_stream
                .write_all(&our_instance_id.to_be_bytes())
                .await
                .map_err(|_| PeerNotConnected)?;
            first_stream
                .write_all(&buf)
                .await
                .map_err(|_| PeerNotConnected)?;
            Ok(())
        });
        let recving_hello = hello_timeout(async {
            let mut first_stream = match uni_streams.next().await {
                Some(Ok(stream)) => stream,
                _ => return Err(PeerNotConnected),
            };
            let mut instance_id_bytes = [0; 8];
            first_stream
                .read_exact(&mut instance_id_bytes)
                .await
                .map_err(|_| PeerNotConnected)?;
            let buf = first_stream
                .read_to_end(256)
                .await
                .map_err(|_| PeerNotConnected)?;
            let hello = app.identity_from_txt(&buf).ok_or(PeerNotConnected)?;
            Ok((u64::from_be_bytes(instance_id_bytes), hello))
        });
        let ((), (peer_instance_id, hello)) =
            tokio::try_join!(sending_hello, recving_hello)?;
        verify_peer(&connection, &*app, &hello).ok_or(PeerNotConnected)?;

        let peer_instance_id = (hello.clone(), peer_instance_id);

        {
            let mut guard = active_connections.lock().await;
            // TODO: replace with try_insert
            if let Some(existing_conn) = guard.get(&peer_instance_id) {
                let peer_id = PeerId {
                    identity: peer_instance_id.0,
                    unique: existing_conn.stable_id(),
                };
                // this might be vulnerable to a race condition where peers resolve
                // connections in the opposite order and both get closed, but idk
                // if that will happen often enough in practice to matter
                connection
                    .close(0_u8.into(), "correspondent: duplicate".as_bytes());
                return Ok((peer_id, futures_util::stream::empty().boxed()));
            } else {
                guard.insert(peer_instance_id.clone(), connection.clone());
            }
        }

        let peer_id = PeerId {
            identity: hello.clone(),
            unique: connection.stable_id(),
        };

        peer_list
            .lock()
            .await
            .insert(hello.clone(), connection.clone());

        use crate::util::insert::StreamInsertExt;

        Ok((
            peer_id.clone(),
            futures_util::stream::once({
                let peer_id = peer_id.clone();
                let connection = connection.clone();
                futures_util::future::lazy(|_cx| {
                    InternalEvent::Event(Event::NewPeer(peer_id, connection))
                })
            })
            .chain({
                let peer_id_uni = peer_id.clone();
                let peer_id_bi = peer_id.clone();
                futures_util::stream::select(
                    uni_streams.scan((), move |(), maybe_stream| {
                        let item = match maybe_stream {
                            Ok(stream) => Some(InternalEvent::Event(
                                Event::UniStream(peer_id_uni.clone(), stream),
                            )),
                            Err(_) => None,
                        };
                        async { item }
                    }),
                    bi_streams.scan((), move |(), maybe_stream| {
                        let item = match maybe_stream {
                            Ok((send, recv)) => {
                                Some(InternalEvent::Event(Event::BiStream(
                                    peer_id_bi.clone(),
                                    send,
                                    recv,
                                )))
                            }
                            Err(_) => None,
                        };
                        async { item }
                    }),
                )
            })
            .chain(futures_util::stream::once(async move {
                InternalEvent::Event(Event::PeerGone(peer_id.clone()))
            }))
            .insert_boxed({
                let connection = connection.clone();
                async move {
                    let mut peer_list_guard = peer_list.lock().await;
                    let mut active_conn_guard =
                        active_connections.lock().await;
                    peer_list_guard.remove(hello, &connection);
                    active_conn_guard.remove(&peer_instance_id);
                }
            })
            .boxed(),
        ))
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
        std::fs::create_dir_all(&data_dir)?;
        data_dir.push("instance-certificate");
        if let Some(cert) = Self::load(&data_dir).await? {
            let (_rem, pem) =
                x509_parser::pem::parse_x509_pem(cert.chain_pem.as_bytes())?;
            let parsed = pem.parse_x509()?;
            if parsed.validity().is_valid() {
                return Ok(cert);
            }
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

fn configure_client(
    cert: &SocketCertificate,
) -> Result<ClientConfig, Box<dyn Error>> {
    let priv_key = rustls::PrivateKey(cert.priv_key_der.clone());
    let chain = CertificateChain::from_pem(cert.chain_pem.as_ref())?;
    let ca_cert = Certificate::from_pem(cert.authority_pem.as_bytes())?;
    let mut cfg = ClientConfigBuilder::default().build();
    let crypto_cfg =
        Arc::get_mut(&mut cfg.crypto).expect("Arc::get_mut failed");
    crypto_cfg.root_store.roots.clear();
    crypto_cfg
        .set_single_client_cert(chain.iter().cloned().collect(), priv_key)?;
    cfg.add_certificate_authority(ca_cert)?;
    let trans_cfg =
        Arc::get_mut(&mut cfg.transport).expect("Arc::get_mut failed");
    trans_cfg.keep_alive_interval(Some(Duration::from_secs(1)));
    Ok(cfg)
}

fn configure_server(
    cert: &SocketCertificate,
) -> Result<ServerConfig, Box<dyn Error>> {
    let priv_key = PrivateKey::from_der(&cert.priv_key_der)?;
    let chain = CertificateChain::from_pem(cert.chain_pem.as_ref())?;
    let mut server_config = ServerConfig::default();
    let mut allowed_client_signers = rustls::RootCertStore::empty();
    allowed_client_signers
        .add_pem_file(&mut cert.authority_pem.as_ref())
        .map_err(|()| {
            "Failed to add certificate authority as an allowed client signer"
        })?;
    let crypto =
        Arc::get_mut(&mut server_config.crypto).expect("Arc::get_mut failed");
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
    rcgen::Certificate::from_params(params)
        .expect("Failed to create socket certificate")
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
    let pki_name = webpki::DNSNameRef::try_from_ascii_str(&hostname)
        .expect("Application::identity_to_dns returned invalid DNS name");
    pki_cert.verify_is_valid_for_dns_name(pki_name).ok()?;
    Some(PeerVerified)
}
