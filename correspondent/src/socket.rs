/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use {
    futures_util::{Stream, StreamExt},
    quinn::{Connection, Endpoint},
    tokio::sync::Mutex,
};

use crate::{
    application::IdentityCanonicalizer,
    nsd::NsdManager,
    peer::start_peer,
    socket_builder::SocketBuilderComplete,
    util::{send_buf, ConnectionSet},
    PeerId, PeerNotConnected,
};

pub(crate) type PeerList<T> = Arc<Mutex<ConnectionSet<T>>>;
pub(crate) type ActiveConnections<T> =
    Arc<Mutex<HashMap<(T, u64), Connection>>>;

pub struct Identity<T: IdentityCanonicalizer> {
    pub(crate) identity: T::Identity,
    pub(crate) identity_txt: Vec<u8>,
    pub(crate) canonicalizer: T,
}

/// A socket handles connections and messages.
pub struct Socket<T: IdentityCanonicalizer> {
    pub(crate) instance_id: u64,
    pub(crate) identity: Arc<Identity<T>>,
    pub(crate) discovery_addr: Option<IpAddr>,
    endpoint: Endpoint,
    peers: PeerList<T::Identity>,
    active_connections: ActiveConnections<T::Identity>,
    runtime: tokio::runtime::Handle,
    post_event: tokio::sync::mpsc::UnboundedSender<InternalEvent<T::Identity>>,
    nsd_manager: Arc<NsdManager>,
}

impl<T: IdentityCanonicalizer> Clone for Socket<T> {
    fn clone(&self) -> Self {
        Self {
            instance_id: self.instance_id,
            identity: Arc::clone(&self.identity),
            discovery_addr: self.discovery_addr,
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

impl<T: IdentityCanonicalizer> Socket<T> {
    /// Start running the socket, listening for incoming connections.
    pub(crate) fn start(
        builder: SocketBuilderComplete<T>,
    ) -> io::Result<(Self, Events<T::Identity>)> {
        let instance_id = rand::Rng::gen(&mut rand::thread_rng());
        let (mut endpoint, incoming) = Endpoint::new(
            builder.endpoint_cfg,
            Some(builder.server_cfg),
            builder.socket,
        )?;
        endpoint.set_default_client_config(builder.client_cfg);
        let identity = Arc::new(builder.identity);
        let identity2 = Arc::clone(&identity);
        let peers = PeerList::default();
        let peers2 = Arc::clone(&peers);
        let active_connections = ActiveConnections::default();
        let active_connections2 = Arc::clone(&active_connections);
        let (post_event, mut recv_event) =
            tokio::sync::mpsc::unbounded_channel();
        let mut events = Events::<T::Identity> {
            streams: futures_util::stream::SelectAll::new(),
        };
        events.streams.push(Box::pin(futures_util::stream::poll_fn(
            move |cx| recv_event.poll_recv(cx),
        )));
        events.streams.push(
            incoming
                .filter_map(move |connecting| {
                    let identity2 = Arc::clone(&identity2);
                    let peers2 = Arc::clone(&peers2);
                    let active_connections2 = Arc::clone(&active_connections2);
                    async move {
                        start_peer(
                            identity2,
                            connecting,
                            instance_id,
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
            identity,
            discovery_addr: builder.discovery_addr,
            endpoint,
            peers,
            active_connections,
            runtime: tokio::runtime::Handle::current(),
            post_event,
            // pass a socket with an empty nsd mananger into the nsd mananger,
            // so as to avoid circular references
            nsd_manager: Arc::new(NsdManager::empty()),
        };
        let nsd_manager =
            Arc::new(NsdManager::new(temp.clone(), builder.service_name.0));
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

    /// Get a reference to the tokio runtime stored in this socket
    pub fn runtime(&self) -> &tokio::runtime::Handle {
        &self.runtime
    }

    /// Manually connect to a specific peer
    async fn connect(
        &self,
        addr: SocketAddr,
        mut identity: T::Identity,
        instance_id: Option<u64>,
    ) -> Result<PeerId<T::Identity>, PeerNotConnected> {
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
        let hostname = self.identity.canonicalizer.to_dns(&identity);
        if let Ok(connecting) = self.endpoint.connect(addr, &hostname) {
            let (peer_id, stream) = start_peer(
                Arc::clone(&self.identity),
                connecting,
                self.instance_id,
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
        peer: crate::nsd::PeerEntry<T::Identity>,
    ) -> Result<(), PeerNotConnected> {
        let maybe_self = self.port() == Some(peer.port)
            && self.instance_id == peer.instance_id;
        for ip in peer.addresses {
            let addr = (ip, peer.port).into();
            if maybe_self && tokio::net::UdpSocket::bind((ip, 0)).await.is_ok()
            {
                // the udp bind succeeded, so it's extremely likely this
                // is ourself
                return Ok(());
            }
            if self
                .connect(addr, peer.identity.clone(), Some(peer.instance_id))
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
        target: PeerId<T::Identity>,
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
        target: PeerId<T::Identity>,
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
    pub fn send_to(&self, target: T::Identity, msg: Vec<u8>) {
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
    pub fn send_to_id(&self, target: PeerId<T::Identity>, msg: Vec<u8>) {
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
#[non_exhaustive]
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

pub(crate) type InternalEventStream<Id> =
    futures_util::stream::BoxStream<'static, InternalEvent<Id>>;

pub(crate) enum InternalEvent<Id> {
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
