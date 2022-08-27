/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{
    collections::HashMap, future::Future, net::IpAddr, sync::Arc,
    time::Duration,
};

use tokio::{
    sync::{oneshot, Mutex, Notify},
    time::sleep,
};

const SERVICE_TYPE: &str = "_quic._udp";

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(windows, path = "windows/mod.rs")]
mod platform;

#[derive(Clone, Debug)]
pub struct PeerEntry<T> {
    pub identity: T,
    pub instance_id: u64,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct FoundPeer<T> {
    identity: T,
    instance_id: u64,
    hostname: String,
    port: u16,
}

pub type NsdManager = NsdManagerGeneric<platform::NsdManager>;

#[derive(Debug)]
pub struct NsdManagerGeneric<Plat> {
    _plat: Option<Plat>,
    _handle: oneshot::Sender<()>,
}

impl<Plat> NsdManagerGeneric<Plat> {
    pub fn empty() -> Self {
        let (_handle, _) = oneshot::channel();
        Self {
            _plat: None,
            _handle,
        }
    }

    pub fn new<T>(
        socket: crate::socket::Socket<T>,
        service_name: String,
    ) -> Self
    where
        T: crate::application::IdentityCanonicalizer,
        Plat: Interface<T>,
    {
        let (_handle, mut alive) = oneshot::channel();
        let new_peers = Arc::new(NewPeers::default());
        let proxy_peer_found = {
            let new_peers = Arc::clone(&new_peers);
            move |found_peer, ip| {
                let new_peers = Arc::clone(&new_peers);
                async move {
                    let mut guard = new_peers.found.lock().await;
                    guard.entry(found_peer).or_default().push(ip);
                    new_peers.notify.notify_one();
                }
            }
        };
        let socket2 = socket.clone();
        let sleep_time = Duration::from_millis(100);
        let main = async move {
            loop {
                tokio::select!(
                    _ = new_peers.notify.notified() => {},
                    _ = &mut alive => { break; },
                );
                sleep(sleep_time).await;
                for (found_peer, mut addresses) in
                    new_peers.found.lock().await.drain()
                {
                    let socket = socket2.clone();
                    addresses.sort_unstable_by(|a, b| b.cmp(a));
                    tokio::spawn(async move {
                        let _ = socket
                            .connect_local(PeerEntry {
                                identity: found_peer.identity,
                                instance_id: found_peer.instance_id,
                                port: found_peer.port,
                                addresses,
                            })
                            .await;
                    });
                }
            }
        };
        Self {
            _plat: Plat::start(socket, service_name, proxy_peer_found, main),
            _handle,
        }
    }
}

pub trait Interface<T: crate::application::IdentityCanonicalizer>:
    Sized
{
    fn start<Found, FoundFut, Main>(
        socket: crate::Socket<T>,
        service_name: String,
        peer_found: Found,
        main: Main,
    ) -> Option<Self>
    where
        Found: 'static
            + Send
            + Sync
            + Fn(FoundPeer<T::Identity>, IpAddr) -> FoundFut,
        FoundFut: Send + Sync + Future<Output = ()>,
        Main: 'static + Send + Sync + Future<Output = ()>;
}

struct NewPeers<Id> {
    notify: Notify,
    found: Mutex<HashMap<FoundPeer<Id>, Vec<IpAddr>>>,
}

impl<Id> Default for NewPeers<Id> {
    fn default() -> Self {
        Self {
            notify: Notify::default(),
            found: Mutex::default(),
        }
    }
}
