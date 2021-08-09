/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{
    collections::HashMap, future::Future, net::IpAddr, sync::Arc,
    time::Duration,
};

use tokio::{
    sync::{Mutex, Notify},
    time::sleep,
};

const SERVICE_TYPE: &str = "_quic._udp";

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(windows, path = "windows/mod.rs")]
mod platform;

#[derive(Clone, Debug)]
pub struct PeerEntry<T> {
    pub identity: T,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
}

pub type NsdManager = NsdManagerGeneric<platform::NsdManager>;

#[derive(Debug)]
pub struct NsdManagerGeneric<Plat> {
    _plat: Option<Plat>,
}

impl<Plat> NsdManagerGeneric<Plat> {
    pub fn empty() -> Self {
        Self { _plat: None }
    }

    pub fn new<App>(socket: crate::socket::Socket<App>) -> Self
    where
        App: crate::application::Application,
        Plat: Interface<App>,
    {
        let port = if let Some(port) = socket.port() {
            port
        } else {
            return Self { _plat: None };
        };
        let new_peers = Arc::new(NewPeers::default());
        let proxy_peer_found = {
            let new_peers = Arc::clone(&new_peers);
            move |identity, host, ip, port| {
                let new_peers = Arc::clone(&new_peers);
                async move {
                    let mut guard = new_peers.found.lock().await;
                    guard.entry((host, port, identity)).or_default().push(ip);
                    new_peers.notify.notify_one();
                }
            }
        };
        let app = Arc::clone(socket.app());
        let sleep_time = Duration::from_millis(100);
        let main = async move {
            loop {
                new_peers.notify.notified().await;
                sleep(sleep_time).await;
                for ((_host, port, identity), mut addresses) in
                    new_peers.found.lock().await.drain()
                {
                    let socket = socket.clone();
                    addresses.sort_unstable_by(|a, b| b.cmp(a));
                    tokio::spawn(async move {
                        let res = socket
                            .connect_local(PeerEntry {
                                identity,
                                port,
                                addresses,
                            })
                            .await;
                        if res.is_err() {
                            /*
                            eprintln!(
                                "failed to connect to {}:{}",
                                host, port,
                            );
                            */
                        }
                    });
                }
            }
        };
        Self {
            _plat: Plat::start(
                app,
                None, // TODO: handle non-wildcard?
                port,
                proxy_peer_found,
                main,
            ),
        }
    }
}

pub trait Interface<App: crate::application::Application>: Sized {
    fn start<Found, FoundFut, Main>(
        app: Arc<App>,
        bind_addr: Option<IpAddr>,
        port: u16,
        peer_found: Found,
        main: Main,
    ) -> Option<Self>
    where
        Found: 'static
            + Send
            + Sync
            + Fn(App::Identity, String, IpAddr, u16) -> FoundFut,
        FoundFut: Send + Sync + Future<Output = ()>,
        Main: 'static + Send + Sync + Future<Output = ()>;
}

struct NewPeers<Id> {
    notify: Notify,
    found: Mutex<HashMap<(String, u16, Id), Vec<IpAddr>>>,
}

impl<Id> Default for NewPeers<Id> {
    fn default() -> Self {
        Self {
            notify: Notify::default(),
            found: Mutex::default(),
        }
    }
}
