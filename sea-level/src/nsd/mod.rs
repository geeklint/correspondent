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
    pub player_id: T,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
}

pub type NsdManager = NsdManagerGeneric<platform::NsdManager>;

pub struct NsdManagerGeneric<Plat> {
    _plat: Option<Plat>,
}

impl<Plat> NsdManagerGeneric<Plat> {
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
        let identity = socket.identity().clone();
        let new_peers = Arc::new(NewPeers::default());
        let proxy_peer_found = {
            let new_peers = Arc::clone(&new_peers);
            move |player_id, host, ip, port| {
                let new_peers = Arc::clone(&new_peers);
                async move {
                    let mut guard = new_peers.found.lock().await;
                    guard.entry((host, port, player_id)).or_default().push(ip);
                    new_peers.notify.notify_one();
                }
            }
        };
        let sleep_time = Duration::from_millis(100);
        let main = async move {
            loop {
                new_peers.notify.notified().await;
                sleep(sleep_time).await;
                for ((_host, port, player_id), mut addresses) in
                    new_peers.found.lock().await.drain()
                {
                    let socket = socket.clone();
                    addresses.sort_unstable_by(|a, b| b.cmp(a));
                    tokio::spawn(async move {
                        let res = socket
                            .connect_local(PeerEntry {
                                player_id,
                                port,
                                addresses,
                            })
                            .await;
                        if res.is_err() {
                            /*
                            eprintln!(
                                "failed to connect to {}@(local):{}",
                                player_id, port,
                            );
                            */
                        }
                    });
                }
            }
        };
        Self {
            _plat: Plat::start(
                identity,
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
        identity: App::Identity,
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
