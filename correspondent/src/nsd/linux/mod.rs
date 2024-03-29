/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{
    borrow::Cow, fmt::Write, future::Future, net::IpAddr, sync::Arc,
    time::Duration,
};

use {
    dbus::{
        message::SignalArgs,
        nonblock::{MsgMatch, Proxy, SyncConnection},
    },
    dbus_tokio::connection,
    futures_util::future::{FutureExt, RemoteHandle},
};

#[allow(clippy::many_single_char_names)]
#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::single_component_path_imports)]
mod avahi;
#[allow(clippy::many_single_char_names)]
#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::single_component_path_imports)]
mod avahi_entry_group;
#[allow(clippy::many_single_char_names)]
#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::single_component_path_imports)]
mod avahi_service_browser;

use avahi::OrgFreedesktopAvahiServer;
use avahi_entry_group::OrgFreedesktopAvahiEntryGroup as EntryGroup;
use avahi_service_browser::OrgFreedesktopAvahiServiceBrowserItemNew as ItemNew;

pub struct NsdManager {
    _handles: Option<(
        RemoteHandle<connection::IOResourceError>,
        Arc<SyncConnection>,
    )>,
}

impl<T> super::Interface<T> for NsdManager
where
    T: crate::application::IdentityCanonicalizer,
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
            + Fn(super::FoundPeer<T::Identity>, IpAddr) -> FoundFut,
        FoundFut: Send + Sync + Future<Output = ()>,
        Main: 'static + Send + Sync + Future<Output = ()>,
    {
        // Connect to the D-Bus session bus (this is blocking, unfortunately).
        let (resource, conn) = connection::new_system_sync().ok()?;

        let (resource, resource_handle) = resource.remote_handle();

        tokio::spawn(async move {
            resource.await;
        });

        let proxy = Proxy::new(
            "org.freedesktop.Avahi",
            "/",
            Duration::from_secs(5),
            Arc::clone(&conn),
        );
        tokio::spawn({
            async move {
                Self::startup(socket, service_name, proxy, peer_found, main)
                    .await;
            }
        });
        Some(Self {
            _handles: Some((resource_handle, conn)),
        })
    }
}

impl NsdManager {
    async fn startup<T, Found, FoundFut, Main>(
        socket: crate::Socket<T>,
        service_name: String,
        proxy: Proxy<'static, Arc<SyncConnection>>,
        peer_found: Found,
        main: Main,
    ) where
        T: crate::application::IdentityCanonicalizer,
        Found: 'static
            + Send
            + Sync
            + Fn(super::FoundPeer<T::Identity>, IpAddr) -> FoundFut,
        FoundFut: Send + Sync + Future<Output = ()>,
        Main: 'static + Send + Sync + Future<Output = ()>,
    {
        match proxy.get_version_string().await {
            Ok(_version) => (), //println!("avahi version: {}", version),
            Err(_) => {
                return;
            }
        }
        let serving = if let Some(port) = socket.port() {
            Some(
                create_service(
                    &service_name,
                    socket.instance_id,
                    &socket.identity.identity_txt,
                    &proxy,
                    port,
                    socket.discovery_addr,
                )
                .await,
            )
        } else {
            None
        };
        /*
        match &serving {
            Ok(_) => println!("registered service with avahi"),
            Err(err) => eprintln!("failed to create service: {}", err),
        }
        */
        let identity = Arc::clone(&socket.identity);
        let browsing = browse_services(
            &service_name,
            move |txt| identity.canonicalizer.parse_txt(txt),
            &proxy,
            socket.discovery_addr,
            peer_found,
        )
        .await;
        /*
        match &browsing {
            Ok(_) => println!("started browsing for avahi services"),
            Err(err) => eprintln!("failed to start browsing: {}", err),
        }
        */
        main.await;
        std::mem::drop((serving, browsing));
    }
}

async fn create_service(
    mut service_name: &str,
    instance_id: u64,
    identity_txt: &[u8],
    proxy: &Proxy<'static, Arc<SyncConnection>>,
    port: u16,
    discovery_addr: Option<IpAddr>,
) -> Result<MsgMatch, dbus::Error> {
    let group = Proxy {
        path: proxy.entry_group_new().await?,
        ..proxy.clone()
    };
    let rule = avahi_entry_group::OrgFreedesktopAvahiEntryGroupStateChanged::match_rule(None, Some(&group.path)).static_clone();
    let msg_match = proxy.connection.add_match(rule).await?.msg_cb(|_msg| {
        //println!("got message: {:?}", msg);
        true
    });
    let interface = -1; // IF_UNSPEC
    let protocol = match discovery_addr {
        None => -1, // PROTO_UNSPEC
        Some(IpAddr::V4(_)) => 0,
        Some(IpAddr::V6(_)) => 1,
    };
    let flags = 0;
    let mut alt_service_name: String;
    let type_ = super::SERVICE_TYPE;
    let domain = "";
    let host = match discovery_addr {
        Some(ip) => Cow::Owned(ip.to_string()),
        None => Cow::Borrowed(""),
    };
    let mut id_txt_line = b"id=".to_vec();
    id_txt_line.extend(identity_txt);
    let mut ins_txt_line = "ins=".to_string();
    write!(&mut ins_txt_line, "{:x}", instance_id)
        .expect("formatting an integer into a string failed");
    let txt = vec![id_txt_line, ins_txt_line.into_bytes()];
    loop {
        match group
            .add_service(
                interface,
                protocol,
                flags,
                service_name,
                type_,
                domain,
                &host,
                port,
                txt.clone(),
            )
            .await
        {
            Ok(_) => break,
            Err(err) => {
                if err.name() == Some("org.freedesktop.Avahi.CollisionError") {
                    alt_service_name = proxy
                        .get_alternative_service_name(service_name)
                        .await?;
                    service_name = &alt_service_name;
                    continue;
                } else {
                    return Err(err);
                }
            }
        }
    }
    //println!("nsd service name: '{}'", name);
    group.commit().await?;
    Ok(msg_match)
}

async fn browse_services<Id, IdFromTxt, Found, FoundFut>(
    service_name: &str,
    identity_from_txt: IdFromTxt,
    proxy: &Proxy<'static, Arc<SyncConnection>>,
    bind_addr: Option<IpAddr>,
    peer_found: Found,
) -> Result<MsgMatch, dbus::Error>
where
    Id: Send + Sync,
    IdFromTxt: 'static + Send + Sync + Clone + Fn(&[u8]) -> Option<Id>,
    Found:
        'static + Send + Sync + Fn(super::FoundPeer<Id>, IpAddr) -> FoundFut,
    FoundFut: Send + Sync + Future<Output = ()>,
{
    let interface = -1; // IF_UNSPEC
    let protocol = match bind_addr {
        None => -1, // PROTO_UNSPEC
        Some(IpAddr::V4(_)) => 0,
        Some(IpAddr::V6(_)) => 1,
    };
    let type_ = super::SERVICE_TYPE;
    let domain = "";
    let flags = 0;
    let sb = Proxy {
        path: proxy
            .service_browser_new(interface, protocol, type_, domain, flags)
            .await?,
        ..proxy.clone()
    };
    let rule = ItemNew::match_rule(None, Some(&sb.path)).static_clone();
    let proxy2 = proxy.clone();
    let peer_found = Arc::new(peer_found);
    Ok(proxy.connection.add_match(rule).await?.cb(
        move |_msg, item_new: ItemNew| {
            let identity_from_txt = identity_from_txt.clone();
            let proxy = proxy2.clone();
            let peer_found = Arc::clone(&peer_found);
            tokio::spawn(async move {
                let aproto = -1; // PROTO_UNSPEC
                let flags = 0;
                let resolved = proxy
                    .resolve_service(
                        item_new.interface,
                        item_new.protocol,
                        &item_new.name,
                        &item_new.type_,
                        &item_new.domain,
                        aproto,
                        flags,
                    )
                    .await
                    .ok()?;
                let (
                    _interface,
                    _protocol,
                    _name,
                    _type_,
                    _domain,
                    host,
                    _aprotocol,
                    address,
                    port,
                    txt,
                    _flags,
                ) = resolved;
                let ip_addr = address.parse::<IpAddr>().ok()?;
                let mut identity = None;
                let mut instance_id = None;
                for txt_line in txt {
                    if let Some(id_bytes) = txt_line.strip_prefix(b"id=") {
                        identity = identity_from_txt(id_bytes);
                    } else if let Some(ins_bytes) =
                        txt_line.strip_prefix(b"ins=")
                    {
                        instance_id = std::str::from_utf8(ins_bytes)
                            .ok()
                            .and_then(|ins_str| {
                                u64::from_str_radix(ins_str, 16).ok()
                            });
                    }
                }
                let identity = identity?;
                let instance_id = instance_id?;
                let found_peer = super::FoundPeer {
                    hostname: host,
                    identity,
                    instance_id,
                    port,
                };
                peer_found(found_peer, ip_addr).await;
                Some(())
            });
            true
        },
    ))
}
