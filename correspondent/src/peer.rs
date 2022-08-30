/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{convert::TryFrom, future::Future, sync::Arc, time::Duration};

use {
    futures_util::StreamExt,
    quinn::{Connecting, Connection, NewConnection},
    tokio::time::timeout,
};

use crate::{
    application::IdentityCanonicalizer,
    socket::{
        ActiveConnections, Event, Identity, InternalEvent, InternalEventStream,
    },
};

/// Unique identifier for a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId<T> {
    /// Identity advertised by the peer
    pub identity: T,

    /// A unique identifier for the connection
    pub unique: usize,
}

/// Error returned by Socket::connect if an error happens when connecting to
/// a peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerNotConnected;

pub(crate) async fn start_peer<T: IdentityCanonicalizer>(
    identity: Arc<Identity<T>>,
    connecting: Connecting,
    our_instance_id: u64,
    active_connections: ActiveConnections<T::Identity>,
) -> Result<
    (PeerId<T::Identity>, InternalEventStream<T::Identity>),
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
        first_stream
            .write_all(&our_instance_id.to_be_bytes())
            .await
            .map_err(|_| PeerNotConnected)?;
        first_stream
            .write_all(&identity.identity_txt)
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
        let hello = identity
            .canonicalizer
            .parse_txt(&buf)
            .ok_or(PeerNotConnected)?;
        Ok((u64::from_be_bytes(instance_id_bytes), hello))
    });
    let ((), (peer_instance_id, hello)) =
        tokio::try_join!(sending_hello, recving_hello)?;
    let peer_hostname = identity.canonicalizer.to_dns(&hello);
    verify_peer(&connection, &peer_hostname).ok_or(PeerNotConnected)?;

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

    use crate::util::StreamInsertExt;

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
                        Ok((send, recv)) => Some(InternalEvent::Event(
                            Event::BiStream(peer_id_bi.clone(), send, recv),
                        )),
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
            let _connection = connection;
            async move {
                let mut active_conn_guard = active_connections.lock().await;
                active_conn_guard.remove(&peer_instance_id);
            }
        })
        .boxed(),
    ))
}

#[derive(Clone, Copy, Debug, Default)]
struct PeerVerified;

#[must_use]
#[deny(unused)]
fn verify_peer(
    connection: &Connection,
    hostname: &str,
) -> Option<PeerVerified> {
    let chain = connection
        .peer_identity()?
        .downcast::<Vec<rustls::Certificate>>()
        .ok()?;
    let cert = chain.iter().next()?;
    let pki_cert = webpki::EndEntityCert::try_from(cert.0.as_ref()).ok()?;
    let pki_name = webpki::DnsNameRef::try_from_ascii_str(hostname)
        .expect("Application::identity_to_dns returned invalid DNS name");
    pki_cert.verify_is_valid_for_dns_name(pki_name).ok()?;
    Some(PeerVerified)
}
