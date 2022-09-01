/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{collections::HashMap, sync::Arc, sync::RwLock, time::Duration};

use futures_util::stream::FuturesUnordered;
use quinn::Connection;
use tokio::sync::oneshot::{channel, Sender};

use correspondent::PeerId;

use crate::{
    application::{
        AppCertSigner, Application, ApplicationVTable, StringIdCanonicalizer,
    },
    StreamWriterVTable,
};

/// Representation of a correspondent socket.
pub struct Socket {
    inner: correspondent::Socket<StringIdCanonicalizer>,
    runtime: tokio::runtime::Handle,
    current_peers: RwLock<HashMap<PeerId<String>, Connection>>,
}

impl Socket {
    pub(crate) unsafe fn send_to(
        &self,
        id: *const u8,
        id_len: usize,
        msg: *const u8,
        msg_len: usize,
    ) {
        if id.is_null() || msg.is_null() {
            return;
        }
        let id_bytes = std::slice::from_raw_parts(id, id_len);
        let id_str = match std::str::from_utf8(id_bytes) {
            Ok(s) => s,
            Err(_) => return,
        };
        let msg_bytes = std::slice::from_raw_parts(msg, msg_len).to_vec();
        let connections: Vec<_> = {
            self.current_peers
                .read()
                .expect("mutex was poisoned")
                .iter()
                .filter_map(|(peer_id, conn)| {
                    (peer_id.identity == id_str).then_some(conn)
                })
                .cloned()
                .collect()
        };
        self.runtime.spawn(async move {
            use futures_util::StreamExt;
            let msg_bytes = &msg_bytes;
            let mut futures: FuturesUnordered<_> = connections
                .into_iter()
                .map(|conn| async move {
                    let mut stream = conn.open_uni().await.ok()?;
                    stream.write_all(msg_bytes).await.ok()?;
                    stream.finish().await.ok()?;
                    Some(())
                })
                .collect();
            while (futures.next().await).is_some() {}
        });
    }

    pub(crate) unsafe fn send_to_id(
        &self,
        id: *const u8,
        id_len: usize,
        unique: usize,
        msg: *const u8,
        msg_len: usize,
    ) {
        if id.is_null() || msg.is_null() {
            return;
        }
        let id_bytes = std::slice::from_raw_parts(id, id_len);
        let peer_id = if let Ok(id_str) = std::str::from_utf8(id_bytes) {
            correspondent::PeerId {
                identity: id_str.to_string(),
                unique,
            }
        } else {
            return;
        };
        let msg_bytes = std::slice::from_raw_parts(msg, msg_len).to_vec();
        let connection = {
            match self
                .current_peers
                .read()
                .expect("mutex was poisoned")
                .get(&peer_id)
                .cloned()
            {
                Some(conn) => conn,
                None => return,
            }
        };
        self.runtime.spawn(async move {
            let mut stream = connection.open_uni().await.ok()?;
            stream.write_all(&msg_bytes).await.ok()?;
            stream.finish().await.ok()?;
            Some(())
        });
    }

    pub(crate) unsafe fn send_to_all(&self, msg: *const u8, msg_len: usize) {
        if msg.is_null() {
            return;
        }
        let msg_bytes = std::slice::from_raw_parts(msg, msg_len).to_vec();
        let connections: Vec<_> = {
            self.current_peers
                .read()
                .expect("mutex was poisoned")
                .values()
                .cloned()
                .collect()
        };
        self.runtime.spawn(async move {
            use futures_util::StreamExt;
            let msg_bytes = &msg_bytes;
            let mut futures: FuturesUnordered<_> = connections
                .into_iter()
                .map(|conn| async move {
                    let mut stream = conn.open_uni().await.ok()?;
                    stream.write_all(msg_bytes).await.ok()?;
                    stream.finish().await.ok()?;
                    Some(())
                })
                .collect();
            while (futures.next().await).is_some() {}
        });
    }

    pub(crate) unsafe fn start_stream_to_id(
        &self,
        id: *const u8,
        id_len: usize,
        unique: usize,
        writer: *mut StreamWriterVTable,
    ) {
        if id.is_null() || writer.is_null() {
            return;
        }
        let writer = crate::stream::StreamWriter::new(writer);
        let id_bytes = std::slice::from_raw_parts(id, id_len);
        let peer_id = if let Ok(id_str) = std::str::from_utf8(id_bytes) {
            correspondent::PeerId {
                identity: id_str.to_string(),
                unique,
            }
        } else {
            return;
        };
        let connection = {
            match self
                .current_peers
                .read()
                .expect("mutex was poisoned")
                .get(&peer_id)
                .cloned()
            {
                Some(conn) => conn,
                None => return,
            }
        };
        self.runtime.spawn(async move {
            use futures_util::TryFutureExt;
            let mut writer = writer;
            let mut stream = connection.open_uni().await.ok()?;
            let mut left = vec![0; writer.chunk_size()];
            let mut right = vec![0; writer.chunk_size()];
            let mut left_len = 0;
            loop {
                let sending =
                    stream.write_all(&left[..left_len]).map_err(|_| ());
                let recving = tokio::task::spawn_blocking(move || {
                    let right_len = writer.get_data_to_write(&mut right);
                    (writer, right, right_len)
                })
                .map_err(|_| ());
                let right_len;
                ((), (writer, right, right_len)) =
                    tokio::try_join!(sending, recving).ok()?;
                if right_len == 0 {
                    break;
                }
                std::mem::swap(&mut left, &mut right);
                left_len = right_len;
            }
            Some(())
        });
    }

    pub(crate) unsafe fn close(
        &self,
        code: u32,
        msg: *const u8,
        msg_len: usize,
    ) {
        if msg.is_null() {
            return;
        }
        let msg_bytes = std::slice::from_raw_parts(msg, msg_len);
        self.inner.endpoint().close(code.into(), msg_bytes);
    }
}

pub unsafe fn start(app: *const ApplicationVTable) -> *const Socket {
    if app.is_null() {
        return std::ptr::null_mut();
    }
    let app = (&*app).clone();
    if !app.check() {
        return std::ptr::null_mut();
    }
    let app = Application::from(app);
    let (send, recv) = channel();
    std::thread::spawn(move || {
        network_thread(app, send);
    });
    recv.blocking_recv()
        .map(Arc::into_raw)
        .unwrap_or(std::ptr::null())
}

#[tokio::main(flavor = "current_thread")]
async fn network_thread(
    app: Application,
    sender: Sender<Arc<Socket>>,
) -> Option<()> {
    use futures_util::StreamExt;

    let app = Arc::new(app);

    let mut builder = correspondent::SocketBuilder::new()
        .with_identity(
            app.identity.clone(),
            StringIdCanonicalizer {
                dns_suffix: app.dns_suffix.clone(),
            },
        )
        .with_service_name("Correspondent Chat Example".to_string())
        .with_default_socket()
        .ok()?
        .with_default_endpoint_cfg()
        .with_new_certificate(
            Duration::from_secs(60 * 60 * 24 /* = 1 day */),
            AppCertSigner(Arc::clone(&app)),
        )
        .await
        .ok()?;

    Arc::get_mut(&mut builder.client_cfg.transport)
        .expect("there should not be any other references at this point")
        .keep_alive_interval(Some(Duration::from_secs(5)));

    let (socket, mut events) = builder.start().ok()?;
    let socket = Arc::new(Socket {
        inner: socket,
        runtime: tokio::runtime::Handle::current(),
        current_peers: RwLock::default(),
    });
    let _ = sender.send(Arc::clone(&socket));
    while let Some(event) = events.next().await {
        use correspondent::Event;
        match event {
            Event::NewPeer(peer_id, connection) => {
                {
                    socket
                        .current_peers
                        .write()
                        .expect("mutex was poisoned")
                        .insert(peer_id.clone(), connection);
                }
                app.handle_new_peer(&peer_id);
            }
            Event::PeerGone(peer_id) => {
                {
                    socket
                        .current_peers
                        .write()
                        .expect("mutex was poisoned")
                        .remove(&peer_id);
                }
                app.handle_peer_gone(&peer_id);
            }
            Event::UniStream(peer_id, stream) => {
                let stream_handler = app.handle_stream(&peer_id);
                tokio::spawn(handle_stream(stream_handler, stream));
            }
            Event::BiStream(..) => {
                // TODO: support bi streams in ffi?
            }
            _ => {}
        }
    }
    Some(())
}

async fn handle_stream(
    mut stream_handler: crate::stream::StreamHandler,
    mut stream: quinn::RecvStream,
) {
    let mut ordered = stream_handler.ordered_initial();
    let chunk_size = stream_handler.max_chunk_size();
    let mut next_chunk = stream.read_chunk(chunk_size, ordered).await;
    loop {
        use crate::stream::HandleChunkResult::*;
        let current_chunk = next_chunk;
        let result;
        let current_chunk = match current_chunk {
            Ok(None) => break,
            Ok(Some(chunk)) => chunk,
            Err(_) => {
                tokio::task::spawn_blocking(move || {
                    stream_handler
                        .finish(Some(&crate::StreamReadError { _inner: () }));
                });
                return;
            }
        };
        (next_chunk, (stream_handler, result)) =
            tokio::join!(stream.read_chunk(chunk_size, ordered), async {
                let bg = tokio::task::spawn_blocking(move || {
                    let res = stream_handler.handle_chunk(
                        current_chunk.offset,
                        &current_chunk.bytes,
                    );
                    (stream_handler, res)
                });
                bg.await.expect(
                    "panic while running handle_chunk on blocking thread",
                )
            });
        match result {
            CleanupNow => break,
            ContinueOrdered => continue,
            ContinueUnordered => ordered = true,
        }
    }
    tokio::task::spawn_blocking(move || stream_handler.finish(None));
}
