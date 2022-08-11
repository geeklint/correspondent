/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::sync::{
    mpsc::{channel, Sender},
    Arc,
};

use crate::{
    application::{Application, ApplicationVTable},
    StreamWriterVTable,
};

/// Representation of a correspondent socket.
pub struct Socket {
    inner: correspondent::Socket<Application>,
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
        let msg_bytes = std::slice::from_raw_parts(msg, msg_len);
        if let Ok(id_str) = std::str::from_utf8(id_bytes) {
            self.inner.send_to(id_str.to_string(), msg_bytes.to_vec());
        }
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
        let msg_bytes = std::slice::from_raw_parts(msg, msg_len);
        self.inner.send_to_id(peer_id, msg_bytes.to_vec());
    }

    pub(crate) unsafe fn send_to_all(&self, msg: *const u8, msg_len: usize) {
        if msg.is_null() {
            return;
        }
        let msg_bytes = std::slice::from_raw_parts(msg, msg_len);
        self.inner.send_to_all(msg_bytes.to_vec());
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
        let socket = self.inner.clone();
        self.inner.runtime().spawn(async move {
            use futures_util::TryFutureExt;
            let mut writer = writer;
            let mut stream = socket.open_uni(peer_id).await.ok()?;
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

pub unsafe fn start(app: *const ApplicationVTable) -> *mut Socket {
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
    recv.recv()
        .map(|inner| {
            let socket = Socket { inner };
            Box::into_raw(Box::new(socket))
        })
        .unwrap_or(std::ptr::null_mut())
}

#[tokio::main(flavor = "current_thread")]
async fn network_thread(
    app: Application,
    sender: Sender<correspondent::Socket<Application>>,
) {
    use futures_util::StreamExt;
    let app = Arc::new(app);
    let (socket, mut events) =
        match correspondent::Socket::start(Arc::clone(&app)).await {
            Ok(socket) => socket,
            Err(_) => return,
        };
    let _ = sender.send(socket);
    while let Some(event) = events.next().await {
        use correspondent::Event;
        match event {
            Event::NewPeer(peer_id, _connection) => {
                app.handle_new_peer(&peer_id);
            }
            Event::PeerGone(peer_id) => {
                app.handle_peer_gone(&peer_id);
            }
            Event::UniStream(peer_id, stream) => {
                let stream_handler = app.handle_stream(&peer_id);
                tokio::spawn(handle_stream(stream_handler, stream));
            }
            Event::BiStream(..) => {
                // TODO: support bi streams in ffi?
            }
        }
    }
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
