/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::sync::{
    mpsc::{channel, Sender},
    Arc,
};

use crate::application::{Application, ApplicationVTable};

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

#[tokio::main]
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
                let app = Arc::clone(&app);
                tokio::spawn(async move {
                    if let Ok(message) =
                        stream.read_to_end(app.max_message_size()).await
                    {
                        app.handle_message(&peer_id, message);
                    }
                });
            }
        }
    }
}
