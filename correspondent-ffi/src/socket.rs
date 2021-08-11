/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::sync::{
    mpsc::{channel, Sender},
    Arc,
};

use tokio::sync::oneshot;

use crate::application::{Application, ApplicationVTable};

/// Representation of a correspondent socket.
pub struct Socket {
    inner: correspondent::Socket<Application>,
    _handle: oneshot::Sender<()>,
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
        id: u64,
        msg: *const u8,
        msg_len: usize,
    ) {
        if msg.is_null() {
            return;
        }
        if let Some(peer_id) = self.inner.app().lookup_peer_id(id) {
            let msg_bytes = std::slice::from_raw_parts(msg, msg_len);
            self.inner.send_to_id(peer_id, msg_bytes.to_vec());
        }
    }

    pub(crate) unsafe fn send_to_all(&self, msg: *const u8, msg_len: usize) {
        if msg.is_null() {
            return;
        }
        let msg_bytes = std::slice::from_raw_parts(msg, msg_len);
        self.inner.send_to_all(msg_bytes.to_vec());
    }
}

pub unsafe fn start(app: *const ApplicationVTable) -> *mut Socket {
    if app.is_null() {
        return std::ptr::null_mut();
    }
    let app = Application::from((&*app).clone());
    let (send, recv) = channel();
    let (_handle, pending) = oneshot::channel();
    std::thread::spawn(move || {
        network_thread(app, send, pending);
    });
    recv.recv()
        .map(|inner| {
            let socket = Socket { inner, _handle };
            Box::into_raw(Box::new(socket))
        })
        .unwrap_or(std::ptr::null_mut())
}

// clippy bug: https://github.com/rust-lang/rust-clippy/issues/7438
#[allow(clippy::semicolon_if_nothing_returned)]
#[tokio::main]
async fn network_thread(
    app: Application,
    sender: Sender<correspondent::Socket<Application>>,
    pending: oneshot::Receiver<()>,
) {
    let socket = match correspondent::Socket::start(Arc::new(app)).await {
        Ok(socket) => socket,
        Err(_) => return,
    };
    let _ = sender.send(socket);
    let _ = pending.await;
}
