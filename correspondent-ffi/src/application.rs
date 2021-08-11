/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{
    collections::HashMap,
    error::Error,
    ffi::{c_void, CStr, CString},
    future::Future,
    hash::Hash,
    os::raw::c_char,
    path::PathBuf,
    sync::Mutex,
};

use tokio::sync::oneshot;

#[derive(Clone)]
#[repr(C)]
pub struct ApplicationVTable {
    pub obj: *mut c_void,

    pub max_message_size: usize,

    pub application_data_dir: *const u8,
    pub application_data_dir_len: usize,

    pub service_name: *const u8,
    pub service_name_len: usize,

    pub identity: *const u8,
    pub identity_len: usize,

    pub dns_suffix: *const u8,
    pub dns_suffix_len: usize,

    pub cleanup: extern "C" fn(obj: *mut ApplicationVTable),

    pub sign_certificate: extern "C" fn(
        obj: *mut c_void,
        csr_pem: *const c_char,
        async_context: *mut SigningContext,
    ),

    pub handle_message: extern "C" fn(
        obj: *mut c_void,
        sender: *const PeerId,
        msg: *const u8,
        msg_len: usize,
    ),

    pub handle_new_peer: extern "C" fn(obj: *mut c_void, id: *const PeerId),
    pub handle_peer_gone: extern "C" fn(obj: *mut c_void, id: *const PeerId),
}

unsafe impl Send for ApplicationVTable {}
unsafe impl Sync for ApplicationVTable {}

#[repr(C)]
pub struct CertificateResponse {
    pub success: bool,
    pub ctx: *mut SigningContext,
    pub client_chain_pem: *const c_char,
    pub authority_pem: *const c_char,
}

pub struct SigningContext {
    send: oneshot::Sender<correspondent::CertificateResponse>,
}

impl SigningContext {
    pub(crate) unsafe fn finish(
        self,
        success: bool,
        client_chain_pem: *const c_char,
        authority_pem: *const c_char,
    ) {
        if success {
            assert!(!client_chain_pem.is_null());
            assert!(!authority_pem.is_null());
            let client_chain_pem = CStr::from_ptr(client_chain_pem)
                .to_string_lossy()
                .into_owned();
            let authority_pem =
                CStr::from_ptr(authority_pem).to_string_lossy().into_owned();
            let _ = self.send.send(correspondent::CertificateResponse {
                client_chain_pem,
                authority_pem,
            });
        }
    }
}

#[repr(C)]
pub struct PeerId {
    pub identity: *const u8,
    pub identity_len: usize,
    pub unique: u64,
}

type PeerIdInternal = correspondent::PeerId<String>;

type PeerIdMap = Mutex<(
    thunderdome::Arena<PeerIdInternal>,
    HashMap<PeerIdInternal, thunderdome::Index>,
)>;

struct Application {
    peer_id_map: PeerIdMap,
    identity: String,
    dns_suffix: String,
    vtable: ApplicationVTable,
}

macro_rules! vtable_string {
    ($vtable:expr, $field:ident, $len:ident) => {{
        assert!(!$vtable.$field.is_null());
        let bytes = unsafe {
            std::slice::from_raw_parts($vtable.$field, $vtable.$len)
        };
        String::from_utf8_lossy(bytes).into_owned()
    }};
}

impl From<ApplicationVTable> for Application {
    fn from(vtable: ApplicationVTable) -> Self {
        let identity = vtable_string!(vtable, identity, identity_len);
        let dns_suffix = vtable_string!(vtable, dns_suffix, dns_suffix_len);
        Self {
            peer_id_map: Mutex::default(),
            identity,
            dns_suffix,
            vtable,
        }
    }
}

impl Drop for Application {
    fn drop(&mut self) {
        let cleanup = self.vtable.cleanup;
        cleanup(&mut self.vtable);
    }
}

impl correspondent::Application for Application {
    fn application_data_dir(&self) -> PathBuf {
        assert!(!self.vtable.application_data_dir.is_null());
        let bytes = unsafe {
            std::slice::from_raw_parts(
                self.vtable.application_data_dir,
                self.vtable.application_data_dir_len,
            )
        };
        let string = String::from_utf8_lossy(bytes);
        string.into_owned().into()
    }

    fn max_message_size(&self) -> usize {
        self.vtable.max_message_size
    }

    fn service_name(&self) -> String {
        vtable_string!(self.vtable, service_name, service_name_len)
    }

    type Identity = String;

    fn identity(&self) -> &String {
        &self.identity
    }

    fn identity_to_dns(&self, id: &String) -> String {
        format!("{}{}", id, self.dns_suffix)
    }

    fn identity_to_txt(&self, id: &String) -> Vec<u8> {
        id.as_bytes().to_vec()
    }

    fn identity_from_txt(&self, txt: &[u8]) -> Option<String> {
        std::str::from_utf8(txt).ok().map(String::from)
    }

    type SigningError = oneshot::error::RecvError;

    type SigningFuture = oneshot::Receiver<correspondent::CertificateResponse>;

    fn sign_certificate(&self, csr_pem: &str) -> Self::SigningFuture {
        let c_str =
            CString::new(csr_pem).expect("PEM-formatted CSR contained null");
        let (send, recv) = oneshot::channel();
        let ctx = Box::new(SigningContext { send });
        (self.vtable.sign_certificate)(
            self.vtable.obj,
            c_str.as_ptr(),
            Box::into_raw(ctx),
        );
        recv
    }

    fn handle_message(
        &self,
        sender: &correspondent::PeerId<String>,
        msg: Vec<u8>,
    ) {
        let index = {
            let mut guard =
                self.peer_id_map.lock().expect("Mutex was poisoned");
            let (_arena, lookup) = &mut *guard;
            lookup
                .get(sender)
                .copied()
                .expect("Failed to find peer in lookup table")
        };
        let identity: &[u8] = sender.0.as_bytes();
        let peer_id = PeerId {
            identity: identity.as_ptr(),
            identity_len: identity.len(),
            unique: index.to_bits(),
        };
        (self.vtable.handle_message)(
            self.vtable.obj,
            &peer_id,
            msg.as_ptr(),
            msg.len(),
        );
    }

    fn handle_new_peer(
        &self,
        id: &correspondent::PeerId<String>,
        _peer: &correspondent::Peer,
    ) {
        let index = {
            let mut guard =
                self.peer_id_map.lock().expect("Mutex was poisoned");
            let (arena, lookup) = &mut *guard;
            let index = arena.insert(id.clone());
            lookup.insert(id.clone(), index);
            index
        };
        let identity: &[u8] = id.0.as_bytes();
        let peer_id = PeerId {
            identity: identity.as_ptr(),
            identity_len: identity.len(),
            unique: index.to_bits(),
        };
        (self.vtable.handle_new_peer)(self.vtable.obj, &peer_id);
    }

    fn handle_peer_gone(&self, peer: &correspondent::PeerId<String>) {
        let index = {
            let mut guard =
                self.peer_id_map.lock().expect("Mutex was poisoned");
            let (arena, lookup) = &mut *guard;
            let index = lookup
                .remove(peer)
                .expect("Failed to find peer in lookup table");
            arena.remove(index);
            index
        };
        let identity: &[u8] = peer.0.as_bytes();
        let peer_id = PeerId {
            identity: identity.as_ptr(),
            identity_len: identity.len(),
            unique: index.to_bits(),
        };
        (self.vtable.handle_peer_gone)(self.vtable.obj, &peer_id);
    }
}
