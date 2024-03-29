/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{
    ffi::{c_void, CStr, CString},
    os::raw::c_char,
    sync::Arc,
};

use tokio::sync::oneshot;

use correspondent::PeerId as CorrespondentPeerId;

/// cbindgen:ignore
type PeerIdInternal = CorrespondentPeerId<String>;

/// This v-table provides the core ability for a FFI client to define the
/// functionality of the correspondent application.
///
/// See [correspondent documentation](https://docs.rs/correspondent/0.1.0/correspondent/trait.Application.html)
/// for more details on Application.
#[derive(Clone)]
#[repr(C)]
pub struct ApplicationVTable {
    /// User-specified object pointer.
    ///
    /// # Safety
    ///
    /// This function pointer must be safe to send to arbitrary threads.
    pub obj: *mut c_void,

    /// Provide a location for correspondent to store some information, notably
    /// offline copies of signed certificates.
    ///
    /// # Safety
    ///
    /// Must point to a valid allocation of at least
    /// `application_data_dir_len` bytes, indicating a UTF-8 encoded
    /// directory path.
    pub application_data_dir: *const u8,

    /// See `application_data_dir`.
    pub application_data_dir_len: usize,

    /// The name of the DNS-SD service to use.
    ///
    /// # Safety
    ///
    /// Must point to a valid allocation of at least `service_name_len` bytes,
    /// UTF-8 (preferably ASCII) encoded.
    pub service_name: *const u8,

    /// See `service_name`.
    pub service_name_len: usize,

    /// The identity string used by this instance.
    ///
    /// # Safety
    ///
    /// Must point to a valid allocation of at least `identity_len` bytes,
    /// UTF-8 (preferably ASCII) encoded.
    pub identity: *const u8,

    /// See `identity`.
    pub identity_len: usize,

    /// Suffix to use for DNS names for clients, e.g. ".example.com".
    ///
    /// # Safety
    ///
    /// Must point to a valid allocation of at least `dns_suffix_len` bytes,
    /// UTF-8 (preferably ASCII) encoded.
    pub dns_suffix: *const u8,

    /// See `dns_suffix`.
    pub dns_suffix_len: usize,

    /// This function is called by the library when it is done using the
    /// contents of this v-table. To avoid a memory leak, `cleanup` should
    /// de-allocate all the memory associated with the v-table.
    ///
    /// # Safety
    ///
    /// This function pointer must not be null.
    ///
    /// This function must tolerate being called from an arbitrary thread.
    pub cleanup: extern "C" fn(obj: *mut ApplicationVTable),

    /// This function is called by the library when it needs to sign a
    /// certificate to use.
    ///
    /// This function is asynchronous. It should return without blocking, and
    /// use the [`finish_signing`](crate::finish_signing) function to complete
    /// the asynchronous operation.
    ///
    /// # Safety
    ///
    /// This function pointer must not be null.
    ///
    /// This function must tolerate being called simultaneously from
    /// arbitrary threads.
    ///
    /// The `csr_pem` pointer is valid only for the duration of this function.
    /// Implementers should make a copy with e.g. `strdup` if they need access
    /// to the data after the function has returned.
    ///
    /// The `async_context` pointer is valid until passed into
    /// [`finish_signing`](crate::finish_signing).
    ///
    /// To avoid a memory leak, the `async_context` pointer must be passed
    /// into [`finish_signing`](crate::finish_signing) eventually.
    pub sign_certificate: extern "C" fn(
        obj: *mut c_void,
        csr_pem: *const c_char,
        async_context: *mut SigningContext,
    ),

    /// This function is called by the library when the socket has finished
    /// initializing, before any other event are processed.
    ///
    /// # Safety
    ///
    /// This function pointer must not be null.
    pub handle_initialized:
        extern "C" fn(obj: *mut c_void, socket: *const crate::Socket),

    /// This function is called by the library when a message is received.
    ///
    /// # Safety
    ///
    /// This function pointer must not be null.
    ///
    /// This function must tolerate being called simultaneously from
    /// arbitrary threads.
    ///
    /// The `sender`, pointers are valid only for the duration of this function.
    /// Implementers should make a copy of the pointed-to data if they need
    /// access after the function has returned.
    pub handle_stream: extern "C" fn(
        obj: *mut c_void,
        sender: *const PeerId,
    ) -> *mut crate::StreamHandlerVTable,

    /// This function is called by the library when a peer first connects.
    ///
    /// # Safety
    ///
    /// This function pointer must not be null.
    ///
    /// This function must tolerate being called simultaneously from
    /// arbitrary threads.
    ///
    /// The `id`, pointer is valid only for the duration of this function.
    /// Implementers should make a copy of the pointed-to data if they need
    /// access after the function has returned.
    pub handle_new_peer: extern "C" fn(obj: *mut c_void, id: *const PeerId),

    /// This function is called by the library when a peer is no longer
    /// connected.
    ///
    /// # Safety
    ///
    /// This function pointer must not be null.
    ///
    /// This function must tolerate being called simultaneously from
    /// arbitrary threads.
    ///
    /// The `id`, pointer is valid only for the duration of this function.
    /// Implementers should make a copy of the pointed-to data if they need
    /// access after the function has returned.
    pub handle_peer_gone: extern "C" fn(obj: *mut c_void, id: *const PeerId),
}

unsafe impl Send for ApplicationVTable {}
unsafe impl Sync for ApplicationVTable {}

impl ApplicationVTable {
    pub(crate) fn check(&self) -> bool {
        !(self.application_data_dir.is_null()
            || self.service_name.is_null()
            || self.identity.is_null()
            || self.dns_suffix.is_null())
    }
}

/// This type represents an active asynchronous context for signing a
/// certificate.
///
/// # Safety
///
/// Foreign code is not allowed to make any assumptions about the interior
/// layout of this type.
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
            if client_chain_pem.is_null() || authority_pem.is_null() {
                return;
            }
            let chain_pem = match CStr::from_ptr(client_chain_pem).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => return,
            };
            let authority_pem = match CStr::from_ptr(authority_pem).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => return,
            };
            let _ = self.send.send(correspondent::CertificateResponse {
                chain_pem,
                authority_pem,
            });
        }
    }
}

/// This type represents the identity of a peer, along with a unique
/// connection id.
///
/// Since peers may advertise an arbitrary identity string, the unique index
/// can be used to differentiate two peers with the same identity string.
#[repr(C)]
pub struct PeerId {
    /// The identity the peer advertised, as a pointer to a buffer of at least
    /// `identity_len` bytes, UTF-8 (preferably ASCII) encoded.
    pub identity: *const u8,

    /// See `identity`.
    pub identity_len: usize,

    /// An index guaranteed to uniquely identify the specific peer for
    /// as long as the peer is connected.
    pub unique: usize,
}

pub struct Application {
    pub(crate) identity: String,
    pub(crate) dns_suffix: String,
    vtable: ApplicationVTable,
}

impl Application {
    pub(crate) fn handle_initialized(&self, socket: Arc<crate::Socket>) {
        (self.vtable.handle_initialized)(
            self.vtable.obj,
            Arc::into_raw(socket),
        );
    }

    pub(crate) fn handle_stream(
        &self,
        sender: &PeerIdInternal,
    ) -> crate::stream::StreamHandler {
        let identity: &[u8] = sender.identity.as_bytes();
        let peer_id = PeerId {
            identity: identity.as_ptr(),
            identity_len: identity.len(),
            unique: sender.unique,
        };
        let vtable = (self.vtable.handle_stream)(self.vtable.obj, &peer_id);
        crate::stream::StreamHandler::new(vtable)
    }

    pub(crate) fn handle_new_peer(&self, id: &PeerIdInternal) {
        let identity: &[u8] = id.identity.as_bytes();
        let peer_id = PeerId {
            identity: identity.as_ptr(),
            identity_len: identity.len(),
            unique: id.unique,
        };
        (self.vtable.handle_new_peer)(self.vtable.obj, &peer_id);
    }

    pub(crate) fn handle_peer_gone(&self, peer: &PeerIdInternal) {
        let identity: &[u8] = peer.identity.as_bytes();
        let peer_id = PeerId {
            identity: identity.as_ptr(),
            identity_len: identity.len(),
            unique: peer.unique,
        };
        (self.vtable.handle_peer_gone)(self.vtable.obj, &peer_id);
    }
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

pub(crate) struct StringIdCanonicalizer {
    pub dns_suffix: String,
}

pub(crate) struct AppCertSigner(pub Arc<Application>);

impl correspondent::IdentityCanonicalizer for StringIdCanonicalizer {
    type Identity = String;

    fn to_dns(&self, id: &String) -> String {
        format!("{}{}", id, self.dns_suffix)
    }

    fn to_txt(&self, id: &String) -> Vec<u8> {
        id.as_bytes().to_vec()
    }

    fn parse_txt(&self, txt: &[u8]) -> Option<String> {
        std::str::from_utf8(txt).ok().map(String::from)
    }
}

impl correspondent::CertificateSigner for AppCertSigner {
    type SigningError = oneshot::error::RecvError;

    type SigningFuture = oneshot::Receiver<correspondent::CertificateResponse>;

    fn sign_certificate(&mut self, csr_pem: &str) -> Self::SigningFuture {
        let c_str =
            CString::new(csr_pem).expect("PEM-formatted CSR contained null");
        let (send, recv) = oneshot::channel();
        let ctx = Box::new(SigningContext { send });
        (self.0.vtable.sign_certificate)(
            self.0.vtable.obj,
            c_str.as_ptr(),
            Box::into_raw(ctx),
        );
        recv
    }
}
