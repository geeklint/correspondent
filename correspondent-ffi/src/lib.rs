/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

//! FFI bindings for correspondent
//! [https://github.com/geeklint/correspondent](https://github.com/geeklint/correspondent)

#![warn(missing_docs)]
#![warn(clippy::clone_on_ref_ptr)]
#![deny(clippy::unwrap_used)]
#![warn(clippy::default_trait_access)]
#![warn(clippy::cast_lossless)]
#![warn(clippy::explicit_into_iter_loop)]
#![warn(clippy::explicit_iter_loop)]
#![warn(clippy::implicit_clone)]
#![warn(clippy::if_then_some_else_none)]
#![warn(clippy::fn_params_excessive_bools)]
#![warn(clippy::inefficient_to_string)]
#![warn(clippy::let_unit_value)]
#![warn(clippy::manual_ok_or)]
#![warn(clippy::match_bool)]
#![deny(clippy::mem_forget)]
#![warn(clippy::mut_mut)]
#![warn(clippy::mutex_integer)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_continue)]
#![warn(clippy::option_option)]
#![warn(clippy::path_buf_push_overwrite)]
#![warn(clippy::rc_buffer)]
#![warn(clippy::redundant_pub_crate)]
#![warn(clippy::ref_option_ref)]
#![warn(clippy::rest_pat_in_fully_bound_structs)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![warn(clippy::type_repetition_in_bounds)]
#![warn(clippy::unreadable_literal)]
#![warn(clippy::unseparated_literal_suffix)]
#![warn(clippy::useless_let_if_seq)]
#![warn(clippy::verbose_file_reads)]

use std::{ffi::CString, os::raw::c_char};

mod application;
mod certificate;
mod socket;

thread_local! {
    static VERSION: CString = CString::new(env!("CARGO_PKG_VERSION"))
        .expect("CARGO_PKG_VERSION should not contain a null byte");
}

pub use application::{ApplicationVTable, PeerId, SigningContext};
pub use certificate::AuthorityCertificate;
pub use socket::Socket;

/// Get the version number of this library as a UTF-8 encoded null-terminated
/// string.
///
/// This pointer will be valid until the program exits, it does not
/// need to be cleaned up.
#[export_name = "correspondent_version"]
pub extern "C" fn version() -> *const c_char {
    VERSION.with(|cstr| cstr.as_ptr())
}

/// Create a start running a socket based on the given v-table.
///
/// Returns null if creating the socket failed.
///
/// # Safety
///
/// `app` must point to a valid [`ApplicationVTable`].  The `app` pointer
/// itself will not be used after this function returns (the caller must clean
/// it up), however the pointers within the v-table must remain valid until the
/// cleanup function in the v-table is called.
///
/// To avoid a memory leak, the returned pointer (if not null) must be cleaned
/// up with [`socket_free`].
#[export_name = "correspondent_start"]
pub unsafe extern "C" fn start(app: *const ApplicationVTable) -> *mut Socket {
    socket::start(app)
}

/// Send a message to all connected peers with the specified identity
///
/// # Safety
///
/// `socket` must point to a valid socket previously returned from a call to
/// [`start`].  `id` must point to a valid allocation of at least `id_len`
/// UTF-8 encoded bytes.  `msg` must point to a valid allocation of at least
/// `msg_len` bytes.  `id` and `msg` are not used after this function returns;
/// the caller must clean them up.
#[export_name = "correspondent_socket_send_to"]
pub unsafe extern "C" fn socket_send_to(
    socket: *const Socket,
    id: *const u8,
    id_len: usize,
    msg: *const u8,
    msg_len: usize,
) {
    if !socket.is_null() {
        (&*socket).send_to(id, id_len, msg, msg_len);
    }
}

/// Send a message to a specific peer with the given unique id
///
/// # Safety
///
/// `socket` must point to a valid socket previously returned from a call to
/// [`start`].  `msg` must point to a valid allocation of at least
/// `msg_len` bytes.  `msg` is not used after this function returns;
/// the caller must clean it up.
#[export_name = "correspondent_socket_send_to_id"]
pub unsafe extern "C" fn socket_send_to_id(
    socket: *const Socket,
    id: u64,
    msg: *const u8,
    msg_len: usize,
) {
    if !socket.is_null() {
        (&*socket).send_to_id(id, msg, msg_len);
    }
}

/// Send a message to all connected peers.
///
/// # Safety
///
/// `socket` must point to a valid socket previously returned from a call to
/// [`start`].  `msg` must point to a valid allocation of at least
/// `msg_len` bytes.  `msg` is not used after this function returns;
/// the caller must clean it up.
#[export_name = "correspondent_socket_send_to_all"]
pub unsafe extern "C" fn socket_send_to_all(
    socket: *const Socket,
    msg: *const u8,
    msg_len: usize,
) {
    if !socket.is_null() {
        (&*socket).send_to_all(msg, msg_len);
    }
}

/// Cleanup a socket
///
/// # Safety
///
/// `socket` must point to a valid socket previously returned from a call to
/// [`start`], and must not be used again after this call.
#[export_name = "correspondent_socket_free"]
pub unsafe extern "C" fn socket_free(socket: *mut Socket) {
    if !socket.is_null() {
        Box::from_raw(socket);
    }
}

/// Call this to complete a pending signing process.
///
/// # Safety
///
/// `ctx` must be a valid pointer previously generated by this library,
/// provided to `ApplicationVTable::sign_certificate`.  `ctx` must not be used
/// again for any purpose after calling this function.
///
/// If `success` is true, `client_chain_pem` and `authority_pem` must point
/// to valid, null-terminated ASCII PEM strings.  They will not be used after
/// this function, the caller must clean them up.
#[export_name = "correspondent_finish_signing"]
pub unsafe extern "C" fn finish_signing(
    ctx: *mut SigningContext,
    success: bool,
    client_chain_pem: *const c_char,
    authority_pem: *const c_char,
) {
    if ctx.is_null() {
        return;
    }
    let ctx = Box::from_raw(ctx);
    ctx.finish(success, client_chain_pem, authority_pem);
}

/// Sign a certificate
///
/// This function will sign a certificate in a way compatible with
/// the rest of this library.
///
/// Returns null on error.  Returns a null-terminated ASCII PEM certificate
/// chain on success.
///
/// # Safety
///
/// `csr_pem` and `authority_pem` must point to valid, null-terminated,
/// ASCII PEM strings.  They will not be used after this function; the caller
/// must clean them up.  `authority_key_pk8` must point to a valid allocation
/// of at least `authority_key_pk8_len` bytes.
///
/// To avoid a memory leak, the returned pointer (if not null) must be cleaned
/// up with [`free_string`].
#[export_name = "correspondent_sign_certificate"]
pub unsafe extern "C" fn sign_certificate(
    csr_pem: *const c_char,
    authority_pem: *const c_char,
    authority_key_pk8: *const u8,
    authority_key_pk8_len: usize,
) -> *mut c_char {
    certificate::do_sign(
        csr_pem,
        authority_pem,
        authority_key_pk8,
        authority_key_pk8_len,
    )
    .unwrap_or(std::ptr::null_mut())
}

/// Free a string previously allocated by this library.
///
/// # Safety
///
/// The provided string must have been previously returned by a call to
/// [`sign_certificate`].  It must not be used again after this call.
#[export_name = "correspondent_free_string"]
pub unsafe extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() {
        CString::from_raw(s);
    }
}

/// Create a certificate to be used as a signing authority.
///
/// This function generates a certificate compatible with the rest of this
/// library.
///
/// Returns null on error.
///
/// # Safety
///
/// `dns_name` must point to a valid, null-terminated, ASCII string of the
/// "subject name" to associate with the certificate.
///
/// To avoid a memory leak, the returned pointer (if not null) must be cleaned
/// up with [`free_ca_cert`].
#[export_name = "correspondent_create_ca_cert"]
pub unsafe extern "C" fn create_ca_cert(
    dns_name: *const c_char,
) -> *mut AuthorityCertificate {
    certificate::create_ca_cert(dns_name).unwrap_or(std::ptr::null_mut())
}

/// Free a certificate previously generated by this library.
///
/// # Safety
///
/// The provided pointer must have been previously returned by a call to
/// [`create_ca_cert`].  It must not be used again after this call.
#[export_name = "correspondent_free_ca_cert"]
pub unsafe extern "C" fn free_ca_cert(cert: *mut AuthorityCertificate) {
    certificate::free_ca_cert(cert);
}
