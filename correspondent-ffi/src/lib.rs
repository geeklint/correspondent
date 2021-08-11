use std::{
    ffi::{c_void, CStr, CString},
    os::raw::c_char,
};

mod application;
mod certificate;

thread_local! {
    static VERSION: CString = CString::new(env!("CARGO_PKG_VERSION")).unwrap();
}

pub use application::*;
pub use certificate::AuthorityCertificate;

/// Get the version number of this library
#[export_name = "correspondent_version"]
pub extern "C" fn version() -> *const c_char {
    VERSION.with(|cstr| cstr.as_ptr())
}

#[export_name = "correspondent_finish_signing"]
pub unsafe extern "C" fn finish_signing(
    ctx: *mut SigningContext,
    success: bool,
    client_chain_pem: *const c_char,
    authority_pem: *const c_char,
) {
    assert!(!ctx.is_null());
    let ctx = Box::from_raw(ctx);
    ctx.finish(success, client_chain_pem, authority_pem);
}

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

#[export_name = "correspondent_free_string"]
pub unsafe extern "C" fn free_string(s: *mut c_char) {
    assert!(!s.is_null());
    CString::from_raw(s);
}

#[export_name = "correspondent_start"]
pub unsafe extern "C" fn start() {}
