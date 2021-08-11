/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
};

use rcgen::RcgenError;

pub(crate) unsafe fn do_sign(
    csr_pem: *const c_char,
    authority_pem: *const c_char,
    authority_key_pk8: *const u8,
    authority_key_pk8_len: usize,
) -> Result<*mut c_char, RcgenError> {
    assert!(!csr_pem.is_null());
    assert!(!authority_pem.is_null());
    assert!(!authority_key_pk8.is_null());
    let csr_pem = CStr::from_ptr(csr_pem)
        .to_str()
        .map_err(|_| RcgenError::CouldNotParseCertificate)?;
    let authority_pem = CStr::from_ptr(authority_pem)
        .to_str()
        .map_err(|_| RcgenError::CouldNotParseCertificate)?;
    let authority_key_pk8 =
        std::slice::from_raw_parts(authority_key_pk8, authority_key_pk8_len);
    let ca_key = rcgen::KeyPair::from_der(authority_key_pk8)?;
    let params =
        rcgen::CertificateParams::from_ca_cert_pem(authority_pem, ca_key)?;
    let ca_cert = rcgen::Certificate::from_params(params)?;
    let csr = rcgen::CertificateSigningRequest::from_pem(csr_pem)?;
    csr.serialize_pem_with_signer(&ca_cert)
        .and_then(|string| {
            CString::new(string)
                .map_err(|_| RcgenError::CouldNotParseCertificate)
        })
        .map(|c_string| c_string.into_raw())
}

#[repr(C)]
pub struct AuthorityCertificate {
    pub authority_pem: *mut c_char,
    pub authority_key_pk8: *mut u8,
    pub authority_key_pk8_len: usize,
}

pub(crate) unsafe fn create_ca_cert(
    dns_name: *const c_char,
) -> Result<*mut AuthorityCertificate, rcgen::RcgenError> {
    assert!(!dns_name.is_null());
    let dns_name = CStr::from_ptr(dns_name).to_string_lossy().into_owned();
    let ca_cert = rcgen::generate_simple_self_signed(&[dns_name][..])?;
    let cert_pem = ca_cert.serialize_pem()?;
    let key_pk8 = ca_cert.serialize_private_key_der().into_boxed_slice();
    let authority_pem = CString::new(cert_pem)
        .map_err(|_| RcgenError::CouldNotParseCertificate)?
        .into_raw();
    let authority_key_pk8_len = key_pk8.len();
    let authority_key_pk8 = Box::into_raw(key_pk8) as *mut u8;
    let result = Box::new(AuthorityCertificate {
        authority_pem,
        authority_key_pk8,
        authority_key_pk8_len,
    });
    Ok(Box::into_raw(result))
}

pub(crate) unsafe fn cleanup_ca_cert(cert: *mut AuthorityCertificate) {
    assert!(!cert.is_null());
    let cert = Box::from_raw(cert);
    assert!(!cert.authority_pem.is_null());
    assert!(!cert.authority_key_pk8.is_null());
    CString::from_raw(cert.authority_pem);
    let slice = std::slice::from_raw_parts_mut(
        cert.authority_key_pk8,
        cert.authority_key_pk8_len,
    );
    Box::from_raw(slice);
}
