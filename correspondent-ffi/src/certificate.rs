/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{
    convert::TryFrom,
    ffi::{CStr, CString},
    os::raw::c_char,
};

use rcgen::RcgenError;

pub unsafe fn do_sign(
    csr_pem: *const c_char,
    authority_pem: *const c_char,
    authority_key_pk8: *const u8,
    authority_key_pk8_len: usize,
) -> Result<*mut c_char, RcgenError> {
    if csr_pem.is_null()
        || authority_pem.is_null()
        || authority_key_pk8.is_null()
    {
        return Err(RcgenError::CouldNotParseCertificate);
    }
    let csr_pem = CStr::from_ptr(csr_pem)
        .to_str()
        .map_err(|_| RcgenError::CouldNotParseCertificate)?;
    let authority_pem = CStr::from_ptr(authority_pem)
        .to_str()
        .map_err(|_| RcgenError::CouldNotParseCertificate)?;
    let authority_key_pk8 =
        std::slice::from_raw_parts(authority_key_pk8, authority_key_pk8_len);
    let ca_key = rcgen::KeyPair::try_from(authority_key_pk8)?;
    let params = rcgen::CertificateParams::from_ca_cert_pem(authority_pem)?;
    let ca_cert = params.self_signed(&ca_key)?;
    let csr = rcgen::CertificateSigningRequestParams::from_pem(csr_pem)?;
    csr.signed_by(&ca_cert, &ca_key)
        .and_then(|cert| {
            let string = cert.pem();
            CString::new(string)
                .map_err(|_| RcgenError::CouldNotParseCertificate)
        })
        .map(CString::into_raw)
}

/// A representation of a certificate, along with signing keys.
#[repr(C)]
pub struct AuthorityCertificate {
    /// A pointer to a null-terminated ASCII PEM string representing the
    /// certificate.
    pub authority_pem: *mut c_char,

    /// A pointer to an allocation of at least `authority_key_pk8_len` bytes
    /// of a PK8 encoded private key.
    pub authority_key_pk8: *mut u8,

    /// See `authority_key_pk8`.
    pub authority_key_pk8_len: usize,
}

pub unsafe fn create_ca_cert(
    dns_name: *const c_char,
) -> Result<*mut AuthorityCertificate, rcgen::RcgenError> {
    if dns_name.is_null() {
        return Err(RcgenError::CouldNotParseCertificate);
    }
    let dns_name = CStr::from_ptr(dns_name).to_string_lossy().into_owned();
    let ca_cert = rcgen::generate_simple_self_signed(&[dns_name][..])?;
    let cert_pem = ca_cert.cert.pem();
    let key_pk8 = ca_cert.key_pair.serialize_der().into_boxed_slice();
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

pub unsafe fn free_ca_cert(cert: *mut AuthorityCertificate) {
    if !cert.is_null() {
        let cert = Box::from_raw(cert);
        if !cert.authority_pem.is_null() {
            std::mem::drop(CString::from_raw(cert.authority_pem));
        }
        if !cert.authority_key_pk8.is_null() {
            let slice = std::slice::from_raw_parts_mut(
                cert.authority_key_pk8,
                cert.authority_key_pk8_len,
            );
            Box::from_raw(slice);
        }
    }
}
