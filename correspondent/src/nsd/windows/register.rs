/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{
    convert::TryInto,
    ffi::c_void,
    net::IpAddr,
    sync::atomic::{AtomicBool, Ordering},
};

use super::bindings::Windows::Win32::{
    Foundation::{HANDLE, PWSTR},
    NetworkManagement::Dns,
};

pub(super) fn create_service<App: crate::application::Application>(
    app: &App,
    port: u16,
    _bind_addr: Option<IpAddr>,
) -> Option<RegisterRequest> {
    let service_name = format!(
        "{}.{}.local",
        app.service_name(),
        super::super::SERVICE_TYPE
    );
    let mut hostname =
        gethostname::gethostname().to_string_lossy().into_owned();
    hostname.push_str(".local");

    let id_value = app.identity_to_txt(app.identity());
    let id_value = std::str::from_utf8(&id_value).ok()?;
    let txt_pairs = [("id", id_value)];
    let service_instance =
        construct_instance(&service_name, &hostname, port, &txt_pairs)?;
    let complete_flag = Box::leak(Box::new(AtomicBool::new(false)));
    let request = Box::new(Dns::DNS_SERVICE_REGISTER_REQUEST {
        Version: Dns::DNS_QUERY_REQUEST_VERSION1,
        InterfaceIndex: 0,
        pServiceInstance: service_instance.ptr,
        pRegisterCompletionCallback: Some(service_register_complete),
        pQueryContext: complete_flag as *const AtomicBool as *mut c_void,
        hCredentials: HANDLE::default(),
        unicastEnabled: false.into(),
    });
    let request = Box::into_raw(request);
    let retcode =
        unsafe { Dns::DnsServiceRegister(request, std::ptr::null_mut()) };
    if retcode == 9506 {
        Some(RegisterRequest {
            complete_flag,
            _service_instance: service_instance,
            request,
        })
    } else {
        unsafe { Box::from_raw(request) };
        None
    }
}

fn construct_instance(
    service_name: &str,
    hostname: &str,
    port: u16,
    txt_pairs: &[(&str, &str)],
) -> Option<super::ServiceInstance> {
    let txt_count: u32 = txt_pairs.len().try_into().expect(
        "TXT pairs is defined in this module and should be < u32::MAX",
    );
    let mut owned_keys = to_windows_str_boxen(txt_pairs.iter().map(|p| p.0));
    let mut owned_values = to_windows_str_boxen(txt_pairs.iter().map(|p| p.1));
    let mut keys = to_windows_str_array_ptr(&mut owned_keys);
    let mut values = to_windows_str_array_ptr(&mut owned_values);
    let ptr = unsafe {
        Dns::DnsServiceConstructInstance(
            // service name
            service_name,
            // host name
            hostname,
            // ipv4
            std::ptr::null_mut(),
            // ipv6
            std::ptr::null_mut(),
            // port
            port,
            // priority
            0,
            // weight
            0,
            // properties count
            txt_count,
            // keys
            keys[..].as_mut_ptr(),
            // values
            values[..].as_mut_ptr(),
        )
    };
    (!ptr.is_null()).then(|| super::ServiceInstance { ptr })
}

unsafe extern "system" fn service_register_complete(
    status: u32,
    ctx: *mut c_void,
    instance: *mut Dns::DNS_SERVICE_INSTANCE,
) {
    let _service = super::ServiceInstance { ptr: instance };
    if status == 0 {
        let flag = &*(ctx as *const AtomicBool);
        flag.store(true, Ordering::Release);
    }
}

fn to_windows_str_boxen<'a>(
    iter: impl Iterator<Item = &'a str>,
) -> Box<[Box<[u16]>]> {
    iter.map(|s| s.encode_utf16().chain(Some(0)).collect())
        .collect()
}

fn to_windows_str_array_ptr(boxen: &mut [Box<[u16]>]) -> Box<[PWSTR]> {
    boxen
        .iter_mut()
        .map(|slice| PWSTR(<[u16]>::as_mut_ptr(slice)))
        .collect()
}

pub(super) struct RegisterRequest {
    complete_flag: &'static AtomicBool,
    _service_instance: super::ServiceInstance,
    request: *mut Dns::DNS_SERVICE_REGISTER_REQUEST,
}

unsafe impl Send for RegisterRequest {}
unsafe impl Sync for RegisterRequest {}

impl Drop for RegisterRequest {
    fn drop(&mut self) {
        assert!(!self.request.is_null());
        unsafe {
            if self.complete_flag.load(Ordering::Acquire) {
                Dns::DnsServiceDeRegister(self.request, std::ptr::null_mut());
            }
            Box::from_raw(self.request);
            self.request = std::ptr::null_mut();
        }
    }
}
