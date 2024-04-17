/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{
    convert::TryInto,
    ffi::c_void,
    net::{IpAddr, Ipv4Addr},
    os::windows::ffi::OsStrExt,
    sync::atomic::{AtomicBool, Ordering},
};

use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{DNS_REQUEST_PENDING, HANDLE},
        NetworkManagement::Dns,
    },
};

pub(super) fn create_service(
    service_name: &str,
    instance_id: u64,
    identity_txt: &[u8],
    port: u16,
    _bind_addr: Option<IpAddr>,
) -> Option<RegisterRequest> {
    let service_name =
        format!("{}.{}.local", service_name, super::super::SERVICE_TYPE);
    let mut hostname =
        gethostname::gethostname().to_string_lossy().into_owned();
    hostname.push_str(".local");

    let id_value = std::str::from_utf8(identity_txt).ok()?;
    let ins_value = format!("{:x}", instance_id);
    let txt_pairs = [("id", id_value), ("ins", &ins_value)];
    let service_instance =
        construct_instance(&service_name, &hostname, port, &txt_pairs)?;
    let complete_flag = Box::leak(Box::new(AtomicBool::new(false)));
    let request = Box::new(Dns::DNS_SERVICE_REGISTER_REQUEST {
        Version: Dns::DNS_QUERY_REQUEST_VERSION1.0,
        InterfaceIndex: 0,
        pServiceInstance: service_instance.ptr.cast_mut(),
        pRegisterCompletionCallback: Some(service_register_complete),
        pQueryContext: <*mut _>::cast::<c_void>(complete_flag),
        hCredentials: HANDLE::default(),
        unicastEnabled: false.into(),
    });
    let request = Box::into_raw(request);
    let retcode = unsafe { Dns::DnsServiceRegister(request, None) };
    if retcode == (DNS_REQUEST_PENDING as u32) {
        Some(RegisterRequest {
            complete_flag,
            _service_instance: service_instance,
            request,
        })
    } else {
        tracing::warn!("unexpected result from DnsServiceRegister: {retcode}");
        let _ = unsafe { Box::from_raw(request) };
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
    let keys = to_windows_str_array_ptr(&mut owned_keys);
    let values = to_windows_str_array_ptr(&mut owned_values);
    let service_name = std::ffi::OsStr::new(service_name)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<u16>>();
    let hostname = std::ffi::OsStr::new(hostname)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<u16>>();
    let ptr = unsafe {
        Dns::DnsServiceConstructInstance(
            // service name
            PCWSTR(service_name.as_ptr()),
            // host name
            PCWSTR(hostname.as_ptr()),
            // ipv4
            None,
            // ipv6
            None,
            // port
            port,
            // priority
            0,
            // weight
            0,
            // properties count
            txt_count,
            // keys
            keys[..].as_ptr(),
            // values
            values[..].as_ptr(),
        )
    };
    (!ptr.is_null()).then(|| super::ServiceInstance { ptr })
}

#[tracing::instrument]
unsafe extern "system" fn service_register_complete(
    status: u32,
    ctx: *const c_void,
    instance: *const Dns::DNS_SERVICE_INSTANCE,
) {
    let service = super::ServiceInstance { ptr: instance };
    if status == 0 {
        let flag = &*(ctx.cast::<AtomicBool>());
        flag.store(true, Ordering::Release);
        if let Some(s) = service.get() {
            let mut ip = Ipv4Addr::UNSPECIFIED;
            let dbg_name = s.pszInstanceName.display();
            if !s.ip4Address.is_null() {
                ip = Ipv4Addr::from((*s.ip4Address).to_be());
            }
            let port = s.wPort;
            tracing::info!(
                "registered dns-sd service {dbg_name} => {ip}:{port}"
            );
        }
    } else {
        tracing::warn!("non-zero status registering service: {status}");
    }
}

fn to_windows_str_boxen<'a>(
    iter: impl Iterator<Item = &'a str>,
) -> Box<[Box<[u16]>]> {
    iter.map(|s| s.encode_utf16().chain(Some(0)).collect())
        .collect()
}

fn to_windows_str_array_ptr(boxen: &mut [Box<[u16]>]) -> Box<[PCWSTR]> {
    boxen
        .iter()
        .map(|slice| PCWSTR(<[u16]>::as_ptr(slice)))
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
                Dns::DnsServiceDeRegister(self.request, None);
            }
            let _ = Box::from_raw(self.request);
            self.request = std::ptr::null_mut();
        }
    }
}
