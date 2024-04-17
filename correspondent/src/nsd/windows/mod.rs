/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{future::Future, net::IpAddr, sync::Arc};

use windows::Win32::NetworkManagement::Dns;

// #[allow(clippy::unseparated_literal_suffix)]
// #[allow(clippy::unreadable_literal)]
// #[allow(clippy::default_trait_access)]
// #[allow(clippy::semicolon_if_nothing_returned)]
// #[allow(clippy::unwrap_used)]
// mod bindings;

mod browse;
mod register;

use {
    browse::{browse_services, CancelBrowse},
    register::{create_service, RegisterRequest},
};

pub struct NsdManager {
    _cancel_browse: Option<CancelToken<CancelBrowse>>,
    _deregister: Option<RegisterRequest>,
}

impl<T> super::Interface<T> for NsdManager
where
    T: crate::application::IdentityCanonicalizer,
{
    fn start<Found, FoundFut, Main>(
        socket: crate::Socket<T>,
        service_name: String,
        peer_found: Found,
        main: Main,
    ) -> Option<Self>
    where
        Found: 'static
            + Send
            + Sync
            + Fn(super::FoundPeer<T::Identity>, IpAddr) -> FoundFut,
        FoundFut: Send + Sync + Future<Output = ()>,
        Main: 'static + Send + Sync + Future<Output = ()>,
    {
        let _deregister = socket.port().and_then(|port| {
            create_service(
                &service_name,
                socket.instance_id,
                &socket.identity.identity_txt,
                port,
                socket.discovery_addr,
            )
        });
        let _cancel_browse = browse_services(
            Arc::clone(&socket.identity),
            service_name,
            peer_found,
        );
        tokio::spawn(main);
        Some(Self {
            _cancel_browse,
            _deregister,
        })
    }
}

unsafe fn utf16_null_equals(test: &[u16], ptr: *const u16) -> bool {
    let test_chars = test.iter().copied();
    let ptr_chars = (0..).map(|i| *ptr.offset(i));
    test_chars.zip(ptr_chars).all(|(a, b)| a == b)
}

unsafe fn utf16_null_to_string(ptr: *const u16) -> String {
    let len = (0..).take_while(|&i| *ptr.offset(i) != 0).count();
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}

#[derive(Default)]
struct CancelToken<T: CancelType> {
    token: Box<Dns::DNS_SERVICE_CANCEL>,
    _type: T,
}

impl<T: CancelType> CancelToken<T> {
    fn as_ptr(&mut self) -> *mut Dns::DNS_SERVICE_CANCEL {
        &mut *self.token
    }
}

unsafe impl<T: CancelType + Send> Send for CancelToken<T> {}
unsafe impl<T: CancelType> Sync for CancelToken<T> {}

impl<T: CancelType> Drop for CancelToken<T> {
    fn drop(&mut self) {
        if !self.token.reserved.is_null() {
            unsafe {
                (T::CANCEL_FN)(&*self.token);
            }
            self.token.reserved = std::ptr::null_mut();
        }
    }
}

trait CancelType {
    const CANCEL_FN: unsafe fn(*const Dns::DNS_SERVICE_CANCEL) -> i32;
}

struct ServiceInstance {
    ptr: *const Dns::DNS_SERVICE_INSTANCE,
}

impl ServiceInstance {
    unsafe fn get(&self) -> Option<&Dns::DNS_SERVICE_INSTANCE> {
        (!self.ptr.is_null()).then(|| &*self.ptr)
    }
}

impl Drop for ServiceInstance {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                Dns::DnsServiceFreeInstance(self.ptr);
            }
            self.ptr = std::ptr::null_mut();
        }
    }
}
