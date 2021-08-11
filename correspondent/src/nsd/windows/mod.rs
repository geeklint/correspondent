/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{future::Future, net::IpAddr, sync::Arc};

#[allow(clippy::unseparated_literal_suffix)]
#[allow(clippy::unreadable_literal)]
#[allow(clippy::default_trait_access)]
#[allow(clippy::semicolon_if_nothing_returned)]
#[allow(clippy::unwrap_used)]
mod bindings;

mod browse;
mod register;

use {
    bindings::Windows::Win32::NetworkManagement::Dns,
    browse::{browse_services, CancelBrowse},
    register::{create_service, RegisterRequest},
};

pub struct NsdManager {
    _cancel_browse: Option<CancelToken<CancelBrowse>>,
    _deregister: Option<RegisterRequest>,
}

impl<App> super::Interface<App> for NsdManager
where
    App: crate::application::Application,
{
    fn start<Found, FoundFut, Main>(
        app: Arc<App>,
        bind_addr: Option<IpAddr>,
        port: u16,
        peer_found: Found,
        main: Main,
    ) -> Option<Self>
    where
        Found: 'static
            + Send
            + Sync
            + Fn(App::Identity, String, IpAddr, u16) -> FoundFut,
        FoundFut: Send + Sync + Future<Output = ()>,
        Main: 'static + Send + Sync + Future<Output = ()>,
    {
        let _deregister = create_service(&*app, port, bind_addr);
        let _cancel_browse = browse_services(app, peer_found);
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
    token: Dns::DNS_SERVICE_CANCEL,
    _type: T,
}

impl<T: CancelType> CancelToken<T> {
    fn as_ptr(&mut self) -> *mut Dns::DNS_SERVICE_CANCEL {
        (&mut self.token) as *mut _
    }
}

unsafe impl<T: CancelType + Send> Send for CancelToken<T> {}
unsafe impl<T: CancelType> Sync for CancelToken<T> {}

impl<T: CancelType> Drop for CancelToken<T> {
    fn drop(&mut self) {
        if !self.token.reserved.is_null() {
            unsafe {
                (T::CANCEL_FN)(&mut self.token);
            }
        }
    }
}

trait CancelType {
    const CANCEL_FN: unsafe fn(*mut Dns::DNS_SERVICE_CANCEL) -> i32;
}

struct ServiceInstance {
    ptr: *mut Dns::DNS_SERVICE_INSTANCE,
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
        }
    }
}
