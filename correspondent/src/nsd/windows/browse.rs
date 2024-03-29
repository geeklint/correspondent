/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{
    ffi::c_void,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use super::bindings::Windows::Win32::{
    Foundation::PWSTR, NetworkManagement::Dns,
};

pub(super) fn browse_services<T, Found, FoundFut>(
    identity: Arc<crate::socket::Identity<T>>,
    peer_found: Found,
) -> Option<super::CancelToken<CancelBrowse>>
where
    T: crate::IdentityCanonicalizer,
    Found: 'static
        + Send
        + Sync
        + Fn(super::super::FoundPeer<T::Identity>, IpAddr) -> FoundFut,
    FoundFut: Send + Sync + Future<Output = ()>,
{
    let browse_context: Box<Arc<dyn BrowsingContext>> =
        Box::new(Arc::new(BrowsingContextGeneric {
            handle: tokio::runtime::Handle::current(),
            identity,
            peer_found,
        }));
    let callback = unsafe {
        let mut cb_union: Dns::DNS_SERVICE_BROWSE_REQUEST_0 =
            std::mem::zeroed();
        cb_union.pBrowseCallback = service_browse_callback as *mut c_void;
        cb_union
    };
    let query_name = windows::IntoParam::<'_, PWSTR>::into_param(format!(
        "{}.local",
        super::super::SERVICE_TYPE
    ))
    .abi();
    let mut request = Dns::DNS_SERVICE_BROWSE_REQUEST {
        Version: Dns::DNS_QUERY_REQUEST_VERSION1,
        InterfaceIndex: 0,
        QueryName: query_name,
        Anonymous: callback,
        pQueryContext: Box::into_raw(browse_context) as *mut c_void,
    };
    let mut cancel_token = super::CancelToken::<CancelBrowse>::default();
    let retcode = unsafe {
        Dns::DnsServiceBrowse(&mut request as *mut _, cancel_token.as_ptr())
    };
    if retcode != 9506 {
        return None;
    }
    Some(cancel_token)
}

#[derive(Default)]
pub(super) struct CancelBrowse;

impl super::CancelType for CancelBrowse {
    const CANCEL_FN: unsafe fn(*mut Dns::DNS_SERVICE_CANCEL) -> i32 =
        Dns::DnsServiceBrowseCancel;
}

#[derive(Default)]
struct CancelResolve;

impl super::CancelType for CancelResolve {
    const CANCEL_FN: unsafe fn(*mut Dns::DNS_SERVICE_CANCEL) -> i32 =
        Dns::DnsServiceResolveCancel;
}

struct RecordList {
    ptr: *mut Dns::DNS_RECORDW,
}

impl Drop for RecordList {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                Dns::DnsFree(self.ptr as *mut _, Dns::DnsFreeRecordList);
            }
            self.ptr = std::ptr::null_mut();
        }
    }
}

unsafe extern "system" fn service_browse_callback(
    status: u32,
    ctx: *mut c_void,
    records: *mut Dns::DNS_RECORDW,
) {
    let _guard = RecordList { ptr: records };
    if status != 0 {
        return;
    }
    let mut current = records;
    while !current.is_null() {
        if u32::from((*current).wType) != Dns::DNS_TYPE_SRV {
            current = (*current).pNext;
            continue;
        }
        let mut resolve_request = Dns::DNS_SERVICE_RESOLVE_REQUEST {
            Version: Dns::DNS_QUERY_REQUEST_VERSION1,
            InterfaceIndex: 0,
            QueryName: (*current).pName,
            pResolveCompletionCallback: Some(service_resolve_callback),
            pQueryContext: ctx,
        };
        let mut cancel_token = super::CancelToken::<CancelResolve>::default();
        let retcode = Dns::DnsServiceResolve(
            &mut resolve_request,
            cancel_token.as_ptr(),
        );
        #[allow(clippy::mem_forget)]
        std::mem::forget(cancel_token);
        if retcode != 9506 {
            //eprintln!("failed to request resolve: {}", retcode);
        }
        current = (*current).pNext;
    }
}

unsafe extern "system" fn service_resolve_callback(
    status: u32,
    ctx: *mut c_void,
    instance: *mut Dns::DNS_SERVICE_INSTANCE,
) {
    let instance = super::ServiceInstance { ptr: instance };
    if status != 0 {
        return;
    }
    let ctx = &*(ctx as *const Arc<dyn BrowsingContext>);
    let ctx = Arc::clone(ctx);
    if let Some(instance_ref) = instance.get() {
        ctx.do_spawn(instance_ref);
    }
}

struct BrowsingContextGeneric<T: crate::IdentityCanonicalizer, Found> {
    handle: tokio::runtime::Handle,
    identity: Arc<crate::socket::Identity<T>>,
    peer_found: Found,
}

trait BrowsingContext {
    unsafe fn do_spawn(self: Arc<Self>, instance: &Dns::DNS_SERVICE_INSTANCE);
}

impl<T, Found, FoundFut> BrowsingContext for BrowsingContextGeneric<T, Found>
where
    T: crate::IdentityCanonicalizer,
    Found: 'static
        + Send
        + Sync
        + Fn(super::super::FoundPeer<T::Identity>, IpAddr) -> FoundFut,
    FoundFut: Send + Sync + Future<Output = ()>,
{
    unsafe fn do_spawn(self: Arc<Self>, instance: &Dns::DNS_SERVICE_INSTANCE) {
        let ipv4 = (!instance.ip4Address.is_null()).then(|| {
            IpAddr::V4(Ipv4Addr::from((*instance.ip4Address).to_be()))
        });
        let _ipv6 = (!instance.ip6Address.is_null()).then(|| {
            IpAddr::V6(Ipv6Addr::from((*instance.ip6Address).IP6Byte))
        });
        if instance.pszHostName.is_null() {
            return;
        }
        let host = super::utf16_null_to_string(instance.pszHostName.0);
        let port = instance.wPort;
        let props_len = instance.dwPropertyCount as usize;
        let keys = std::slice::from_raw_parts(instance.keys, props_len);
        let values = std::slice::from_raw_parts(instance.values, props_len);
        let id_key = [b'i'.into(), b'd'.into(), 0];
        let ins_key = [b'i'.into(), b'n'.into(), b's'.into(), 0];
        let mut identity = None;
        let mut instance = None;
        for (key, value) in keys.iter().copied().zip(values.iter().copied()) {
            if super::utf16_null_equals(&id_key, key.0) {
                let id_str = super::utf16_null_to_string(value.0);
                identity =
                    self.identity.canonicalizer.parse_txt(id_str.as_bytes());
            } else if super::utf16_null_equals(&ins_key, key.0) {
                let ins_str = super::utf16_null_to_string(value.0);
                instance = u64::from_str_radix(&ins_str, 16).ok();
            }
        }
        let (identity, instance_id) = match (identity, instance) {
            (Some(id), Some(ins)) => (id, ins),
            _ => return,
        };
        // no ipv6 on Windows because of dual-stack things
        if let Some(ip_addr) = ipv4 {
            let ctx = Arc::clone(&self);
            let found_peer = super::super::FoundPeer {
                hostname: host,
                identity,
                instance_id,
                port,
            };
            self.handle.spawn(async move {
                (ctx.peer_found)(found_peer, ip_addr).await;
            });
        }
    }
}
