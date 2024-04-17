/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::{
    convert::TryFrom,
    ffi::c_void,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::windows::ffi::OsStrExt,
    sync::Arc,
};

use windows::{
    core::PCWSTR,
    Win32::{Foundation::DNS_REQUEST_PENDING, NetworkManagement::Dns},
};

pub(super) fn browse_services<T, Found, FoundFut>(
    identity: Arc<crate::socket::Identity<T>>,
    service_name_prefix: String,
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
            service_name_prefix,
            peer_found,
        }));
    let callback = unsafe {
        let mut cb_union: Dns::DNS_SERVICE_BROWSE_REQUEST_0 =
            std::mem::zeroed();
        cb_union.pBrowseCallback = Some(service_browse_callback);
        cb_union
    };
    let query_name = std::ffi::OsString::from(format!(
        "{}.local",
        super::super::SERVICE_TYPE
    ));
    let query_name = query_name
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<u16>>();
    let request = Dns::DNS_SERVICE_BROWSE_REQUEST {
        Version: Dns::DNS_QUERY_REQUEST_VERSION1.0,
        InterfaceIndex: 0,
        QueryName: PCWSTR(query_name.as_ptr()),
        Anonymous: callback,
        pQueryContext: Box::into_raw(browse_context).cast(),
    };
    let mut cancel_token = super::CancelToken::<CancelBrowse>::default();
    let retcode =
        unsafe { Dns::DnsServiceBrowse(&request, cancel_token.as_ptr()) };
    if retcode != DNS_REQUEST_PENDING {
        tracing::warn!("unexpected result from DnsServiceBrowse: {retcode}");
        return None;
    }
    Some(cancel_token)
}

#[derive(Default)]
pub(super) struct CancelBrowse;

impl super::CancelType for CancelBrowse {
    const CANCEL_FN: unsafe fn(*const Dns::DNS_SERVICE_CANCEL) -> i32 =
        Dns::DnsServiceBrowseCancel;
}

#[derive(Default)]
struct CancelResolve;

impl super::CancelType for CancelResolve {
    const CANCEL_FN: unsafe fn(*const Dns::DNS_SERVICE_CANCEL) -> i32 =
        Dns::DnsServiceResolveCancel;
}

struct RecordList {
    ptr: *const Dns::DNS_RECORDW,
}

impl Drop for RecordList {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                Dns::DnsFree(Some(self.ptr.cast()), Dns::DnsFreeRecordList);
            }
            self.ptr = std::ptr::null_mut();
        }
    }
}

#[tracing::instrument]
unsafe extern "system" fn service_browse_callback(
    status: u32,
    ctx: *const c_void,
    records: *const Dns::DNS_RECORDW,
) {
    let _guard = RecordList { ptr: records };
    if status != 0 {
        tracing::warn!("non-zero status while browsing services: {status}");
        return;
    }
    let mut next = records;
    let mut current;
    while {
        current = next;
        !current.is_null()
    } {
        next = (*current).pNext;
        if (*current).wType != Dns::DNS_TYPE_SRV.0 {
            continue;
        }
        {
            let ctx = &*ctx.cast::<Arc<dyn BrowsingContext>>();
            let service_name = (*current).pName.as_wide();
            if !ctx.check_interest(service_name) {
                continue;
            }
        }
        let resolve_request = Dns::DNS_SERVICE_RESOLVE_REQUEST {
            Version: Dns::DNS_QUERY_REQUEST_VERSION1.0,
            InterfaceIndex: 0,
            QueryName: (*current).pName,
            pResolveCompletionCallback: Some(service_resolve_callback),
            pQueryContext: ctx.cast_mut(),
        };
        let mut cancel_token = super::CancelToken::<CancelResolve>::default();
        let retcode =
            Dns::DnsServiceResolve(&resolve_request, cancel_token.as_ptr());
        #[allow(clippy::mem_forget)]
        std::mem::forget(cancel_token);
        if retcode != DNS_REQUEST_PENDING {
            tracing::warn!("failed to request resolve: {retcode}");
        }
    }
}

#[tracing::instrument]
unsafe extern "system" fn service_resolve_callback(
    status: u32,
    ctx: *const c_void,
    instance: *const Dns::DNS_SERVICE_INSTANCE,
) {
    let instance = super::ServiceInstance { ptr: instance };
    if status != 0 {
        tracing::warn!("non-zero status resolving service: {status}");
        return;
    }
    let ctx = &*ctx.cast::<Arc<dyn BrowsingContext>>();
    let ctx = Arc::clone(ctx);
    if let Some(instance_ref) = instance.get() {
        ctx.do_spawn(instance_ref);
    }
}

struct BrowsingContextGeneric<T: crate::IdentityCanonicalizer, Found> {
    handle: tokio::runtime::Handle,
    identity: Arc<crate::socket::Identity<T>>,
    service_name_prefix: String,
    peer_found: Found,
}

trait BrowsingContext {
    fn check_interest(&self, service_name: &[u16]) -> bool;
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
    fn check_interest(&self, service_name: &[u16]) -> bool {
        let mut prefix_iter = self.service_name_prefix.encode_utf16();
        let mut srv_name_iter = service_name.iter().copied();
        loop {
            match (prefix_iter.next(), srv_name_iter.next()) {
                (None, _) => return true,
                (Some(pc), Some(nc)) if pc == nc => continue,
                _ => return false,
            }
        }
    }

    unsafe fn do_spawn(self: Arc<Self>, instance: &Dns::DNS_SERVICE_INSTANCE) {
        let ipv4 = (!instance.ip4Address.is_null()).then(|| {
            IpAddr::V4(Ipv4Addr::from((*instance.ip4Address).to_be()))
        });
        let _ipv6 = (!instance.ip6Address.is_null()).then(|| {
            IpAddr::V6(Ipv6Addr::from((*instance.ip6Address).IP6Byte))
        });
        if instance.pszHostName.is_null() {
            tracing::warn!("dns service instance hostname was null");
            return;
        }
        let host = super::utf16_null_to_string(instance.pszHostName.0);
        let port = instance.wPort;
        let props_len = usize::try_from(instance.dwPropertyCount)
            .expect("u32 should be convertable to usize");
        let keys = std::slice::from_raw_parts(instance.keys, props_len);
        let values = std::slice::from_raw_parts(instance.values, props_len);
        let id_key = b"id\0".map(u16::from);
        let ins_key = b"ins\0".map(u16::from);
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
