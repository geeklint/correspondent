use std::{
    ffi::c_void,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use super::bindings::Windows::Win32::{
    Foundation::PWSTR,
    NetworkManagement::Dns,
};

pub(super) fn browse_services<App, Found, FoundFut>(
    app: Arc<App>,
    peer_found: Found,
) -> Option<super::CancelToken<CancelBrowse>>
where
    App: crate::application::Application,
    Found: 'static
        + Send
        + Sync
        + Fn(App::Identity, String, IpAddr, u16) -> FoundFut,
    FoundFut: Send + Sync + Future<Output = ()>,
{
    let browse_context: Box<Arc<dyn BrowsingContext>> =
        Box::new(Arc::new(BrowsingContextGeneric {
            handle: tokio::runtime::Handle::current(),
            app,
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

struct BrowsingContextGeneric<App, Found> {
    handle: tokio::runtime::Handle,
    app: Arc<App>,
    peer_found: Found,
}

trait BrowsingContext {
    unsafe fn do_spawn(self: Arc<Self>, instance: &Dns::DNS_SERVICE_INSTANCE);
}

impl<App, Found, FoundFut> BrowsingContext
    for BrowsingContextGeneric<App, Found>
where
    App: crate::application::Application,
    Found: 'static
        + Send
        + Sync
        + Fn(App::Identity, String, IpAddr, u16) -> FoundFut,
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
        let identity = match keys
            .iter()
            .copied()
            .zip(values.iter().copied())
            .find_map(|(key, value)| {
                super::utf16_null_equals(&id_key, key.0)
                    .then(|| super::utf16_null_to_string(value.0))
            })
            .and_then(|s| self.app.identity_from_txt(s.as_bytes()))
        {
            Some(id) => id,
            None => {
                return;
            }
        };
        // no ipv6 on Windows because of dual-stack things
        if let Some(ip_addr) = ipv4 {
            let ctx = Arc::clone(&self);
            self.handle.spawn(async move {
                (ctx.peer_found)(identity, host, ip_addr, port).await;
            });
        }
    }
}
