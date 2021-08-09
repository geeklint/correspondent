use std::{
    convert::TryInto,
    ffi::c_void,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

#[allow(clippy::unseparated_literal_suffix)]
#[allow(clippy::unreadable_literal)]
#[allow(clippy::default_trait_access)]
#[allow(clippy::semicolon_if_nothing_returned)]
#[allow(clippy::unwrap_used)]
mod bindings;

use bindings::Windows::Win32::Foundation::HANDLE;
use bindings::Windows::Win32::NetworkManagement::Dns;

pub struct NsdManager {
    _cancel_browse: Option<CancelToken<CancelBrowse>>,
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
        create_service(&*app, port, bind_addr);
        let _cancel_browse = browse_services(app, peer_found);
        tokio::spawn(main);
        Some(Self { _cancel_browse })
    }
}

fn create_service<App: crate::application::Application>(
    app: &App,
    port: u16,
    _bind_addr: Option<IpAddr>,
) {
    use bindings::Windows::Win32::Foundation::PWSTR;
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

    let service_name =
        format!("{}.{}.local", app.service_name(), super::SERVICE_TYPE);
    let mut hostname =
        gethostname::gethostname().to_string_lossy().into_owned();
    hostname.push_str(".local");

    let id_value = app.identity_to_txt(app.identity());
    let id_value = if let Ok(s) = std::str::from_utf8(&id_value) {
        s
    } else {
        return;
    };
    let txt_pairs = [("id", id_value)];
    let mut owned_keys = to_windows_str_boxen(txt_pairs.iter().map(|p| p.0));
    let mut owned_values = to_windows_str_boxen(txt_pairs.iter().map(|p| p.1));
    let mut keys = to_windows_str_array_ptr(&mut owned_keys);
    let mut values = to_windows_str_array_ptr(&mut owned_values);
    let instance_ptr = unsafe {
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
        txt_pairs.len().try_into().expect(
            "TXT pairs is defined in this function and should be < u32::MAX"),
        // keys
        keys[..].as_mut_ptr(),
        // values
        values[..].as_mut_ptr(),
    )
    };
    let service_instance = if instance_ptr.is_null() {
        return;
    } else {
        ServiceInstance { ptr: instance_ptr }
    };
    let returned_keys = unsafe { (*service_instance.ptr).keys };
    assert!(!std::ptr::eq(keys[..].as_mut_ptr(), returned_keys));
    let mut request = Dns::DNS_SERVICE_REGISTER_REQUEST {
        Version: Dns::DNS_QUERY_REQUEST_VERSION1,
        InterfaceIndex: 0,
        pServiceInstance: service_instance.ptr,
        pRegisterCompletionCallback: Some(service_register_complete),
        pQueryContext: std::ptr::null_mut(),
        hCredentials: HANDLE::default(),
        unicastEnabled: false.into(),
    };
    let retcode = unsafe {
        Dns::DnsServiceRegister(&mut request as *mut _, std::ptr::null_mut())
    };
    if retcode != 9506 {
        // failed
    }
}

fn browse_services<App, Found, FoundFut>(
    app: Arc<App>,
    peer_found: Found,
) -> Option<CancelToken<CancelBrowse>>
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
    use bindings::Windows::Win32::Foundation::PWSTR;
    let query_name = windows::IntoParam::<'_, PWSTR>::into_param(format!(
        "{}.local",
        super::SERVICE_TYPE
    ))
    .abi();
    let mut request = Dns::DNS_SERVICE_BROWSE_REQUEST {
        Version: Dns::DNS_QUERY_REQUEST_VERSION1,
        InterfaceIndex: 0,
        QueryName: query_name,
        Anonymous: callback,
        pQueryContext: Box::into_raw(browse_context) as *mut c_void,
    };
    let mut cancel_token = CancelToken::<CancelBrowse>::default();
    let retcode = unsafe {
        Dns::DnsServiceBrowse(&mut request as *mut _, cancel_token.as_ptr())
    };
    if retcode != 9506 {
        return None;
    }
    Some(cancel_token)
}

unsafe extern "system" fn service_register_complete(
    status: u32,
    _ctx: *mut c_void,
    instance: *mut Dns::DNS_SERVICE_INSTANCE,
) {
    let _service = ServiceInstance { ptr: instance };
    if status != 0 {
        //eprintln!("failed to register; err = {}", status);
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
        let mut cancel_token = CancelToken::<CancelResolve>::default();
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
    let instance = ServiceInstance { ptr: instance };
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
        let host = utf16_null_to_string(instance.pszHostName.0);
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
                utf16_null_equals(&id_key, key.0)
                    .then(|| utf16_null_to_string(value.0))
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

#[derive(Default)]
struct CancelBrowse;

impl CancelType for CancelBrowse {
    const CANCEL_FN: unsafe fn(*mut Dns::DNS_SERVICE_CANCEL) -> i32 =
        Dns::DnsServiceBrowseCancel;
}

#[derive(Default)]
struct CancelResolve;

impl CancelType for CancelResolve {
    const CANCEL_FN: unsafe fn(*mut Dns::DNS_SERVICE_CANCEL) -> i32 =
        Dns::DnsServiceResolveCancel;
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
