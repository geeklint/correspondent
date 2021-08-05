use std::{
    borrow::Cow, convert::TryInto, future::Future, net::IpAddr, sync::Arc,
    time::Duration,
};

#[allow(clippy::unseparated_literal_suffix)]
#[allow(clippy::unreadable_literal)]
#[allow(clippy::default_trait_access)]
#[allow(clippy::semicolon_if_nothing_returned)]
#[allow(clippy::unwrap_used)]
mod bindings;

use bindings::Windows::Win32::NetworkManagement::Dns;

pub struct NsdManager {
    browse_handle: Option<ServiceHandle>,
    register_handle: Option<ServiceHandle>,
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
        let browse_handle = create_service(&*app, port, bind_addr);
        let register_handle = browse_services(app, bind_addr, peer_found);
        (browse_handle.is_some() || register_handle.is_some()).then(|| Self {
            browse_handle,
            register_handle,
        })
    }
}

fn create_service<App: crate::application::Application>(
    app: &App,
    port: u16,
    bind_addr: Option<IpAddr>,
) -> Option<ServiceHandle> {
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

    let id_value = app.identity_to_txt(app.identity());
    let mut ip4_addr = 0_u32;
    let mut ip6_addr = unsafe { std::mem::zeroed() };
    let txt_pairs = [("id", std::str::from_utf8(&id_value).ok()?)];
    let mut owned_keys = to_windows_str_boxen(txt_pairs.iter().map(|p| p.0));
    let mut owned_values = to_windows_str_boxen(txt_pairs.iter().map(|p| p.1));
    let mut keys = to_windows_str_array_ptr(&mut owned_keys);
    let mut values = to_windows_str_array_ptr(&mut owned_values);
    let instance_ptr = unsafe {
        Dns::DnsServiceConstructInstance(
        // service name
        app.service_name(),
        // host name
        "",
        // ipv4
        &mut ip4_addr as *mut _,
        // ipv6
        &mut ip6_addr as *mut _,
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
    (!instance_ptr.is_null()).then(|| ())?;
    None
}

fn browse_services<App, Found, FoundFut>(
    app: Arc<App>,
    bind_addr: Option<IpAddr>,
    peer_found: Found,
) -> Option<ServiceHandle>
where
    App: crate::application::Application,
    Found: 'static
        + Send
        + Sync
        + Fn(App::Identity, String, IpAddr, u16) -> FoundFut,
    FoundFut: Send + Sync + Future<Output = ()>,
{
    todo!()
}

struct ServiceHandle {
    token: Dns::DNS_SERVICE_CANCEL,
    cancel_fn: unsafe fn(*mut Dns::DNS_SERVICE_CANCEL),
}

unsafe impl Send for ServiceHandle {}
unsafe impl Sync for ServiceHandle {}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        let ptr = (&mut self.token) as *mut _;
        unsafe {
            (self.cancel_fn)(ptr);
        }
    }
}

struct ServiceInstance {
    ptr: *mut Dns::DNS_SERVICE_INSTANCE,
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
