// This code was autogenerated with `dbus-codegen-rust -c nonblock -m None`, see https://github.com/diwic/dbus-rs
use dbus;
#[allow(unused_imports)]
use dbus::arg;
use dbus::nonblock;

pub trait OrgFreedesktopDBusIntrospectable {
    fn introspect(&self) -> nonblock::MethodReply<String>;
}

impl<'a, T: nonblock::NonblockReply, C: ::std::ops::Deref<Target = T>>
    OrgFreedesktopDBusIntrospectable for nonblock::Proxy<'a, C>
{
    fn introspect(&self) -> nonblock::MethodReply<String> {
        self.method_call(
            "org.freedesktop.DBus.Introspectable",
            "Introspect",
            (),
        )
        .and_then(|r: (String,)| Ok(r.0))
    }
}

pub trait OrgFreedesktopAvahiServiceBrowser {
    fn free(&self) -> nonblock::MethodReply<()>;
}

impl<'a, T: nonblock::NonblockReply, C: ::std::ops::Deref<Target = T>>
    OrgFreedesktopAvahiServiceBrowser for nonblock::Proxy<'a, C>
{
    fn free(&self) -> nonblock::MethodReply<()> {
        self.method_call("org.freedesktop.Avahi.ServiceBrowser", "Free", ())
    }
}

#[derive(Debug)]
pub struct OrgFreedesktopAvahiServiceBrowserItemNew {
    pub interface: i32,
    pub protocol: i32,
    pub name: String,
    pub type_: String,
    pub domain: String,
    pub flags: u32,
}

impl arg::AppendAll for OrgFreedesktopAvahiServiceBrowserItemNew {
    fn append(&self, i: &mut arg::IterAppend) {
        arg::RefArg::append(&self.interface, i);
        arg::RefArg::append(&self.protocol, i);
        arg::RefArg::append(&self.name, i);
        arg::RefArg::append(&self.type_, i);
        arg::RefArg::append(&self.domain, i);
        arg::RefArg::append(&self.flags, i);
    }
}

impl arg::ReadAll for OrgFreedesktopAvahiServiceBrowserItemNew {
    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
        Ok(OrgFreedesktopAvahiServiceBrowserItemNew {
            interface: i.read()?,
            protocol: i.read()?,
            name: i.read()?,
            type_: i.read()?,
            domain: i.read()?,
            flags: i.read()?,
        })
    }
}

impl dbus::message::SignalArgs for OrgFreedesktopAvahiServiceBrowserItemNew {
    const NAME: &'static str = "ItemNew";
    const INTERFACE: &'static str = "org.freedesktop.Avahi.ServiceBrowser";
}

#[derive(Debug)]
pub struct OrgFreedesktopAvahiServiceBrowserItemRemove {
    pub interface: i32,
    pub protocol: i32,
    pub name: String,
    pub type_: String,
    pub domain: String,
    pub flags: u32,
}

impl arg::AppendAll for OrgFreedesktopAvahiServiceBrowserItemRemove {
    fn append(&self, i: &mut arg::IterAppend) {
        arg::RefArg::append(&self.interface, i);
        arg::RefArg::append(&self.protocol, i);
        arg::RefArg::append(&self.name, i);
        arg::RefArg::append(&self.type_, i);
        arg::RefArg::append(&self.domain, i);
        arg::RefArg::append(&self.flags, i);
    }
}

impl arg::ReadAll for OrgFreedesktopAvahiServiceBrowserItemRemove {
    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
        Ok(OrgFreedesktopAvahiServiceBrowserItemRemove {
            interface: i.read()?,
            protocol: i.read()?,
            name: i.read()?,
            type_: i.read()?,
            domain: i.read()?,
            flags: i.read()?,
        })
    }
}

impl dbus::message::SignalArgs
    for OrgFreedesktopAvahiServiceBrowserItemRemove
{
    const NAME: &'static str = "ItemRemove";
    const INTERFACE: &'static str = "org.freedesktop.Avahi.ServiceBrowser";
}

#[derive(Debug)]
pub struct OrgFreedesktopAvahiServiceBrowserFailure {
    pub error: String,
}

impl arg::AppendAll for OrgFreedesktopAvahiServiceBrowserFailure {
    fn append(&self, i: &mut arg::IterAppend) {
        arg::RefArg::append(&self.error, i);
    }
}

impl arg::ReadAll for OrgFreedesktopAvahiServiceBrowserFailure {
    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
        Ok(OrgFreedesktopAvahiServiceBrowserFailure { error: i.read()? })
    }
}

impl dbus::message::SignalArgs for OrgFreedesktopAvahiServiceBrowserFailure {
    const NAME: &'static str = "Failure";
    const INTERFACE: &'static str = "org.freedesktop.Avahi.ServiceBrowser";
}

#[derive(Debug)]
pub struct OrgFreedesktopAvahiServiceBrowserAllForNow {}

impl arg::AppendAll for OrgFreedesktopAvahiServiceBrowserAllForNow {
    fn append(&self, _: &mut arg::IterAppend) {}
}

impl arg::ReadAll for OrgFreedesktopAvahiServiceBrowserAllForNow {
    fn read(_: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
        Ok(OrgFreedesktopAvahiServiceBrowserAllForNow {})
    }
}

impl dbus::message::SignalArgs for OrgFreedesktopAvahiServiceBrowserAllForNow {
    const NAME: &'static str = "AllForNow";
    const INTERFACE: &'static str = "org.freedesktop.Avahi.ServiceBrowser";
}

#[derive(Debug)]
pub struct OrgFreedesktopAvahiServiceBrowserCacheExhausted {}

impl arg::AppendAll for OrgFreedesktopAvahiServiceBrowserCacheExhausted {
    fn append(&self, _: &mut arg::IterAppend) {}
}

impl arg::ReadAll for OrgFreedesktopAvahiServiceBrowserCacheExhausted {
    fn read(_: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
        Ok(OrgFreedesktopAvahiServiceBrowserCacheExhausted {})
    }
}

impl dbus::message::SignalArgs
    for OrgFreedesktopAvahiServiceBrowserCacheExhausted
{
    const NAME: &'static str = "CacheExhausted";
    const INTERFACE: &'static str = "org.freedesktop.Avahi.ServiceBrowser";
}