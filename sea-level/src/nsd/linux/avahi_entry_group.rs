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

pub trait OrgFreedesktopAvahiEntryGroup {
    fn free(&self) -> nonblock::MethodReply<()>;
    fn commit(&self) -> nonblock::MethodReply<()>;
    fn reset(&self) -> nonblock::MethodReply<()>;
    fn get_state(&self) -> nonblock::MethodReply<i32>;
    fn is_empty(&self) -> nonblock::MethodReply<bool>;
    fn add_service(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        type_: &str,
        domain: &str,
        host: &str,
        port: u16,
        txt: Vec<Vec<u8>>,
    ) -> nonblock::MethodReply<()>;
    fn add_service_subtype(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        type_: &str,
        domain: &str,
        subtype: &str,
    ) -> nonblock::MethodReply<()>;
    fn update_service_txt(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        type_: &str,
        domain: &str,
        txt: Vec<Vec<u8>>,
    ) -> nonblock::MethodReply<()>;
    fn add_address(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        address: &str,
    ) -> nonblock::MethodReply<()>;
    fn add_record(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        clazz: u16,
        type_: u16,
        ttl: u32,
        rdata: Vec<u8>,
    ) -> nonblock::MethodReply<()>;
}

impl<'a, T: nonblock::NonblockReply, C: ::std::ops::Deref<Target = T>>
    OrgFreedesktopAvahiEntryGroup for nonblock::Proxy<'a, C>
{
    fn free(&self) -> nonblock::MethodReply<()> {
        self.method_call("org.freedesktop.Avahi.EntryGroup", "Free", ())
    }

    fn commit(&self) -> nonblock::MethodReply<()> {
        self.method_call("org.freedesktop.Avahi.EntryGroup", "Commit", ())
    }

    fn reset(&self) -> nonblock::MethodReply<()> {
        self.method_call("org.freedesktop.Avahi.EntryGroup", "Reset", ())
    }

    fn get_state(&self) -> nonblock::MethodReply<i32> {
        self.method_call("org.freedesktop.Avahi.EntryGroup", "GetState", ())
            .and_then(|r: (i32,)| Ok(r.0))
    }

    fn is_empty(&self) -> nonblock::MethodReply<bool> {
        self.method_call("org.freedesktop.Avahi.EntryGroup", "IsEmpty", ())
            .and_then(|r: (bool,)| Ok(r.0))
    }

    fn add_service(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        type_: &str,
        domain: &str,
        host: &str,
        port: u16,
        txt: Vec<Vec<u8>>,
    ) -> nonblock::MethodReply<()> {
        self.method_call(
            "org.freedesktop.Avahi.EntryGroup",
            "AddService",
            (
                interface, protocol, flags, name, type_, domain, host, port,
                txt,
            ),
        )
    }

    fn add_service_subtype(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        type_: &str,
        domain: &str,
        subtype: &str,
    ) -> nonblock::MethodReply<()> {
        self.method_call(
            "org.freedesktop.Avahi.EntryGroup",
            "AddServiceSubtype",
            (interface, protocol, flags, name, type_, domain, subtype),
        )
    }

    fn update_service_txt(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        type_: &str,
        domain: &str,
        txt: Vec<Vec<u8>>,
    ) -> nonblock::MethodReply<()> {
        self.method_call(
            "org.freedesktop.Avahi.EntryGroup",
            "UpdateServiceTxt",
            (interface, protocol, flags, name, type_, domain, txt),
        )
    }

    fn add_address(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        address: &str,
    ) -> nonblock::MethodReply<()> {
        self.method_call(
            "org.freedesktop.Avahi.EntryGroup",
            "AddAddress",
            (interface, protocol, flags, name, address),
        )
    }

    fn add_record(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        clazz: u16,
        type_: u16,
        ttl: u32,
        rdata: Vec<u8>,
    ) -> nonblock::MethodReply<()> {
        self.method_call(
            "org.freedesktop.Avahi.EntryGroup",
            "AddRecord",
            (interface, protocol, flags, name, clazz, type_, ttl, rdata),
        )
    }
}

#[derive(Debug)]
pub struct OrgFreedesktopAvahiEntryGroupStateChanged {
    pub state: i32,
    pub error: String,
}

impl arg::AppendAll for OrgFreedesktopAvahiEntryGroupStateChanged {
    fn append(&self, i: &mut arg::IterAppend) {
        arg::RefArg::append(&self.state, i);
        arg::RefArg::append(&self.error, i);
    }
}

impl arg::ReadAll for OrgFreedesktopAvahiEntryGroupStateChanged {
    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
        Ok(OrgFreedesktopAvahiEntryGroupStateChanged {
            state: i.read()?,
            error: i.read()?,
        })
    }
}

impl dbus::message::SignalArgs for OrgFreedesktopAvahiEntryGroupStateChanged {
    const NAME: &'static str = "StateChanged";
    const INTERFACE: &'static str = "org.freedesktop.Avahi.EntryGroup";
}
