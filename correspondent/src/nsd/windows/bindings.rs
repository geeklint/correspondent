#[allow(
    unused_variables,
    non_upper_case_globals,
    non_snake_case,
    unused_unsafe,
    non_camel_case_types,
    dead_code,
    clippy::all
)]
pub mod Windows {
    #[allow(
        unused_variables,
        non_upper_case_globals,
        non_snake_case,
        unused_unsafe,
        non_camel_case_types,
        dead_code,
        clippy::all
    )]
    pub mod Win32 {
        #[allow(
            unused_variables,
            non_upper_case_globals,
            non_snake_case,
            unused_unsafe,
            non_camel_case_types,
            dead_code,
            clippy::all
        )]
        pub mod Foundation {
            #[repr(transparent)]
            #[derive(
                :: std :: default :: Default,
                :: std :: clone :: Clone,
                :: std :: marker :: Copy,
                :: std :: cmp :: PartialEq,
                :: std :: cmp :: Eq,
                :: std :: fmt :: Debug,
            )]
            pub struct BOOL(pub i32);
            unsafe impl ::windows::Abi for BOOL {
                type Abi = Self;
            }
            impl BOOL {
                #[inline]
                pub fn as_bool(self) -> bool {
                    !(self.0 == 0)
                }
                #[inline]
                pub fn ok(self) -> ::windows::Result<()> {
                    if self.as_bool() {
                        Ok(())
                    } else {
                        Err(::windows::HRESULT::from_thread().into())
                    }
                }
                #[inline]
                #[track_caller]
                pub fn unwrap(self) {
                    self.ok().unwrap();
                }
                #[inline]
                #[track_caller]
                pub fn expect(self, msg: &str) {
                    self.ok().expect(msg);
                }
            }
            impl ::std::convert::From<BOOL> for bool {
                fn from(value: BOOL) -> Self {
                    value.as_bool()
                }
            }
            impl ::std::convert::From<&BOOL> for bool {
                fn from(value: &BOOL) -> Self {
                    value.as_bool()
                }
            }
            impl ::std::convert::From<bool> for BOOL {
                fn from(value: bool) -> Self {
                    if value {
                        BOOL(1)
                    } else {
                        BOOL(0)
                    }
                }
            }
            impl ::std::convert::From<&bool> for BOOL {
                fn from(value: &bool) -> Self {
                    (*value).into()
                }
            }
            impl ::std::cmp::PartialEq<bool> for BOOL {
                fn eq(&self, other: &bool) -> bool {
                    self.as_bool() == *other
                }
            }
            impl ::std::cmp::PartialEq<BOOL> for bool {
                fn eq(&self, other: &BOOL) -> bool {
                    *self == other.as_bool()
                }
            }
            impl std::ops::Not for BOOL {
                type Output = Self;
                fn not(self) -> Self::Output {
                    if self.as_bool() {
                        BOOL(0)
                    } else {
                        BOOL(1)
                    }
                }
            }
            impl<'a> ::windows::IntoParam<'a, BOOL> for bool {
                fn into_param(self) -> ::windows::Param<'a, BOOL> {
                    ::windows::Param::Owned(self.into())
                }
            }
            #[repr(transparent)]
            #[derive(:: std :: clone :: Clone, :: std :: marker :: Copy)]
            pub struct HANDLE(pub isize);
            impl HANDLE {}
            impl ::std::default::Default for HANDLE {
                fn default() -> Self {
                    Self(0)
                }
            }
            impl HANDLE {
                pub const NULL: Self = Self(0);
                pub fn is_null(&self) -> bool {
                    self.0 == 0
                }
            }
            impl ::std::fmt::Debug for HANDLE {
                fn fmt(
                    &self,
                    fmt: &mut ::std::fmt::Formatter<'_>,
                ) -> ::std::fmt::Result {
                    fmt.debug_struct("HANDLE").field("Value", &self.0).finish()
                }
            }
            impl ::std::cmp::PartialEq for HANDLE {
                fn eq(&self, other: &Self) -> bool {
                    self.0 == other.0
                }
            }
            impl ::std::cmp::Eq for HANDLE {}
            unsafe impl ::windows::Abi for HANDLE {
                type Abi = Self;
            }
            impl HANDLE {
                pub const INVALID: Self = Self(-1);
                pub fn is_invalid(&self) -> bool {
                    self.0 == -1
                }
            }
            #[repr(transparent)]
            #[derive(
                :: std :: clone :: Clone,
                :: std :: marker :: Copy,
                :: std :: cmp :: Eq,
                :: std :: fmt :: Debug,
            )]
            pub struct PSTR(pub *mut u8);
            impl PSTR {
                pub const NULL: Self = Self(::std::ptr::null_mut());
                pub fn is_null(&self) -> bool {
                    self.0.is_null()
                }
            }
            impl ::std::default::Default for PSTR {
                fn default() -> Self {
                    Self(::std::ptr::null_mut())
                }
            }
            impl ::std::cmp::PartialEq for PSTR {
                fn eq(&self, other: &Self) -> bool {
                    self.0 == other.0
                }
            }
            unsafe impl ::windows::Abi for PSTR {
                type Abi = Self;
                fn drop_param(param: &mut ::windows::Param<'_, Self>) {
                    if let ::windows::Param::Boxed(value) = param {
                        if !value.0.is_null() {
                            unsafe {
                                ::std::boxed::Box::from_raw(value.0);
                            }
                        }
                    }
                }
            }
            impl<'a> ::windows::IntoParam<'a, PSTR> for &'a str {
                fn into_param(self) -> ::windows::Param<'a, PSTR> {
                    ::windows::Param::Boxed(PSTR(
                        ::std::boxed::Box::<[u8]>::into_raw(
                            self.bytes()
                                .chain(::std::iter::once(0))
                                .collect::<std::vec::Vec<u8>>()
                                .into_boxed_slice(),
                        ) as _,
                    ))
                }
            }
            impl<'a> ::windows::IntoParam<'a, PSTR> for String {
                fn into_param(self) -> ::windows::Param<'a, PSTR> {
                    ::windows::Param::Boxed(PSTR(
                        ::std::boxed::Box::<[u8]>::into_raw(
                            self.bytes()
                                .chain(::std::iter::once(0))
                                .collect::<std::vec::Vec<u8>>()
                                .into_boxed_slice(),
                        ) as _,
                    ))
                }
            }
            #[repr(transparent)]
            #[derive(
                :: std :: clone :: Clone,
                :: std :: marker :: Copy,
                :: std :: cmp :: Eq,
                :: std :: fmt :: Debug,
            )]
            pub struct PWSTR(pub *mut u16);
            impl PWSTR {
                pub const NULL: Self = Self(::std::ptr::null_mut());
                pub fn is_null(&self) -> bool {
                    self.0.is_null()
                }
            }
            impl ::std::default::Default for PWSTR {
                fn default() -> Self {
                    Self(::std::ptr::null_mut())
                }
            }
            impl ::std::cmp::PartialEq for PWSTR {
                fn eq(&self, other: &Self) -> bool {
                    self.0 == other.0
                }
            }
            unsafe impl ::windows::Abi for PWSTR {
                type Abi = Self;
                fn drop_param(param: &mut ::windows::Param<'_, Self>) {
                    if let ::windows::Param::Boxed(value) = param {
                        if !value.0.is_null() {
                            unsafe {
                                ::std::boxed::Box::from_raw(value.0);
                            }
                        }
                    }
                }
            }
            impl<'a> ::windows::IntoParam<'a, PWSTR> for &'a str {
                fn into_param(self) -> ::windows::Param<'a, PWSTR> {
                    ::windows::Param::Boxed(PWSTR(
                        ::std::boxed::Box::<[u16]>::into_raw(
                            self.encode_utf16()
                                .chain(::std::iter::once(0))
                                .collect::<std::vec::Vec<u16>>()
                                .into_boxed_slice(),
                        ) as _,
                    ))
                }
            }
            impl<'a> ::windows::IntoParam<'a, PWSTR> for String {
                fn into_param(self) -> ::windows::Param<'a, PWSTR> {
                    ::windows::Param::Boxed(PWSTR(
                        ::std::boxed::Box::<[u16]>::into_raw(
                            self.encode_utf16()
                                .chain(::std::iter::once(0))
                                .collect::<std::vec::Vec<u16>>()
                                .into_boxed_slice(),
                        ) as _,
                    ))
                }
            }
        }
        #[allow(
            unused_variables,
            non_upper_case_globals,
            non_snake_case,
            unused_unsafe,
            non_camel_case_types,
            dead_code,
            clippy::all
        )]
        pub mod NetworkManagement {
            #[allow(
                unused_variables,
                non_upper_case_globals,
                non_snake_case,
                unused_unsafe,
                non_camel_case_types,
                dead_code,
                clippy::all
            )]
            pub mod Dns {
                pub const DNSREC_ADDITIONAL: u32 = 3u32;
                pub const DNSREC_ANSWER: u32 = 1u32;
                pub const DNSREC_AUTHORITY: u32 = 2u32;
                pub const DNSREC_DELETE: u32 = 4u32;
                pub const DNSREC_NOEXIST: u32 = 4u32;
                pub const DNSREC_PREREQ: u32 = 1u32;
                pub const DNSREC_QUESTION: u32 = 0u32;
                pub const DNSREC_SECTION: u32 = 3u32;
                pub const DNSREC_UPDATE: u32 = 2u32;
                pub const DNSREC_ZONE: u32 = 0u32;
                pub const DNSSEC_ALGORITHM_ECDSAP256_SHA256: u32 = 13u32;
                pub const DNSSEC_ALGORITHM_ECDSAP384_SHA384: u32 = 14u32;
                pub const DNSSEC_ALGORITHM_NULL: u32 = 253u32;
                pub const DNSSEC_ALGORITHM_PRIVATE: u32 = 254u32;
                pub const DNSSEC_ALGORITHM_RSAMD5: u32 = 1u32;
                pub const DNSSEC_ALGORITHM_RSASHA1: u32 = 5u32;
                pub const DNSSEC_ALGORITHM_RSASHA1_NSEC3: u32 = 7u32;
                pub const DNSSEC_ALGORITHM_RSASHA256: u32 = 8u32;
                pub const DNSSEC_ALGORITHM_RSASHA512: u32 = 10u32;
                pub const DNSSEC_DIGEST_ALGORITHM_SHA1: u32 = 1u32;
                pub const DNSSEC_DIGEST_ALGORITHM_SHA256: u32 = 2u32;
                pub const DNSSEC_DIGEST_ALGORITHM_SHA384: u32 = 4u32;
                pub const DNSSEC_KEY_FLAG_EXTEND: u32 = 8u32;
                pub const DNSSEC_KEY_FLAG_FLAG10: u32 = 1024u32;
                pub const DNSSEC_KEY_FLAG_FLAG11: u32 = 2048u32;
                pub const DNSSEC_KEY_FLAG_FLAG2: u32 = 4u32;
                pub const DNSSEC_KEY_FLAG_FLAG4: u32 = 16u32;
                pub const DNSSEC_KEY_FLAG_FLAG5: u32 = 32u32;
                pub const DNSSEC_KEY_FLAG_FLAG8: u32 = 256u32;
                pub const DNSSEC_KEY_FLAG_FLAG9: u32 = 512u32;
                pub const DNSSEC_KEY_FLAG_HOST: u32 = 128u32;
                pub const DNSSEC_KEY_FLAG_NOAUTH: u32 = 1u32;
                pub const DNSSEC_KEY_FLAG_NOCONF: u32 = 2u32;
                pub const DNSSEC_KEY_FLAG_NTPE3: u32 = 192u32;
                pub const DNSSEC_KEY_FLAG_SIG0: u32 = 0u32;
                pub const DNSSEC_KEY_FLAG_SIG1: u32 = 4096u32;
                pub const DNSSEC_KEY_FLAG_SIG10: u32 = 40960u32;
                pub const DNSSEC_KEY_FLAG_SIG11: u32 = 45056u32;
                pub const DNSSEC_KEY_FLAG_SIG12: u32 = 49152u32;
                pub const DNSSEC_KEY_FLAG_SIG13: u32 = 53248u32;
                pub const DNSSEC_KEY_FLAG_SIG14: u32 = 57344u32;
                pub const DNSSEC_KEY_FLAG_SIG15: u32 = 61440u32;
                pub const DNSSEC_KEY_FLAG_SIG2: u32 = 8192u32;
                pub const DNSSEC_KEY_FLAG_SIG3: u32 = 12288u32;
                pub const DNSSEC_KEY_FLAG_SIG4: u32 = 16384u32;
                pub const DNSSEC_KEY_FLAG_SIG5: u32 = 20480u32;
                pub const DNSSEC_KEY_FLAG_SIG6: u32 = 24576u32;
                pub const DNSSEC_KEY_FLAG_SIG7: u32 = 28672u32;
                pub const DNSSEC_KEY_FLAG_SIG8: u32 = 32768u32;
                pub const DNSSEC_KEY_FLAG_SIG9: u32 = 36864u32;
                pub const DNSSEC_KEY_FLAG_USER: u32 = 0u32;
                pub const DNSSEC_KEY_FLAG_ZONE: u32 = 64u32;
                pub const DNSSEC_PROTOCOL_DNSSEC: u32 = 3u32;
                pub const DNSSEC_PROTOCOL_EMAIL: u32 = 2u32;
                pub const DNSSEC_PROTOCOL_IPSEC: u32 = 4u32;
                pub const DNSSEC_PROTOCOL_NONE: u32 = 0u32;
                pub const DNSSEC_PROTOCOL_TLS: u32 = 1u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_AAAA_DATA {
                    pub Ip6Address: IP6_ADDRESS,
                }
                impl DNS_AAAA_DATA {}
                unsafe impl ::windows::Abi for DNS_AAAA_DATA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_ADDR {
                    pub MaxSa:
                        [super::super::System::SystemServices::CHAR; 32],
                    pub Data: DNS_ADDR_0,
                }
                impl DNS_ADDR {}
                unsafe impl ::windows::Abi for DNS_ADDR {
                    type Abi = Self;
                }
                #[repr(C, packed(1))]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub union DNS_ADDR_0 {
                    pub DnsAddrUserDword: [u32; 8],
                }
                impl DNS_ADDR_0 {}
                unsafe impl ::windows::Abi for DNS_ADDR_0 {
                    type Abi = Self;
                }
                #[repr(C, packed(1))]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_ADDR_ARRAY {
                    pub MaxCount: u32,
                    pub AddrCount: u32,
                    pub Tag: u32,
                    pub Family: u16,
                    pub WordReserved: u16,
                    pub Flags: u32,
                    pub MatchFlag: u32,
                    pub Reserved1: u32,
                    pub Reserved2: u32,
                    pub AddrArray: [DNS_ADDR; 1],
                }
                impl DNS_ADDR_ARRAY {}
                unsafe impl ::windows::Abi for DNS_ADDR_ARRAY {
                    type Abi = Self;
                }
                pub const DNS_ADDR_MAX_SOCKADDR_LENGTH: u32 = 32u32;
                pub const DNS_ATMA_AESA_ADDR_LENGTH: u32 = 20u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_ATMA_DATA {
                    pub AddressType: u8,
                    pub Address: [u8; 20],
                }
                impl DNS_ATMA_DATA {}
                impl ::std::default::Default for DNS_ATMA_DATA {
                    fn default() -> Self {
                        Self {
                            AddressType: 0,
                            Address: [0; 20],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_ATMA_DATA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_ATMA_DATA")
                            .field("AddressType", &self.AddressType)
                            .field("Address", &self.Address)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_ATMA_DATA {
                    fn eq(&self, other: &Self) -> bool {
                        self.AddressType == other.AddressType
                            && self.Address == other.Address
                    }
                }
                impl ::std::cmp::Eq for DNS_ATMA_DATA {}
                unsafe impl ::windows::Abi for DNS_ATMA_DATA {
                    type Abi = Self;
                }
                pub const DNS_ATMA_FORMAT_AESA: u32 = 2u32;
                pub const DNS_ATMA_FORMAT_E164: u32 = 1u32;
                pub const DNS_ATMA_MAX_ADDR_LENGTH: u32 = 20u32;
                pub const DNS_ATMA_MAX_RECORD_LENGTH: u32 = 21u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_A_DATA {
                    pub IpAddress: u32,
                }
                impl DNS_A_DATA {}
                impl ::std::default::Default for DNS_A_DATA {
                    fn default() -> Self {
                        Self { IpAddress: 0 }
                    }
                }
                impl ::std::fmt::Debug for DNS_A_DATA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_A_DATA")
                            .field("IpAddress", &self.IpAddress)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_A_DATA {
                    fn eq(&self, other: &Self) -> bool {
                        self.IpAddress == other.IpAddress
                    }
                }
                impl ::std::cmp::Eq for DNS_A_DATA {}
                unsafe impl ::windows::Abi for DNS_A_DATA {
                    type Abi = Self;
                }
                #[derive(
                    :: std :: cmp :: PartialEq,
                    :: std :: cmp :: Eq,
                    :: std :: marker :: Copy,
                    :: std :: clone :: Clone,
                    :: std :: default :: Default,
                    :: std :: fmt :: Debug,
                )]
                #[repr(transparent)]
                pub struct DNS_CHARSET(pub i32);
                pub const DnsCharSetUnknown: DNS_CHARSET = DNS_CHARSET(0i32);
                pub const DnsCharSetUnicode: DNS_CHARSET = DNS_CHARSET(1i32);
                pub const DnsCharSetUtf8: DNS_CHARSET = DNS_CHARSET(2i32);
                pub const DnsCharSetAnsi: DNS_CHARSET = DNS_CHARSET(3i32);
                impl ::std::convert::From<i32> for DNS_CHARSET {
                    fn from(value: i32) -> Self {
                        Self(value)
                    }
                }
                unsafe impl ::windows::Abi for DNS_CHARSET {
                    type Abi = Self;
                }
                pub const DNS_CLASS_ALL: u32 = 255u32;
                pub const DNS_CLASS_ANY: u32 = 255u32;
                pub const DNS_CLASS_CHAOS: u32 = 3u32;
                pub const DNS_CLASS_CSNET: u32 = 2u32;
                pub const DNS_CLASS_HESIOD: u32 = 4u32;
                pub const DNS_CLASS_INTERNET: u32 = 1u32;
                pub const DNS_CLASS_NONE: u32 = 254u32;
                pub const DNS_CLASS_UNICAST_RESPONSE: u32 = 32768u32;
                pub const DNS_COMPRESSED_QUESTION_NAME: u32 = 49164u32;
                pub const DNS_CONFIG_FLAG_ALLOC: u32 = 1u32;
                #[derive(
                    :: std :: cmp :: PartialEq,
                    :: std :: cmp :: Eq,
                    :: std :: marker :: Copy,
                    :: std :: clone :: Clone,
                    :: std :: default :: Default,
                    :: std :: fmt :: Debug,
                )]
                #[repr(transparent)]
                pub struct DNS_CONFIG_TYPE(pub i32);
                pub const DnsConfigPrimaryDomainName_W: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(0i32);
                pub const DnsConfigPrimaryDomainName_A: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(1i32);
                pub const DnsConfigPrimaryDomainName_UTF8: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(2i32);
                pub const DnsConfigAdapterDomainName_W: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(3i32);
                pub const DnsConfigAdapterDomainName_A: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(4i32);
                pub const DnsConfigAdapterDomainName_UTF8: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(5i32);
                pub const DnsConfigDnsServerList: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(6i32);
                pub const DnsConfigSearchList: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(7i32);
                pub const DnsConfigAdapterInfo: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(8i32);
                pub const DnsConfigPrimaryHostNameRegistrationEnabled:
                    DNS_CONFIG_TYPE = DNS_CONFIG_TYPE(9i32);
                pub const DnsConfigAdapterHostNameRegistrationEnabled:
                    DNS_CONFIG_TYPE = DNS_CONFIG_TYPE(10i32);
                pub const DnsConfigAddressRegistrationMaxCount:
                    DNS_CONFIG_TYPE = DNS_CONFIG_TYPE(11i32);
                pub const DnsConfigHostName_W: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(12i32);
                pub const DnsConfigHostName_A: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(13i32);
                pub const DnsConfigHostName_UTF8: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(14i32);
                pub const DnsConfigFullHostName_W: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(15i32);
                pub const DnsConfigFullHostName_A: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(16i32);
                pub const DnsConfigFullHostName_UTF8: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(17i32);
                pub const DnsConfigNameServer: DNS_CONFIG_TYPE =
                    DNS_CONFIG_TYPE(18i32);
                impl ::std::convert::From<i32> for DNS_CONFIG_TYPE {
                    fn from(value: i32) -> Self {
                        Self(value)
                    }
                }
                unsafe impl ::windows::Abi for DNS_CONFIG_TYPE {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_CONNECTION_IFINDEX_ENTRY {
                    pub pwszConnectionName: super::super::Foundation::PWSTR,
                    pub dwIfIndex: u32,
                }
                impl DNS_CONNECTION_IFINDEX_ENTRY {}
                impl ::std::default::Default for DNS_CONNECTION_IFINDEX_ENTRY {
                    fn default() -> Self {
                        Self {
                            pwszConnectionName:
                                ::std::default::Default::default(),
                            dwIfIndex: 0,
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_CONNECTION_IFINDEX_ENTRY {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_CONNECTION_IFINDEX_ENTRY")
                            .field(
                                "pwszConnectionName",
                                &self.pwszConnectionName,
                            )
                            .field("dwIfIndex", &self.dwIfIndex)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_CONNECTION_IFINDEX_ENTRY {
                    fn eq(&self, other: &Self) -> bool {
                        self.pwszConnectionName == other.pwszConnectionName
                            && self.dwIfIndex == other.dwIfIndex
                    }
                }
                impl ::std::cmp::Eq for DNS_CONNECTION_IFINDEX_ENTRY {}
                unsafe impl ::windows::Abi for DNS_CONNECTION_IFINDEX_ENTRY {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_CONNECTION_IFINDEX_LIST {
                    pub pConnectionIfIndexEntries:
                        *mut DNS_CONNECTION_IFINDEX_ENTRY,
                    pub nEntries: u32,
                }
                impl DNS_CONNECTION_IFINDEX_LIST {}
                impl ::std::default::Default for DNS_CONNECTION_IFINDEX_LIST {
                    fn default() -> Self {
                        Self {
                            pConnectionIfIndexEntries: ::std::ptr::null_mut(),
                            nEntries: 0,
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_CONNECTION_IFINDEX_LIST {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_CONNECTION_IFINDEX_LIST")
                            .field(
                                "pConnectionIfIndexEntries",
                                &self.pConnectionIfIndexEntries,
                            )
                            .field("nEntries", &self.nEntries)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_CONNECTION_IFINDEX_LIST {
                    fn eq(&self, other: &Self) -> bool {
                        self.pConnectionIfIndexEntries
                            == other.pConnectionIfIndexEntries
                            && self.nEntries == other.nEntries
                    }
                }
                impl ::std::cmp::Eq for DNS_CONNECTION_IFINDEX_LIST {}
                unsafe impl ::windows::Abi for DNS_CONNECTION_IFINDEX_LIST {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_CONNECTION_NAME {
                    pub wszName: [u16; 65],
                }
                impl DNS_CONNECTION_NAME {}
                impl ::std::default::Default for DNS_CONNECTION_NAME {
                    fn default() -> Self {
                        Self { wszName: [0; 65] }
                    }
                }
                impl ::std::fmt::Debug for DNS_CONNECTION_NAME {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_CONNECTION_NAME")
                            .field("wszName", &self.wszName)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_CONNECTION_NAME {
                    fn eq(&self, other: &Self) -> bool {
                        self.wszName == other.wszName
                    }
                }
                impl ::std::cmp::Eq for DNS_CONNECTION_NAME {}
                unsafe impl ::windows::Abi for DNS_CONNECTION_NAME {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_CONNECTION_NAME_LIST {
                    pub cNames: u32,
                    pub pNames: *mut DNS_CONNECTION_NAME,
                }
                impl DNS_CONNECTION_NAME_LIST {}
                impl ::std::default::Default for DNS_CONNECTION_NAME_LIST {
                    fn default() -> Self {
                        Self {
                            cNames: 0,
                            pNames: ::std::ptr::null_mut(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_CONNECTION_NAME_LIST {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_CONNECTION_NAME_LIST")
                            .field("cNames", &self.cNames)
                            .field("pNames", &self.pNames)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_CONNECTION_NAME_LIST {
                    fn eq(&self, other: &Self) -> bool {
                        self.cNames == other.cNames
                            && self.pNames == other.pNames
                    }
                }
                impl ::std::cmp::Eq for DNS_CONNECTION_NAME_LIST {}
                unsafe impl ::windows::Abi for DNS_CONNECTION_NAME_LIST {
                    type Abi = Self;
                }
                pub const DNS_CONNECTION_NAME_MAX_LENGTH: u32 = 64u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_CONNECTION_POLICY_ENTRY {
                    pub pwszHost: super::super::Foundation::PWSTR,
                    pub pwszAppId: super::super::Foundation::PWSTR,
                    pub cbAppSid: u32,
                    pub pbAppSid: *mut u8,
                    pub nConnections: u32,
                    pub ppwszConnections: *mut super::super::Foundation::PWSTR,
                    pub dwPolicyEntryFlags: u32,
                }
                impl DNS_CONNECTION_POLICY_ENTRY {}
                impl ::std::default::Default for DNS_CONNECTION_POLICY_ENTRY {
                    fn default() -> Self {
                        Self {
                            pwszHost: ::std::default::Default::default(),
                            pwszAppId: ::std::default::Default::default(),
                            cbAppSid: 0,
                            pbAppSid: ::std::ptr::null_mut(),
                            nConnections: 0,
                            ppwszConnections: ::std::ptr::null_mut(),
                            dwPolicyEntryFlags: 0,
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_CONNECTION_POLICY_ENTRY {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_CONNECTION_POLICY_ENTRY")
                            .field("pwszHost", &self.pwszHost)
                            .field("pwszAppId", &self.pwszAppId)
                            .field("cbAppSid", &self.cbAppSid)
                            .field("pbAppSid", &self.pbAppSid)
                            .field("nConnections", &self.nConnections)
                            .field("ppwszConnections", &self.ppwszConnections)
                            .field(
                                "dwPolicyEntryFlags",
                                &self.dwPolicyEntryFlags,
                            )
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_CONNECTION_POLICY_ENTRY {
                    fn eq(&self, other: &Self) -> bool {
                        self.pwszHost == other.pwszHost
                            && self.pwszAppId == other.pwszAppId
                            && self.cbAppSid == other.cbAppSid
                            && self.pbAppSid == other.pbAppSid
                            && self.nConnections == other.nConnections
                            && self.ppwszConnections == other.ppwszConnections
                            && self.dwPolicyEntryFlags
                                == other.dwPolicyEntryFlags
                    }
                }
                impl ::std::cmp::Eq for DNS_CONNECTION_POLICY_ENTRY {}
                unsafe impl ::windows::Abi for DNS_CONNECTION_POLICY_ENTRY {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_CONNECTION_POLICY_ENTRY_LIST {
                    pub pPolicyEntries: *mut DNS_CONNECTION_POLICY_ENTRY,
                    pub nEntries: u32,
                }
                impl DNS_CONNECTION_POLICY_ENTRY_LIST {}
                impl ::std::default::Default for DNS_CONNECTION_POLICY_ENTRY_LIST {
                    fn default() -> Self {
                        Self {
                            pPolicyEntries: ::std::ptr::null_mut(),
                            nEntries: 0,
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_CONNECTION_POLICY_ENTRY_LIST {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_CONNECTION_POLICY_ENTRY_LIST")
                            .field("pPolicyEntries", &self.pPolicyEntries)
                            .field("nEntries", &self.nEntries)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_CONNECTION_POLICY_ENTRY_LIST {
                    fn eq(&self, other: &Self) -> bool {
                        self.pPolicyEntries == other.pPolicyEntries
                            && self.nEntries == other.nEntries
                    }
                }
                impl ::std::cmp::Eq for DNS_CONNECTION_POLICY_ENTRY_LIST {}
                unsafe impl ::windows::Abi for DNS_CONNECTION_POLICY_ENTRY_LIST {
                    type Abi = Self;
                }
                pub const DNS_CONNECTION_POLICY_ENTRY_ONDEMAND: u32 = 1u32;
                #[derive(
                    :: std :: cmp :: PartialEq,
                    :: std :: cmp :: Eq,
                    :: std :: marker :: Copy,
                    :: std :: clone :: Clone,
                    :: std :: default :: Default,
                    :: std :: fmt :: Debug,
                )]
                #[repr(transparent)]
                pub struct DNS_CONNECTION_POLICY_TAG(pub i32);
                pub const TAG_DNS_CONNECTION_POLICY_TAG_DEFAULT:
                    DNS_CONNECTION_POLICY_TAG =
                    DNS_CONNECTION_POLICY_TAG(0i32);
                pub const TAG_DNS_CONNECTION_POLICY_TAG_CONNECTION_MANAGER:
                    DNS_CONNECTION_POLICY_TAG =
                    DNS_CONNECTION_POLICY_TAG(1i32);
                pub const TAG_DNS_CONNECTION_POLICY_TAG_WWWPT:
                    DNS_CONNECTION_POLICY_TAG =
                    DNS_CONNECTION_POLICY_TAG(2i32);
                impl ::std::convert::From<i32> for DNS_CONNECTION_POLICY_TAG {
                    fn from(value: i32) -> Self {
                        Self(value)
                    }
                }
                unsafe impl ::windows::Abi for DNS_CONNECTION_POLICY_TAG {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_CONNECTION_PROXY_ELEMENT {
                    pub Type: DNS_CONNECTION_PROXY_TYPE,
                    pub Info: DNS_CONNECTION_PROXY_INFO,
                }
                impl DNS_CONNECTION_PROXY_ELEMENT {}
                unsafe impl ::windows::Abi for DNS_CONNECTION_PROXY_ELEMENT {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_CONNECTION_PROXY_INFO {
                    pub Version: u32,
                    pub pwszFriendlyName: super::super::Foundation::PWSTR,
                    pub Flags: u32,
                    pub Switch: DNS_CONNECTION_PROXY_INFO_SWITCH,
                    pub Anonymous: DNS_CONNECTION_PROXY_INFO_0,
                }
                impl DNS_CONNECTION_PROXY_INFO {}
                unsafe impl ::windows::Abi for DNS_CONNECTION_PROXY_INFO {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub union DNS_CONNECTION_PROXY_INFO_0 {
                    pub Config: DNS_CONNECTION_PROXY_INFO_0_0,
                    pub Script: DNS_CONNECTION_PROXY_INFO_0_1,
                }
                impl DNS_CONNECTION_PROXY_INFO_0 {}
                unsafe impl ::windows::Abi for DNS_CONNECTION_PROXY_INFO_0 {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_CONNECTION_PROXY_INFO_0_0 {
                    pub pwszServer: super::super::Foundation::PWSTR,
                    pub pwszUsername: super::super::Foundation::PWSTR,
                    pub pwszPassword: super::super::Foundation::PWSTR,
                    pub pwszException: super::super::Foundation::PWSTR,
                    pub pwszExtraInfo: super::super::Foundation::PWSTR,
                    pub Port: u16,
                }
                impl DNS_CONNECTION_PROXY_INFO_0_0 {}
                impl ::std::default::Default for DNS_CONNECTION_PROXY_INFO_0_0 {
                    fn default() -> Self {
                        Self {
                            pwszServer: ::std::default::Default::default(),
                            pwszUsername: ::std::default::Default::default(),
                            pwszPassword: ::std::default::Default::default(),
                            pwszException: ::std::default::Default::default(),
                            pwszExtraInfo: ::std::default::Default::default(),
                            Port: 0,
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_CONNECTION_PROXY_INFO_0_0 {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("_DNS_CONNECTION_PROXY_INFO_CONFIG")
                            .field("pwszServer", &self.pwszServer)
                            .field("pwszUsername", &self.pwszUsername)
                            .field("pwszPassword", &self.pwszPassword)
                            .field("pwszException", &self.pwszException)
                            .field("pwszExtraInfo", &self.pwszExtraInfo)
                            .field("Port", &self.Port)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_CONNECTION_PROXY_INFO_0_0 {
                    fn eq(&self, other: &Self) -> bool {
                        self.pwszServer == other.pwszServer
                            && self.pwszUsername == other.pwszUsername
                            && self.pwszPassword == other.pwszPassword
                            && self.pwszException == other.pwszException
                            && self.pwszExtraInfo == other.pwszExtraInfo
                            && self.Port == other.Port
                    }
                }
                impl ::std::cmp::Eq for DNS_CONNECTION_PROXY_INFO_0_0 {}
                unsafe impl ::windows::Abi for DNS_CONNECTION_PROXY_INFO_0_0 {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_CONNECTION_PROXY_INFO_0_1 {
                    pub pwszScript: super::super::Foundation::PWSTR,
                    pub pwszUsername: super::super::Foundation::PWSTR,
                    pub pwszPassword: super::super::Foundation::PWSTR,
                }
                impl DNS_CONNECTION_PROXY_INFO_0_1 {}
                impl ::std::default::Default for DNS_CONNECTION_PROXY_INFO_0_1 {
                    fn default() -> Self {
                        Self {
                            pwszScript: ::std::default::Default::default(),
                            pwszUsername: ::std::default::Default::default(),
                            pwszPassword: ::std::default::Default::default(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_CONNECTION_PROXY_INFO_0_1 {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("_DNS_CONNECTION_PROXY_INFO_SCRIPT")
                            .field("pwszScript", &self.pwszScript)
                            .field("pwszUsername", &self.pwszUsername)
                            .field("pwszPassword", &self.pwszPassword)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_CONNECTION_PROXY_INFO_0_1 {
                    fn eq(&self, other: &Self) -> bool {
                        self.pwszScript == other.pwszScript
                            && self.pwszUsername == other.pwszUsername
                            && self.pwszPassword == other.pwszPassword
                    }
                }
                impl ::std::cmp::Eq for DNS_CONNECTION_PROXY_INFO_0_1 {}
                unsafe impl ::windows::Abi for DNS_CONNECTION_PROXY_INFO_0_1 {
                    type Abi = Self;
                }
                pub const DNS_CONNECTION_PROXY_INFO_CURRENT_VERSION: u32 =
                    1u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_CONNECTION_PROXY_INFO_EX {
                    pub ProxyInfo: DNS_CONNECTION_PROXY_INFO,
                    pub dwInterfaceIndex: u32,
                    pub pwszConnectionName: super::super::Foundation::PWSTR,
                    pub fDirectConfiguration: super::super::Foundation::BOOL,
                    pub hConnection: super::super::Foundation::HANDLE,
                }
                impl DNS_CONNECTION_PROXY_INFO_EX {}
                unsafe impl ::windows::Abi for DNS_CONNECTION_PROXY_INFO_EX {
                    type Abi = Self;
                }
                pub const DNS_CONNECTION_PROXY_INFO_EXCEPTION_MAX_LENGTH: u32 =
                    1024u32;
                pub const DNS_CONNECTION_PROXY_INFO_EXTRA_INFO_MAX_LENGTH:
                    u32 = 1024u32;
                pub const DNS_CONNECTION_PROXY_INFO_FLAG_BYPASSLOCAL: u32 =
                    2u32;
                pub const DNS_CONNECTION_PROXY_INFO_FLAG_DISABLED: u32 = 1u32;
                pub const DNS_CONNECTION_PROXY_INFO_FRIENDLY_NAME_MAX_LENGTH : u32 = 64u32 ;
                pub const DNS_CONNECTION_PROXY_INFO_PASSWORD_MAX_LENGTH: u32 =
                    128u32;
                pub const DNS_CONNECTION_PROXY_INFO_SERVER_MAX_LENGTH: u32 =
                    256u32;
                #[derive(
                    :: std :: cmp :: PartialEq,
                    :: std :: cmp :: Eq,
                    :: std :: marker :: Copy,
                    :: std :: clone :: Clone,
                    :: std :: default :: Default,
                    :: std :: fmt :: Debug,
                )]
                #[repr(transparent)]
                pub struct DNS_CONNECTION_PROXY_INFO_SWITCH(pub i32);
                pub const DNS_CONNECTION_PROXY_INFO_SWITCH_CONFIG:
                    DNS_CONNECTION_PROXY_INFO_SWITCH =
                    DNS_CONNECTION_PROXY_INFO_SWITCH(0i32);
                pub const DNS_CONNECTION_PROXY_INFO_SWITCH_SCRIPT:
                    DNS_CONNECTION_PROXY_INFO_SWITCH =
                    DNS_CONNECTION_PROXY_INFO_SWITCH(1i32);
                pub const DNS_CONNECTION_PROXY_INFO_SWITCH_WPAD:
                    DNS_CONNECTION_PROXY_INFO_SWITCH =
                    DNS_CONNECTION_PROXY_INFO_SWITCH(2i32);
                impl ::std::convert::From<i32> for DNS_CONNECTION_PROXY_INFO_SWITCH {
                    fn from(value: i32) -> Self {
                        Self(value)
                    }
                }
                unsafe impl ::windows::Abi for DNS_CONNECTION_PROXY_INFO_SWITCH {
                    type Abi = Self;
                }
                pub const DNS_CONNECTION_PROXY_INFO_USERNAME_MAX_LENGTH: u32 =
                    128u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_CONNECTION_PROXY_LIST {
                    pub cProxies: u32,
                    pub pProxies: *mut DNS_CONNECTION_PROXY_ELEMENT,
                }
                impl DNS_CONNECTION_PROXY_LIST {}
                impl ::std::default::Default for DNS_CONNECTION_PROXY_LIST {
                    fn default() -> Self {
                        Self {
                            cProxies: 0,
                            pProxies: ::std::ptr::null_mut(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_CONNECTION_PROXY_LIST {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_CONNECTION_PROXY_LIST")
                            .field("cProxies", &self.cProxies)
                            .field("pProxies", &self.pProxies)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_CONNECTION_PROXY_LIST {
                    fn eq(&self, other: &Self) -> bool {
                        self.cProxies == other.cProxies
                            && self.pProxies == other.pProxies
                    }
                }
                impl ::std::cmp::Eq for DNS_CONNECTION_PROXY_LIST {}
                unsafe impl ::windows::Abi for DNS_CONNECTION_PROXY_LIST {
                    type Abi = Self;
                }
                #[derive(
                    :: std :: cmp :: PartialEq,
                    :: std :: cmp :: Eq,
                    :: std :: marker :: Copy,
                    :: std :: clone :: Clone,
                    :: std :: default :: Default,
                    :: std :: fmt :: Debug,
                )]
                #[repr(transparent)]
                pub struct DNS_CONNECTION_PROXY_TYPE(pub i32);
                pub const DNS_CONNECTION_PROXY_TYPE_NULL:
                    DNS_CONNECTION_PROXY_TYPE =
                    DNS_CONNECTION_PROXY_TYPE(0i32);
                pub const DNS_CONNECTION_PROXY_TYPE_HTTP:
                    DNS_CONNECTION_PROXY_TYPE =
                    DNS_CONNECTION_PROXY_TYPE(1i32);
                pub const DNS_CONNECTION_PROXY_TYPE_WAP:
                    DNS_CONNECTION_PROXY_TYPE =
                    DNS_CONNECTION_PROXY_TYPE(2i32);
                pub const DNS_CONNECTION_PROXY_TYPE_SOCKS4:
                    DNS_CONNECTION_PROXY_TYPE =
                    DNS_CONNECTION_PROXY_TYPE(4i32);
                pub const DNS_CONNECTION_PROXY_TYPE_SOCKS5:
                    DNS_CONNECTION_PROXY_TYPE =
                    DNS_CONNECTION_PROXY_TYPE(5i32);
                impl ::std::convert::From<i32> for DNS_CONNECTION_PROXY_TYPE {
                    fn from(value: i32) -> Self {
                        Self(value)
                    }
                }
                unsafe impl ::windows::Abi for DNS_CONNECTION_PROXY_TYPE {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_DHCID_DATA {
                    pub dwByteCount: u32,
                    pub DHCID: [u8; 1],
                }
                impl DNS_DHCID_DATA {}
                impl ::std::default::Default for DNS_DHCID_DATA {
                    fn default() -> Self {
                        Self {
                            dwByteCount: 0,
                            DHCID: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_DHCID_DATA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_DHCID_DATA")
                            .field("dwByteCount", &self.dwByteCount)
                            .field("DHCID", &self.DHCID)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_DHCID_DATA {
                    fn eq(&self, other: &Self) -> bool {
                        self.dwByteCount == other.dwByteCount
                            && self.DHCID == other.DHCID
                    }
                }
                impl ::std::cmp::Eq for DNS_DHCID_DATA {}
                unsafe impl ::windows::Abi for DNS_DHCID_DATA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_DS_DATA {
                    pub wKeyTag: u16,
                    pub chAlgorithm: u8,
                    pub chDigestType: u8,
                    pub wDigestLength: u16,
                    pub wPad: u16,
                    pub Digest: [u8; 1],
                }
                impl DNS_DS_DATA {}
                impl ::std::default::Default for DNS_DS_DATA {
                    fn default() -> Self {
                        Self {
                            wKeyTag: 0,
                            chAlgorithm: 0,
                            chDigestType: 0,
                            wDigestLength: 0,
                            wPad: 0,
                            Digest: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_DS_DATA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_DS_DATA")
                            .field("wKeyTag", &self.wKeyTag)
                            .field("chAlgorithm", &self.chAlgorithm)
                            .field("chDigestType", &self.chDigestType)
                            .field("wDigestLength", &self.wDigestLength)
                            .field("wPad", &self.wPad)
                            .field("Digest", &self.Digest)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_DS_DATA {
                    fn eq(&self, other: &Self) -> bool {
                        self.wKeyTag == other.wKeyTag
                            && self.chAlgorithm == other.chAlgorithm
                            && self.chDigestType == other.chDigestType
                            && self.wDigestLength == other.wDigestLength
                            && self.wPad == other.wPad
                            && self.Digest == other.Digest
                    }
                }
                impl ::std::cmp::Eq for DNS_DS_DATA {}
                unsafe impl ::windows::Abi for DNS_DS_DATA {
                    type Abi = Self;
                }
                #[derive(
                    :: std :: cmp :: PartialEq,
                    :: std :: cmp :: Eq,
                    :: std :: marker :: Copy,
                    :: std :: clone :: Clone,
                    :: std :: default :: Default,
                    :: std :: fmt :: Debug,
                )]
                #[repr(transparent)]
                pub struct DNS_FREE_TYPE(pub i32);
                pub const DnsFreeFlat: DNS_FREE_TYPE = DNS_FREE_TYPE(0i32);
                pub const DnsFreeRecordList: DNS_FREE_TYPE =
                    DNS_FREE_TYPE(1i32);
                pub const DnsFreeParsedMessageFields: DNS_FREE_TYPE =
                    DNS_FREE_TYPE(2i32);
                impl ::std::convert::From<i32> for DNS_FREE_TYPE {
                    fn from(value: i32) -> Self {
                        Self(value)
                    }
                }
                unsafe impl ::windows::Abi for DNS_FREE_TYPE {
                    type Abi = Self;
                }
                #[repr(C, packed(1))]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_HEADER {
                    pub Xid: u16,
                    pub _bitfield1: u8,
                    pub _bitfield2: u8,
                    pub QuestionCount: u16,
                    pub AnswerCount: u16,
                    pub NameServerCount: u16,
                    pub AdditionalCount: u16,
                }
                impl DNS_HEADER {}
                unsafe impl ::windows::Abi for DNS_HEADER {
                    type Abi = Self;
                }
                #[repr(C, packed(1))]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_HEADER_EXT {
                    pub _bitfield: u16,
                    pub chRcode: u8,
                    pub chVersion: u8,
                }
                impl DNS_HEADER_EXT {}
                unsafe impl ::windows::Abi for DNS_HEADER_EXT {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_KEY_DATA {
                    pub wFlags: u16,
                    pub chProtocol: u8,
                    pub chAlgorithm: u8,
                    pub wKeyLength: u16,
                    pub wPad: u16,
                    pub Key: [u8; 1],
                }
                impl DNS_KEY_DATA {}
                impl ::std::default::Default for DNS_KEY_DATA {
                    fn default() -> Self {
                        Self {
                            wFlags: 0,
                            chProtocol: 0,
                            chAlgorithm: 0,
                            wKeyLength: 0,
                            wPad: 0,
                            Key: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_KEY_DATA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_KEY_DATA")
                            .field("wFlags", &self.wFlags)
                            .field("chProtocol", &self.chProtocol)
                            .field("chAlgorithm", &self.chAlgorithm)
                            .field("wKeyLength", &self.wKeyLength)
                            .field("wPad", &self.wPad)
                            .field("Key", &self.Key)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_KEY_DATA {
                    fn eq(&self, other: &Self) -> bool {
                        self.wFlags == other.wFlags
                            && self.chProtocol == other.chProtocol
                            && self.chAlgorithm == other.chAlgorithm
                            && self.wKeyLength == other.wKeyLength
                            && self.wPad == other.wPad
                            && self.Key == other.Key
                    }
                }
                impl ::std::cmp::Eq for DNS_KEY_DATA {}
                unsafe impl ::windows::Abi for DNS_KEY_DATA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_LOC_DATA {
                    pub wVersion: u16,
                    pub wSize: u16,
                    pub wHorPrec: u16,
                    pub wVerPrec: u16,
                    pub dwLatitude: u32,
                    pub dwLongitude: u32,
                    pub dwAltitude: u32,
                }
                impl DNS_LOC_DATA {}
                impl ::std::default::Default for DNS_LOC_DATA {
                    fn default() -> Self {
                        Self {
                            wVersion: 0,
                            wSize: 0,
                            wHorPrec: 0,
                            wVerPrec: 0,
                            dwLatitude: 0,
                            dwLongitude: 0,
                            dwAltitude: 0,
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_LOC_DATA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_LOC_DATA")
                            .field("wVersion", &self.wVersion)
                            .field("wSize", &self.wSize)
                            .field("wHorPrec", &self.wHorPrec)
                            .field("wVerPrec", &self.wVerPrec)
                            .field("dwLatitude", &self.dwLatitude)
                            .field("dwLongitude", &self.dwLongitude)
                            .field("dwAltitude", &self.dwAltitude)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_LOC_DATA {
                    fn eq(&self, other: &Self) -> bool {
                        self.wVersion == other.wVersion
                            && self.wSize == other.wSize
                            && self.wHorPrec == other.wHorPrec
                            && self.wVerPrec == other.wVerPrec
                            && self.dwLatitude == other.dwLatitude
                            && self.dwLongitude == other.dwLongitude
                            && self.dwAltitude == other.dwAltitude
                    }
                }
                impl ::std::cmp::Eq for DNS_LOC_DATA {}
                unsafe impl ::windows::Abi for DNS_LOC_DATA {
                    type Abi = Self;
                }
                pub const DNS_MAX_IP4_REVERSE_NAME_LENGTH: u32 = 31u32;
                pub const DNS_MAX_IP6_REVERSE_NAME_LENGTH: u32 = 75u32;
                pub const DNS_MAX_LABEL_BUFFER_LENGTH: u32 = 64u32;
                pub const DNS_MAX_LABEL_LENGTH: u32 = 63u32;
                pub const DNS_MAX_NAME_BUFFER_LENGTH: u32 = 256u32;
                pub const DNS_MAX_NAME_LENGTH: u32 = 255u32;
                pub const DNS_MAX_TEXT_STRING_LENGTH: u32 = 255u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_MESSAGE_BUFFER {
                    pub MessageHead: DNS_HEADER,
                    pub MessageBody:
                        [super::super::System::SystemServices::CHAR; 1],
                }
                impl DNS_MESSAGE_BUFFER {}
                unsafe impl ::windows::Abi for DNS_MESSAGE_BUFFER {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_MINFO_DATAA {
                    pub pNameMailbox: super::super::Foundation::PSTR,
                    pub pNameErrorsMailbox: super::super::Foundation::PSTR,
                }
                impl DNS_MINFO_DATAA {}
                impl ::std::default::Default for DNS_MINFO_DATAA {
                    fn default() -> Self {
                        Self {
                            pNameMailbox: ::std::default::Default::default(),
                            pNameErrorsMailbox:
                                ::std::default::Default::default(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_MINFO_DATAA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_MINFO_DATAA")
                            .field("pNameMailbox", &self.pNameMailbox)
                            .field(
                                "pNameErrorsMailbox",
                                &self.pNameErrorsMailbox,
                            )
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_MINFO_DATAA {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNameMailbox == other.pNameMailbox
                            && self.pNameErrorsMailbox
                                == other.pNameErrorsMailbox
                    }
                }
                impl ::std::cmp::Eq for DNS_MINFO_DATAA {}
                unsafe impl ::windows::Abi for DNS_MINFO_DATAA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_MINFO_DATAW {
                    pub pNameMailbox: super::super::Foundation::PWSTR,
                    pub pNameErrorsMailbox: super::super::Foundation::PWSTR,
                }
                impl DNS_MINFO_DATAW {}
                impl ::std::default::Default for DNS_MINFO_DATAW {
                    fn default() -> Self {
                        Self {
                            pNameMailbox: ::std::default::Default::default(),
                            pNameErrorsMailbox:
                                ::std::default::Default::default(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_MINFO_DATAW {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_MINFO_DATAW")
                            .field("pNameMailbox", &self.pNameMailbox)
                            .field(
                                "pNameErrorsMailbox",
                                &self.pNameErrorsMailbox,
                            )
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_MINFO_DATAW {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNameMailbox == other.pNameMailbox
                            && self.pNameErrorsMailbox
                                == other.pNameErrorsMailbox
                    }
                }
                impl ::std::cmp::Eq for DNS_MINFO_DATAW {}
                unsafe impl ::windows::Abi for DNS_MINFO_DATAW {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_MX_DATAA {
                    pub pNameExchange: super::super::Foundation::PSTR,
                    pub wPreference: u16,
                    pub Pad: u16,
                }
                impl DNS_MX_DATAA {}
                impl ::std::default::Default for DNS_MX_DATAA {
                    fn default() -> Self {
                        Self {
                            pNameExchange: ::std::default::Default::default(),
                            wPreference: 0,
                            Pad: 0,
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_MX_DATAA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_MX_DATAA")
                            .field("pNameExchange", &self.pNameExchange)
                            .field("wPreference", &self.wPreference)
                            .field("Pad", &self.Pad)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_MX_DATAA {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNameExchange == other.pNameExchange
                            && self.wPreference == other.wPreference
                            && self.Pad == other.Pad
                    }
                }
                impl ::std::cmp::Eq for DNS_MX_DATAA {}
                unsafe impl ::windows::Abi for DNS_MX_DATAA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_MX_DATAW {
                    pub pNameExchange: super::super::Foundation::PWSTR,
                    pub wPreference: u16,
                    pub Pad: u16,
                }
                impl DNS_MX_DATAW {}
                impl ::std::default::Default for DNS_MX_DATAW {
                    fn default() -> Self {
                        Self {
                            pNameExchange: ::std::default::Default::default(),
                            wPreference: 0,
                            Pad: 0,
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_MX_DATAW {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_MX_DATAW")
                            .field("pNameExchange", &self.pNameExchange)
                            .field("wPreference", &self.wPreference)
                            .field("Pad", &self.Pad)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_MX_DATAW {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNameExchange == other.pNameExchange
                            && self.wPreference == other.wPreference
                            && self.Pad == other.Pad
                    }
                }
                impl ::std::cmp::Eq for DNS_MX_DATAW {}
                unsafe impl ::windows::Abi for DNS_MX_DATAW {
                    type Abi = Self;
                }
                #[derive(
                    :: std :: cmp :: PartialEq,
                    :: std :: cmp :: Eq,
                    :: std :: marker :: Copy,
                    :: std :: clone :: Clone,
                    :: std :: default :: Default,
                    :: std :: fmt :: Debug,
                )]
                #[repr(transparent)]
                pub struct DNS_NAME_FORMAT(pub i32);
                pub const DnsNameDomain: DNS_NAME_FORMAT =
                    DNS_NAME_FORMAT(0i32);
                pub const DnsNameDomainLabel: DNS_NAME_FORMAT =
                    DNS_NAME_FORMAT(1i32);
                pub const DnsNameHostnameFull: DNS_NAME_FORMAT =
                    DNS_NAME_FORMAT(2i32);
                pub const DnsNameHostnameLabel: DNS_NAME_FORMAT =
                    DNS_NAME_FORMAT(3i32);
                pub const DnsNameWildcard: DNS_NAME_FORMAT =
                    DNS_NAME_FORMAT(4i32);
                pub const DnsNameSrvRecord: DNS_NAME_FORMAT =
                    DNS_NAME_FORMAT(5i32);
                pub const DnsNameValidateTld: DNS_NAME_FORMAT =
                    DNS_NAME_FORMAT(6i32);
                impl ::std::convert::From<i32> for DNS_NAME_FORMAT {
                    fn from(value: i32) -> Self {
                        Self(value)
                    }
                }
                unsafe impl ::windows::Abi for DNS_NAME_FORMAT {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_NAPTR_DATAA {
                    pub wOrder: u16,
                    pub wPreference: u16,
                    pub pFlags: super::super::Foundation::PSTR,
                    pub pService: super::super::Foundation::PSTR,
                    pub pRegularExpression: super::super::Foundation::PSTR,
                    pub pReplacement: super::super::Foundation::PSTR,
                }
                impl DNS_NAPTR_DATAA {}
                impl ::std::default::Default for DNS_NAPTR_DATAA {
                    fn default() -> Self {
                        Self {
                            wOrder: 0,
                            wPreference: 0,
                            pFlags: ::std::default::Default::default(),
                            pService: ::std::default::Default::default(),
                            pRegularExpression:
                                ::std::default::Default::default(),
                            pReplacement: ::std::default::Default::default(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_NAPTR_DATAA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_NAPTR_DATAA")
                            .field("wOrder", &self.wOrder)
                            .field("wPreference", &self.wPreference)
                            .field("pFlags", &self.pFlags)
                            .field("pService", &self.pService)
                            .field(
                                "pRegularExpression",
                                &self.pRegularExpression,
                            )
                            .field("pReplacement", &self.pReplacement)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_NAPTR_DATAA {
                    fn eq(&self, other: &Self) -> bool {
                        self.wOrder == other.wOrder
                            && self.wPreference == other.wPreference
                            && self.pFlags == other.pFlags
                            && self.pService == other.pService
                            && self.pRegularExpression
                                == other.pRegularExpression
                            && self.pReplacement == other.pReplacement
                    }
                }
                impl ::std::cmp::Eq for DNS_NAPTR_DATAA {}
                unsafe impl ::windows::Abi for DNS_NAPTR_DATAA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_NAPTR_DATAW {
                    pub wOrder: u16,
                    pub wPreference: u16,
                    pub pFlags: super::super::Foundation::PWSTR,
                    pub pService: super::super::Foundation::PWSTR,
                    pub pRegularExpression: super::super::Foundation::PWSTR,
                    pub pReplacement: super::super::Foundation::PWSTR,
                }
                impl DNS_NAPTR_DATAW {}
                impl ::std::default::Default for DNS_NAPTR_DATAW {
                    fn default() -> Self {
                        Self {
                            wOrder: 0,
                            wPreference: 0,
                            pFlags: ::std::default::Default::default(),
                            pService: ::std::default::Default::default(),
                            pRegularExpression:
                                ::std::default::Default::default(),
                            pReplacement: ::std::default::Default::default(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_NAPTR_DATAW {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_NAPTR_DATAW")
                            .field("wOrder", &self.wOrder)
                            .field("wPreference", &self.wPreference)
                            .field("pFlags", &self.pFlags)
                            .field("pService", &self.pService)
                            .field(
                                "pRegularExpression",
                                &self.pRegularExpression,
                            )
                            .field("pReplacement", &self.pReplacement)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_NAPTR_DATAW {
                    fn eq(&self, other: &Self) -> bool {
                        self.wOrder == other.wOrder
                            && self.wPreference == other.wPreference
                            && self.pFlags == other.pFlags
                            && self.pService == other.pService
                            && self.pRegularExpression
                                == other.pRegularExpression
                            && self.pReplacement == other.pReplacement
                    }
                }
                impl ::std::cmp::Eq for DNS_NAPTR_DATAW {}
                unsafe impl ::windows::Abi for DNS_NAPTR_DATAW {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_NSEC3PARAM_DATA {
                    pub chAlgorithm: u8,
                    pub bFlags: u8,
                    pub wIterations: u16,
                    pub bSaltLength: u8,
                    pub bPad: [u8; 3],
                    pub pbSalt: [u8; 1],
                }
                impl DNS_NSEC3PARAM_DATA {}
                impl ::std::default::Default for DNS_NSEC3PARAM_DATA {
                    fn default() -> Self {
                        Self {
                            chAlgorithm: 0,
                            bFlags: 0,
                            wIterations: 0,
                            bSaltLength: 0,
                            bPad: [0; 3],
                            pbSalt: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_NSEC3PARAM_DATA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_NSEC3PARAM_DATA")
                            .field("chAlgorithm", &self.chAlgorithm)
                            .field("bFlags", &self.bFlags)
                            .field("wIterations", &self.wIterations)
                            .field("bSaltLength", &self.bSaltLength)
                            .field("bPad", &self.bPad)
                            .field("pbSalt", &self.pbSalt)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_NSEC3PARAM_DATA {
                    fn eq(&self, other: &Self) -> bool {
                        self.chAlgorithm == other.chAlgorithm
                            && self.bFlags == other.bFlags
                            && self.wIterations == other.wIterations
                            && self.bSaltLength == other.bSaltLength
                            && self.bPad == other.bPad
                            && self.pbSalt == other.pbSalt
                    }
                }
                impl ::std::cmp::Eq for DNS_NSEC3PARAM_DATA {}
                unsafe impl ::windows::Abi for DNS_NSEC3PARAM_DATA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_NSEC3_DATA {
                    pub chAlgorithm: u8,
                    pub bFlags: u8,
                    pub wIterations: u16,
                    pub bSaltLength: u8,
                    pub bHashLength: u8,
                    pub wTypeBitMapsLength: u16,
                    pub chData: [u8; 1],
                }
                impl DNS_NSEC3_DATA {}
                impl ::std::default::Default for DNS_NSEC3_DATA {
                    fn default() -> Self {
                        Self {
                            chAlgorithm: 0,
                            bFlags: 0,
                            wIterations: 0,
                            bSaltLength: 0,
                            bHashLength: 0,
                            wTypeBitMapsLength: 0,
                            chData: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_NSEC3_DATA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_NSEC3_DATA")
                            .field("chAlgorithm", &self.chAlgorithm)
                            .field("bFlags", &self.bFlags)
                            .field("wIterations", &self.wIterations)
                            .field("bSaltLength", &self.bSaltLength)
                            .field("bHashLength", &self.bHashLength)
                            .field(
                                "wTypeBitMapsLength",
                                &self.wTypeBitMapsLength,
                            )
                            .field("chData", &self.chData)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_NSEC3_DATA {
                    fn eq(&self, other: &Self) -> bool {
                        self.chAlgorithm == other.chAlgorithm
                            && self.bFlags == other.bFlags
                            && self.wIterations == other.wIterations
                            && self.bSaltLength == other.bSaltLength
                            && self.bHashLength == other.bHashLength
                            && self.wTypeBitMapsLength
                                == other.wTypeBitMapsLength
                            && self.chData == other.chData
                    }
                }
                impl ::std::cmp::Eq for DNS_NSEC3_DATA {}
                unsafe impl ::windows::Abi for DNS_NSEC3_DATA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_NSEC_DATAA {
                    pub pNextDomainName: super::super::Foundation::PSTR,
                    pub wTypeBitMapsLength: u16,
                    pub wPad: u16,
                    pub TypeBitMaps: [u8; 1],
                }
                impl DNS_NSEC_DATAA {}
                impl ::std::default::Default for DNS_NSEC_DATAA {
                    fn default() -> Self {
                        Self {
                            pNextDomainName: ::std::default::Default::default(
                            ),
                            wTypeBitMapsLength: 0,
                            wPad: 0,
                            TypeBitMaps: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_NSEC_DATAA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_NSEC_DATAA")
                            .field("pNextDomainName", &self.pNextDomainName)
                            .field(
                                "wTypeBitMapsLength",
                                &self.wTypeBitMapsLength,
                            )
                            .field("wPad", &self.wPad)
                            .field("TypeBitMaps", &self.TypeBitMaps)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_NSEC_DATAA {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNextDomainName == other.pNextDomainName
                            && self.wTypeBitMapsLength
                                == other.wTypeBitMapsLength
                            && self.wPad == other.wPad
                            && self.TypeBitMaps == other.TypeBitMaps
                    }
                }
                impl ::std::cmp::Eq for DNS_NSEC_DATAA {}
                unsafe impl ::windows::Abi for DNS_NSEC_DATAA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_NSEC_DATAW {
                    pub pNextDomainName: super::super::Foundation::PWSTR,
                    pub wTypeBitMapsLength: u16,
                    pub wPad: u16,
                    pub TypeBitMaps: [u8; 1],
                }
                impl DNS_NSEC_DATAW {}
                impl ::std::default::Default for DNS_NSEC_DATAW {
                    fn default() -> Self {
                        Self {
                            pNextDomainName: ::std::default::Default::default(
                            ),
                            wTypeBitMapsLength: 0,
                            wPad: 0,
                            TypeBitMaps: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_NSEC_DATAW {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_NSEC_DATAW")
                            .field("pNextDomainName", &self.pNextDomainName)
                            .field(
                                "wTypeBitMapsLength",
                                &self.wTypeBitMapsLength,
                            )
                            .field("wPad", &self.wPad)
                            .field("TypeBitMaps", &self.TypeBitMaps)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_NSEC_DATAW {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNextDomainName == other.pNextDomainName
                            && self.wTypeBitMapsLength
                                == other.wTypeBitMapsLength
                            && self.wPad == other.wPad
                            && self.TypeBitMaps == other.TypeBitMaps
                    }
                }
                impl ::std::cmp::Eq for DNS_NSEC_DATAW {}
                unsafe impl ::windows::Abi for DNS_NSEC_DATAW {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_NULL_DATA {
                    pub dwByteCount: u32,
                    pub Data: [u8; 1],
                }
                impl DNS_NULL_DATA {}
                impl ::std::default::Default for DNS_NULL_DATA {
                    fn default() -> Self {
                        Self {
                            dwByteCount: 0,
                            Data: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_NULL_DATA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_NULL_DATA")
                            .field("dwByteCount", &self.dwByteCount)
                            .field("Data", &self.Data)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_NULL_DATA {
                    fn eq(&self, other: &Self) -> bool {
                        self.dwByteCount == other.dwByteCount
                            && self.Data == other.Data
                    }
                }
                impl ::std::cmp::Eq for DNS_NULL_DATA {}
                unsafe impl ::windows::Abi for DNS_NULL_DATA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_NXT_DATAA {
                    pub pNameNext: super::super::Foundation::PSTR,
                    pub wNumTypes: u16,
                    pub wTypes: [u16; 1],
                }
                impl DNS_NXT_DATAA {}
                impl ::std::default::Default for DNS_NXT_DATAA {
                    fn default() -> Self {
                        Self {
                            pNameNext: ::std::default::Default::default(),
                            wNumTypes: 0,
                            wTypes: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_NXT_DATAA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_NXT_DATAA")
                            .field("pNameNext", &self.pNameNext)
                            .field("wNumTypes", &self.wNumTypes)
                            .field("wTypes", &self.wTypes)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_NXT_DATAA {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNameNext == other.pNameNext
                            && self.wNumTypes == other.wNumTypes
                            && self.wTypes == other.wTypes
                    }
                }
                impl ::std::cmp::Eq for DNS_NXT_DATAA {}
                unsafe impl ::windows::Abi for DNS_NXT_DATAA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_NXT_DATAW {
                    pub pNameNext: super::super::Foundation::PWSTR,
                    pub wNumTypes: u16,
                    pub wTypes: [u16; 1],
                }
                impl DNS_NXT_DATAW {}
                impl ::std::default::Default for DNS_NXT_DATAW {
                    fn default() -> Self {
                        Self {
                            pNameNext: ::std::default::Default::default(),
                            wNumTypes: 0,
                            wTypes: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_NXT_DATAW {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_NXT_DATAW")
                            .field("pNameNext", &self.pNameNext)
                            .field("wNumTypes", &self.wNumTypes)
                            .field("wTypes", &self.wTypes)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_NXT_DATAW {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNameNext == other.pNameNext
                            && self.wNumTypes == other.wNumTypes
                            && self.wTypes == other.wTypes
                    }
                }
                impl ::std::cmp::Eq for DNS_NXT_DATAW {}
                unsafe impl ::windows::Abi for DNS_NXT_DATAW {
                    type Abi = Self;
                }
                pub const DNS_OPCODE_IQUERY: u32 = 1u32;
                pub const DNS_OPCODE_NOTIFY: u32 = 4u32;
                pub const DNS_OPCODE_QUERY: u32 = 0u32;
                pub const DNS_OPCODE_SERVER_STATUS: u32 = 2u32;
                pub const DNS_OPCODE_UNKNOWN: u32 = 3u32;
                pub const DNS_OPCODE_UPDATE: u32 = 5u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_OPT_DATA {
                    pub wDataLength: u16,
                    pub wPad: u16,
                    pub Data: [u8; 1],
                }
                impl DNS_OPT_DATA {}
                impl ::std::default::Default for DNS_OPT_DATA {
                    fn default() -> Self {
                        Self {
                            wDataLength: 0,
                            wPad: 0,
                            Data: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_OPT_DATA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_OPT_DATA")
                            .field("wDataLength", &self.wDataLength)
                            .field("wPad", &self.wPad)
                            .field("Data", &self.Data)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_OPT_DATA {
                    fn eq(&self, other: &Self) -> bool {
                        self.wDataLength == other.wDataLength
                            && self.wPad == other.wPad
                            && self.Data == other.Data
                    }
                }
                impl ::std::cmp::Eq for DNS_OPT_DATA {}
                unsafe impl ::windows::Abi for DNS_OPT_DATA {
                    type Abi = Self;
                }
                pub const DNS_PORT_HOST_ORDER: u32 = 53u32;
                pub const DNS_PORT_NET_ORDER: u32 = 13568u32;
                pub type DNS_PROXY_COMPLETION_ROUTINE =
                    unsafe extern "system" fn(
                        completioncontext: *mut ::std::ffi::c_void,
                        status: i32,
                    );
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_PROXY_INFORMATION {
                    pub version: u32,
                    pub proxyInformationType: DNS_PROXY_INFORMATION_TYPE,
                    pub proxyName: super::super::Foundation::PWSTR,
                }
                impl DNS_PROXY_INFORMATION {}
                impl ::std::default::Default for DNS_PROXY_INFORMATION {
                    fn default() -> Self {
                        Self {
                            version: 0,
                            proxyInformationType:
                                ::std::default::Default::default(),
                            proxyName: ::std::default::Default::default(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_PROXY_INFORMATION {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_PROXY_INFORMATION")
                            .field("version", &self.version)
                            .field(
                                "proxyInformationType",
                                &self.proxyInformationType,
                            )
                            .field("proxyName", &self.proxyName)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_PROXY_INFORMATION {
                    fn eq(&self, other: &Self) -> bool {
                        self.version == other.version
                            && self.proxyInformationType
                                == other.proxyInformationType
                            && self.proxyName == other.proxyName
                    }
                }
                impl ::std::cmp::Eq for DNS_PROXY_INFORMATION {}
                unsafe impl ::windows::Abi for DNS_PROXY_INFORMATION {
                    type Abi = Self;
                }
                #[derive(
                    :: std :: cmp :: PartialEq,
                    :: std :: cmp :: Eq,
                    :: std :: marker :: Copy,
                    :: std :: clone :: Clone,
                    :: std :: default :: Default,
                    :: std :: fmt :: Debug,
                )]
                #[repr(transparent)]
                pub struct DNS_PROXY_INFORMATION_TYPE(pub i32);
                pub const DNS_PROXY_INFORMATION_DIRECT:
                    DNS_PROXY_INFORMATION_TYPE =
                    DNS_PROXY_INFORMATION_TYPE(0i32);
                pub const DNS_PROXY_INFORMATION_DEFAULT_SETTINGS:
                    DNS_PROXY_INFORMATION_TYPE =
                    DNS_PROXY_INFORMATION_TYPE(1i32);
                pub const DNS_PROXY_INFORMATION_PROXY_NAME:
                    DNS_PROXY_INFORMATION_TYPE =
                    DNS_PROXY_INFORMATION_TYPE(2i32);
                pub const DNS_PROXY_INFORMATION_DOES_NOT_EXIST:
                    DNS_PROXY_INFORMATION_TYPE =
                    DNS_PROXY_INFORMATION_TYPE(3i32);
                impl ::std::convert::From<i32> for DNS_PROXY_INFORMATION_TYPE {
                    fn from(value: i32) -> Self {
                        Self(value)
                    }
                }
                unsafe impl ::windows::Abi for DNS_PROXY_INFORMATION_TYPE {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_PTR_DATAA {
                    pub pNameHost: super::super::Foundation::PSTR,
                }
                impl DNS_PTR_DATAA {}
                impl ::std::default::Default for DNS_PTR_DATAA {
                    fn default() -> Self {
                        Self {
                            pNameHost: ::std::default::Default::default(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_PTR_DATAA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_PTR_DATAA")
                            .field("pNameHost", &self.pNameHost)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_PTR_DATAA {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNameHost == other.pNameHost
                    }
                }
                impl ::std::cmp::Eq for DNS_PTR_DATAA {}
                unsafe impl ::windows::Abi for DNS_PTR_DATAA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_PTR_DATAW {
                    pub pNameHost: super::super::Foundation::PWSTR,
                }
                impl DNS_PTR_DATAW {}
                impl ::std::default::Default for DNS_PTR_DATAW {
                    fn default() -> Self {
                        Self {
                            pNameHost: ::std::default::Default::default(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_PTR_DATAW {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_PTR_DATAW")
                            .field("pNameHost", &self.pNameHost)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_PTR_DATAW {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNameHost == other.pNameHost
                    }
                }
                impl ::std::cmp::Eq for DNS_PTR_DATAW {}
                unsafe impl ::windows::Abi for DNS_PTR_DATAW {
                    type Abi = Self;
                }
                pub const DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE: u32 = 1u32;
                pub const DNS_QUERY_ADDRCONFIG: u32 = 8192u32;
                pub const DNS_QUERY_APPEND_MULTILABEL: u32 = 8388608u32;
                pub const DNS_QUERY_BYPASS_CACHE: u32 = 8u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_QUERY_CANCEL {
                    pub Reserved:
                        [super::super::System::SystemServices::CHAR; 32],
                }
                impl DNS_QUERY_CANCEL {}
                impl ::std::default::Default for DNS_QUERY_CANCEL {
                    fn default() -> Self {
                        Self {
                            Reserved: [::std::default::Default::default(); 32],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_QUERY_CANCEL {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_QUERY_CANCEL")
                            .field("Reserved", &self.Reserved)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_QUERY_CANCEL {
                    fn eq(&self, other: &Self) -> bool {
                        self.Reserved == other.Reserved
                    }
                }
                impl ::std::cmp::Eq for DNS_QUERY_CANCEL {}
                unsafe impl ::windows::Abi for DNS_QUERY_CANCEL {
                    type Abi = Self;
                }
                pub const DNS_QUERY_DISABLE_IDN_ENCODING: u32 = 2097152u32;
                pub const DNS_QUERY_DNSSEC_CHECKING_DISABLED: u32 =
                    33554432u32;
                pub const DNS_QUERY_DNSSEC_OK: u32 = 16777216u32;
                pub const DNS_QUERY_DONT_RESET_TTL_VALUES: u32 = 1048576u32;
                pub const DNS_QUERY_DUAL_ADDR: u32 = 16384u32;
                pub const DNS_QUERY_MULTICAST_ONLY: u32 = 1024u32;
                pub const DNS_QUERY_NO_HOSTS_FILE: u32 = 64u32;
                pub const DNS_QUERY_NO_LOCAL_NAME: u32 = 32u32;
                pub const DNS_QUERY_NO_MULTICAST: u32 = 2048u32;
                pub const DNS_QUERY_NO_NETBT: u32 = 128u32;
                pub const DNS_QUERY_NO_RECURSION: u32 = 4u32;
                pub const DNS_QUERY_NO_WIRE_QUERY: u32 = 16u32;
                #[repr(C)]
                #[derive(:: std :: clone :: Clone)]
                pub struct DNS_QUERY_REQUEST {
                    pub Version: u32,
                    pub QueryName: super::super::Foundation::PWSTR,
                    pub QueryType: u16,
                    pub QueryOptions: u64,
                    pub pDnsServerList: *mut DNS_ADDR_ARRAY,
                    pub InterfaceIndex: u32,
                    pub pQueryCompletionCallback:
                        ::std::option::Option<PDNS_QUERY_COMPLETION_ROUTINE>,
                    pub pQueryContext: *mut ::std::ffi::c_void,
                }
                impl DNS_QUERY_REQUEST {}
                impl ::std::default::Default for DNS_QUERY_REQUEST {
                    fn default() -> Self {
                        Self {
                            Version: 0,
                            QueryName: ::std::default::Default::default(),
                            QueryType: 0,
                            QueryOptions: 0,
                            pDnsServerList: ::std::ptr::null_mut(),
                            InterfaceIndex: 0,
                            pQueryCompletionCallback:
                                ::std::default::Default::default(),
                            pQueryContext: ::std::ptr::null_mut(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_QUERY_REQUEST {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_QUERY_REQUEST")
                            .field("Version", &self.Version)
                            .field("QueryName", &self.QueryName)
                            .field("QueryType", &self.QueryType)
                            .field("QueryOptions", &self.QueryOptions)
                            .field("pDnsServerList", &self.pDnsServerList)
                            .field("InterfaceIndex", &self.InterfaceIndex)
                            .field("pQueryContext", &self.pQueryContext)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_QUERY_REQUEST {
                    fn eq(&self, other: &Self) -> bool {
                        self.Version == other.Version
                            && self.QueryName == other.QueryName
                            && self.QueryType == other.QueryType
                            && self.QueryOptions == other.QueryOptions
                            && self.pDnsServerList == other.pDnsServerList
                            && self.InterfaceIndex == other.InterfaceIndex
                            && self
                                .pQueryCompletionCallback
                                .map(|f| f as usize)
                                == other
                                    .pQueryCompletionCallback
                                    .map(|f| f as usize)
                            && self.pQueryContext == other.pQueryContext
                    }
                }
                impl ::std::cmp::Eq for DNS_QUERY_REQUEST {}
                #[repr(C)]
                #[doc(hidden)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_QUERY_REQUEST_abi {
                    pub Version: u32,
                    pub QueryName: super::super::Foundation::PWSTR,
                    pub QueryType: u16,
                    pub QueryOptions: u64,
                    pub pDnsServerList: *mut DNS_ADDR_ARRAY,
                    pub InterfaceIndex: u32,
                    pub pQueryCompletionCallback: ::windows::RawPtr,
                    pub pQueryContext: *mut ::std::ffi::c_void,
                }
                unsafe impl ::windows::Abi for DNS_QUERY_REQUEST {
                    type Abi = DNS_QUERY_REQUEST_abi;
                }
                pub const DNS_QUERY_REQUEST_VERSION1: u32 = 1u32;
                pub const DNS_QUERY_RESERVED: u32 = 4026531840u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_QUERY_RESULT {
                    pub Version: u32,
                    pub QueryStatus: i32,
                    pub QueryOptions: u64,
                    pub pQueryRecords: *mut DNS_RECORDA,
                    pub Reserved: *mut ::std::ffi::c_void,
                }
                impl DNS_QUERY_RESULT {}
                impl ::std::default::Default for DNS_QUERY_RESULT {
                    fn default() -> Self {
                        Self {
                            Version: 0,
                            QueryStatus: 0,
                            QueryOptions: 0,
                            pQueryRecords: ::std::ptr::null_mut(),
                            Reserved: ::std::ptr::null_mut(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_QUERY_RESULT {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_QUERY_RESULT")
                            .field("Version", &self.Version)
                            .field("QueryStatus", &self.QueryStatus)
                            .field("QueryOptions", &self.QueryOptions)
                            .field("pQueryRecords", &self.pQueryRecords)
                            .field("Reserved", &self.Reserved)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_QUERY_RESULT {
                    fn eq(&self, other: &Self) -> bool {
                        self.Version == other.Version
                            && self.QueryStatus == other.QueryStatus
                            && self.QueryOptions == other.QueryOptions
                            && self.pQueryRecords == other.pQueryRecords
                            && self.Reserved == other.Reserved
                    }
                }
                impl ::std::cmp::Eq for DNS_QUERY_RESULT {}
                unsafe impl ::windows::Abi for DNS_QUERY_RESULT {
                    type Abi = Self;
                }
                pub const DNS_QUERY_RESULTS_VERSION1: u32 = 1u32;
                pub const DNS_QUERY_RETURN_MESSAGE: u32 = 512u32;
                pub const DNS_QUERY_STANDARD: u32 = 0u32;
                pub const DNS_QUERY_TREAT_AS_FQDN: u32 = 4096u32;
                pub const DNS_QUERY_USE_TCP_ONLY: u32 = 2u32;
                pub const DNS_QUERY_WIRE_ONLY: u32 = 256u32;
                pub const DNS_RCLASS_ALL: u32 = 65280u32;
                pub const DNS_RCLASS_ANY: u32 = 65280u32;
                pub const DNS_RCLASS_CHAOS: u32 = 768u32;
                pub const DNS_RCLASS_CSNET: u32 = 512u32;
                pub const DNS_RCLASS_HESIOD: u32 = 1024u32;
                pub const DNS_RCLASS_INTERNET: u32 = 256u32;
                pub const DNS_RCLASS_NONE: u32 = 65024u32;
                pub const DNS_RCLASS_UNICAST_RESPONSE: u32 = 128u32;
                pub const DNS_RCODE_BADKEY: u32 = 17u32;
                pub const DNS_RCODE_BADSIG: u32 = 16u32;
                pub const DNS_RCODE_BADTIME: u32 = 18u32;
                pub const DNS_RCODE_BADVERS: u32 = 16u32;
                pub const DNS_RCODE_FORMERR: u32 = 1u32;
                pub const DNS_RCODE_MAX: u32 = 15u32;
                pub const DNS_RCODE_NOERROR: u32 = 0u32;
                pub const DNS_RCODE_NOTAUTH: u32 = 9u32;
                pub const DNS_RCODE_NOTIMPL: u32 = 4u32;
                pub const DNS_RCODE_NOTZONE: u32 = 10u32;
                pub const DNS_RCODE_NXDOMAIN: u32 = 3u32;
                pub const DNS_RCODE_NXRRSET: u32 = 8u32;
                pub const DNS_RCODE_REFUSED: u32 = 5u32;
                pub const DNS_RCODE_SERVFAIL: u32 = 2u32;
                pub const DNS_RCODE_YXDOMAIN: u32 = 6u32;
                pub const DNS_RCODE_YXRRSET: u32 = 7u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_RECORDA {
                    pub pNext: *mut DNS_RECORDA,
                    pub pName: super::super::Foundation::PSTR,
                    pub wType: u16,
                    pub wDataLength: u16,
                    pub Flags: DNS_RECORDA_1,
                    pub dwTtl: u32,
                    pub dwReserved: u32,
                    pub Data: DNS_RECORDA_0,
                }
                impl DNS_RECORDA {}
                unsafe impl ::windows::Abi for DNS_RECORDA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub union DNS_RECORDA_0 {
                    pub A: DNS_A_DATA,
                    pub SOA: DNS_SOA_DATAA,
                    pub Soa: DNS_SOA_DATAA,
                    pub PTR: DNS_PTR_DATAA,
                    pub Ptr: DNS_PTR_DATAA,
                    pub NS: DNS_PTR_DATAA,
                    pub Ns: DNS_PTR_DATAA,
                    pub CNAME: DNS_PTR_DATAA,
                    pub Cname: DNS_PTR_DATAA,
                    pub DNAME: DNS_PTR_DATAA,
                    pub Dname: DNS_PTR_DATAA,
                    pub MB: DNS_PTR_DATAA,
                    pub Mb: DNS_PTR_DATAA,
                    pub MD: DNS_PTR_DATAA,
                    pub Md: DNS_PTR_DATAA,
                    pub MF: DNS_PTR_DATAA,
                    pub Mf: DNS_PTR_DATAA,
                    pub MG: DNS_PTR_DATAA,
                    pub Mg: DNS_PTR_DATAA,
                    pub MR: DNS_PTR_DATAA,
                    pub Mr: DNS_PTR_DATAA,
                    pub MINFO: DNS_MINFO_DATAA,
                    pub Minfo: DNS_MINFO_DATAA,
                    pub RP: DNS_MINFO_DATAA,
                    pub Rp: DNS_MINFO_DATAA,
                    pub MX: DNS_MX_DATAA,
                    pub Mx: DNS_MX_DATAA,
                    pub AFSDB: DNS_MX_DATAA,
                    pub Afsdb: DNS_MX_DATAA,
                    pub RT: DNS_MX_DATAA,
                    pub Rt: DNS_MX_DATAA,
                    pub HINFO: DNS_TXT_DATAA,
                    pub Hinfo: DNS_TXT_DATAA,
                    pub ISDN: DNS_TXT_DATAA,
                    pub Isdn: DNS_TXT_DATAA,
                    pub TXT: DNS_TXT_DATAA,
                    pub Txt: DNS_TXT_DATAA,
                    pub X25: DNS_TXT_DATAA,
                    pub Null: DNS_NULL_DATA,
                    pub WKS: DNS_WKS_DATA,
                    pub Wks: DNS_WKS_DATA,
                    pub AAAA: DNS_AAAA_DATA,
                    pub KEY: DNS_KEY_DATA,
                    pub Key: DNS_KEY_DATA,
                    pub SIG: DNS_SIG_DATAA,
                    pub Sig: DNS_SIG_DATAA,
                    pub ATMA: DNS_ATMA_DATA,
                    pub Atma: DNS_ATMA_DATA,
                    pub NXT: DNS_NXT_DATAA,
                    pub Nxt: DNS_NXT_DATAA,
                    pub SRV: DNS_SRV_DATAA,
                    pub Srv: DNS_SRV_DATAA,
                    pub NAPTR: DNS_NAPTR_DATAA,
                    pub Naptr: DNS_NAPTR_DATAA,
                    pub OPT: DNS_OPT_DATA,
                    pub Opt: DNS_OPT_DATA,
                    pub DS: DNS_DS_DATA,
                    pub Ds: DNS_DS_DATA,
                    pub RRSIG: DNS_SIG_DATAA,
                    pub Rrsig: DNS_SIG_DATAA,
                    pub NSEC: DNS_NSEC_DATAA,
                    pub Nsec: DNS_NSEC_DATAA,
                    pub DNSKEY: DNS_KEY_DATA,
                    pub Dnskey: DNS_KEY_DATA,
                    pub TKEY: DNS_TKEY_DATAA,
                    pub Tkey: DNS_TKEY_DATAA,
                    pub TSIG: DNS_TSIG_DATAA,
                    pub Tsig: DNS_TSIG_DATAA,
                    pub WINS: DNS_WINS_DATA,
                    pub Wins: DNS_WINS_DATA,
                    pub WINSR: DNS_WINSR_DATAA,
                    pub WinsR: DNS_WINSR_DATAA,
                    pub NBSTAT: DNS_WINSR_DATAA,
                    pub Nbstat: DNS_WINSR_DATAA,
                    pub DHCID: DNS_DHCID_DATA,
                    pub NSEC3: DNS_NSEC3_DATA,
                    pub Nsec3: DNS_NSEC3_DATA,
                    pub NSEC3PARAM: DNS_NSEC3PARAM_DATA,
                    pub Nsec3Param: DNS_NSEC3PARAM_DATA,
                    pub TLSA: DNS_TLSA_DATA,
                    pub Tlsa: DNS_TLSA_DATA,
                    pub UNKNOWN: DNS_UNKNOWN_DATA,
                    pub Unknown: DNS_UNKNOWN_DATA,
                    pub pDataPtr: *mut u8,
                }
                impl DNS_RECORDA_0 {}
                unsafe impl ::windows::Abi for DNS_RECORDA_0 {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub union DNS_RECORDA_1 {
                    pub DW: u32,
                    pub S: DNS_RECORD_FLAGS,
                }
                impl DNS_RECORDA_1 {}
                unsafe impl ::windows::Abi for DNS_RECORDA_1 {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_RECORDW {
                    pub pNext: *mut DNS_RECORDW,
                    pub pName: super::super::Foundation::PWSTR,
                    pub wType: u16,
                    pub wDataLength: u16,
                    pub Flags: DNS_RECORDW_1,
                    pub dwTtl: u32,
                    pub dwReserved: u32,
                    pub Data: DNS_RECORDW_0,
                }
                impl DNS_RECORDW {}
                unsafe impl ::windows::Abi for DNS_RECORDW {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub union DNS_RECORDW_0 {
                    pub A: DNS_A_DATA,
                    pub SOA: DNS_SOA_DATAW,
                    pub Soa: DNS_SOA_DATAW,
                    pub PTR: DNS_PTR_DATAW,
                    pub Ptr: DNS_PTR_DATAW,
                    pub NS: DNS_PTR_DATAW,
                    pub Ns: DNS_PTR_DATAW,
                    pub CNAME: DNS_PTR_DATAW,
                    pub Cname: DNS_PTR_DATAW,
                    pub DNAME: DNS_PTR_DATAW,
                    pub Dname: DNS_PTR_DATAW,
                    pub MB: DNS_PTR_DATAW,
                    pub Mb: DNS_PTR_DATAW,
                    pub MD: DNS_PTR_DATAW,
                    pub Md: DNS_PTR_DATAW,
                    pub MF: DNS_PTR_DATAW,
                    pub Mf: DNS_PTR_DATAW,
                    pub MG: DNS_PTR_DATAW,
                    pub Mg: DNS_PTR_DATAW,
                    pub MR: DNS_PTR_DATAW,
                    pub Mr: DNS_PTR_DATAW,
                    pub MINFO: DNS_MINFO_DATAW,
                    pub Minfo: DNS_MINFO_DATAW,
                    pub RP: DNS_MINFO_DATAW,
                    pub Rp: DNS_MINFO_DATAW,
                    pub MX: DNS_MX_DATAW,
                    pub Mx: DNS_MX_DATAW,
                    pub AFSDB: DNS_MX_DATAW,
                    pub Afsdb: DNS_MX_DATAW,
                    pub RT: DNS_MX_DATAW,
                    pub Rt: DNS_MX_DATAW,
                    pub HINFO: DNS_TXT_DATAW,
                    pub Hinfo: DNS_TXT_DATAW,
                    pub ISDN: DNS_TXT_DATAW,
                    pub Isdn: DNS_TXT_DATAW,
                    pub TXT: DNS_TXT_DATAW,
                    pub Txt: DNS_TXT_DATAW,
                    pub X25: DNS_TXT_DATAW,
                    pub Null: DNS_NULL_DATA,
                    pub WKS: DNS_WKS_DATA,
                    pub Wks: DNS_WKS_DATA,
                    pub AAAA: DNS_AAAA_DATA,
                    pub KEY: DNS_KEY_DATA,
                    pub Key: DNS_KEY_DATA,
                    pub SIG: DNS_SIG_DATAW,
                    pub Sig: DNS_SIG_DATAW,
                    pub ATMA: DNS_ATMA_DATA,
                    pub Atma: DNS_ATMA_DATA,
                    pub NXT: DNS_NXT_DATAW,
                    pub Nxt: DNS_NXT_DATAW,
                    pub SRV: DNS_SRV_DATAW,
                    pub Srv: DNS_SRV_DATAW,
                    pub NAPTR: DNS_NAPTR_DATAW,
                    pub Naptr: DNS_NAPTR_DATAW,
                    pub OPT: DNS_OPT_DATA,
                    pub Opt: DNS_OPT_DATA,
                    pub DS: DNS_DS_DATA,
                    pub Ds: DNS_DS_DATA,
                    pub RRSIG: DNS_SIG_DATAW,
                    pub Rrsig: DNS_SIG_DATAW,
                    pub NSEC: DNS_NSEC_DATAW,
                    pub Nsec: DNS_NSEC_DATAW,
                    pub DNSKEY: DNS_KEY_DATA,
                    pub Dnskey: DNS_KEY_DATA,
                    pub TKEY: DNS_TKEY_DATAW,
                    pub Tkey: DNS_TKEY_DATAW,
                    pub TSIG: DNS_TSIG_DATAW,
                    pub Tsig: DNS_TSIG_DATAW,
                    pub WINS: DNS_WINS_DATA,
                    pub Wins: DNS_WINS_DATA,
                    pub WINSR: DNS_WINSR_DATAW,
                    pub WinsR: DNS_WINSR_DATAW,
                    pub NBSTAT: DNS_WINSR_DATAW,
                    pub Nbstat: DNS_WINSR_DATAW,
                    pub DHCID: DNS_DHCID_DATA,
                    pub NSEC3: DNS_NSEC3_DATA,
                    pub Nsec3: DNS_NSEC3_DATA,
                    pub NSEC3PARAM: DNS_NSEC3PARAM_DATA,
                    pub Nsec3Param: DNS_NSEC3PARAM_DATA,
                    pub TLSA: DNS_TLSA_DATA,
                    pub Tlsa: DNS_TLSA_DATA,
                    pub UNKNOWN: DNS_UNKNOWN_DATA,
                    pub Unknown: DNS_UNKNOWN_DATA,
                    pub pDataPtr: *mut u8,
                }
                impl DNS_RECORDW_0 {}
                unsafe impl ::windows::Abi for DNS_RECORDW_0 {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub union DNS_RECORDW_1 {
                    pub DW: u32,
                    pub S: DNS_RECORD_FLAGS,
                }
                impl DNS_RECORDW_1 {}
                unsafe impl ::windows::Abi for DNS_RECORDW_1 {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_RECORD_FLAGS {
                    pub _bitfield: u32,
                }
                impl DNS_RECORD_FLAGS {}
                impl ::std::default::Default for DNS_RECORD_FLAGS {
                    fn default() -> Self {
                        Self { _bitfield: 0 }
                    }
                }
                impl ::std::fmt::Debug for DNS_RECORD_FLAGS {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_RECORD_FLAGS")
                            .field("_bitfield", &self._bitfield)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_RECORD_FLAGS {
                    fn eq(&self, other: &Self) -> bool {
                        self._bitfield == other._bitfield
                    }
                }
                impl ::std::cmp::Eq for DNS_RECORD_FLAGS {}
                unsafe impl ::windows::Abi for DNS_RECORD_FLAGS {
                    type Abi = Self;
                }
                pub const DNS_RFC_MAX_UDP_PACKET_LENGTH: u32 = 512u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_RRSET {
                    pub pFirstRR: *mut DNS_RECORDA,
                    pub pLastRR: *mut DNS_RECORDA,
                }
                impl DNS_RRSET {}
                impl ::std::default::Default for DNS_RRSET {
                    fn default() -> Self {
                        Self {
                            pFirstRR: ::std::ptr::null_mut(),
                            pLastRR: ::std::ptr::null_mut(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_RRSET {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_RRSET")
                            .field("pFirstRR", &self.pFirstRR)
                            .field("pLastRR", &self.pLastRR)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_RRSET {
                    fn eq(&self, other: &Self) -> bool {
                        self.pFirstRR == other.pFirstRR
                            && self.pLastRR == other.pLastRR
                    }
                }
                impl ::std::cmp::Eq for DNS_RRSET {}
                unsafe impl ::windows::Abi for DNS_RRSET {
                    type Abi = Self;
                }
                pub const DNS_RTYPE_A: u32 = 256u32;
                pub const DNS_RTYPE_A6: u32 = 9728u32;
                pub const DNS_RTYPE_AAAA: u32 = 7168u32;
                pub const DNS_RTYPE_AFSDB: u32 = 4608u32;
                pub const DNS_RTYPE_ALL: u32 = 65280u32;
                pub const DNS_RTYPE_ANY: u32 = 65280u32;
                pub const DNS_RTYPE_ATMA: u32 = 8704u32;
                pub const DNS_RTYPE_AXFR: u32 = 64512u32;
                pub const DNS_RTYPE_CERT: u32 = 9472u32;
                pub const DNS_RTYPE_CNAME: u32 = 1280u32;
                pub const DNS_RTYPE_DHCID: u32 = 12544u32;
                pub const DNS_RTYPE_DNAME: u32 = 9984u32;
                pub const DNS_RTYPE_DNSKEY: u32 = 12288u32;
                pub const DNS_RTYPE_DS: u32 = 11008u32;
                pub const DNS_RTYPE_EID: u32 = 7936u32;
                pub const DNS_RTYPE_GID: u32 = 26112u32;
                pub const DNS_RTYPE_GPOS: u32 = 6912u32;
                pub const DNS_RTYPE_HINFO: u32 = 3328u32;
                pub const DNS_RTYPE_ISDN: u32 = 5120u32;
                pub const DNS_RTYPE_IXFR: u32 = 64256u32;
                pub const DNS_RTYPE_KEY: u32 = 6400u32;
                pub const DNS_RTYPE_KX: u32 = 9216u32;
                pub const DNS_RTYPE_LOC: u32 = 7424u32;
                pub const DNS_RTYPE_MAILA: u32 = 65024u32;
                pub const DNS_RTYPE_MAILB: u32 = 64768u32;
                pub const DNS_RTYPE_MB: u32 = 1792u32;
                pub const DNS_RTYPE_MD: u32 = 768u32;
                pub const DNS_RTYPE_MF: u32 = 1024u32;
                pub const DNS_RTYPE_MG: u32 = 2048u32;
                pub const DNS_RTYPE_MINFO: u32 = 3584u32;
                pub const DNS_RTYPE_MR: u32 = 2304u32;
                pub const DNS_RTYPE_MX: u32 = 3840u32;
                pub const DNS_RTYPE_NAPTR: u32 = 8960u32;
                pub const DNS_RTYPE_NIMLOC: u32 = 8192u32;
                pub const DNS_RTYPE_NS: u32 = 512u32;
                pub const DNS_RTYPE_NSAP: u32 = 5632u32;
                pub const DNS_RTYPE_NSAPPTR: u32 = 5888u32;
                pub const DNS_RTYPE_NSEC: u32 = 12032u32;
                pub const DNS_RTYPE_NSEC3: u32 = 12800u32;
                pub const DNS_RTYPE_NSEC3PARAM: u32 = 13056u32;
                pub const DNS_RTYPE_NULL: u32 = 2560u32;
                pub const DNS_RTYPE_NXT: u32 = 7680u32;
                pub const DNS_RTYPE_OPT: u32 = 10496u32;
                pub const DNS_RTYPE_PTR: u32 = 3072u32;
                pub const DNS_RTYPE_PX: u32 = 6656u32;
                pub const DNS_RTYPE_RP: u32 = 4352u32;
                pub const DNS_RTYPE_RRSIG: u32 = 11776u32;
                pub const DNS_RTYPE_RT: u32 = 5376u32;
                pub const DNS_RTYPE_SIG: u32 = 6144u32;
                pub const DNS_RTYPE_SINK: u32 = 10240u32;
                pub const DNS_RTYPE_SOA: u32 = 1536u32;
                pub const DNS_RTYPE_SRV: u32 = 8448u32;
                pub const DNS_RTYPE_TEXT: u32 = 4096u32;
                pub const DNS_RTYPE_TKEY: u32 = 63744u32;
                pub const DNS_RTYPE_TLSA: u32 = 13312u32;
                pub const DNS_RTYPE_TSIG: u32 = 64000u32;
                pub const DNS_RTYPE_UID: u32 = 25856u32;
                pub const DNS_RTYPE_UINFO: u32 = 25600u32;
                pub const DNS_RTYPE_UNSPEC: u32 = 26368u32;
                pub const DNS_RTYPE_WINS: u32 = 511u32;
                pub const DNS_RTYPE_WINSR: u32 = 767u32;
                pub const DNS_RTYPE_WKS: u32 = 2816u32;
                pub const DNS_RTYPE_X25: u32 = 4864u32;
                #[derive(
                    :: std :: cmp :: PartialEq,
                    :: std :: cmp :: Eq,
                    :: std :: marker :: Copy,
                    :: std :: clone :: Clone,
                    :: std :: default :: Default,
                    :: std :: fmt :: Debug,
                )]
                #[repr(transparent)]
                pub struct DNS_SECTION(pub i32);
                pub const DnsSectionQuestion: DNS_SECTION = DNS_SECTION(0i32);
                pub const DnsSectionAnswer: DNS_SECTION = DNS_SECTION(1i32);
                pub const DnsSectionAuthority: DNS_SECTION = DNS_SECTION(2i32);
                pub const DnsSectionAddtional: DNS_SECTION = DNS_SECTION(3i32);
                impl ::std::convert::From<i32> for DNS_SECTION {
                    fn from(value: i32) -> Self {
                        Self(value)
                    }
                }
                unsafe impl ::windows::Abi for DNS_SECTION {
                    type Abi = Self;
                }
                #[repr(C)]
                pub struct DNS_SERVICE_BROWSE_REQUEST {
                    pub Version: u32,
                    pub InterfaceIndex: u32,
                    pub QueryName: super::super::Foundation::PWSTR,
                    pub Anonymous: DNS_SERVICE_BROWSE_REQUEST_0,
                    pub pQueryContext: *mut ::std::ffi::c_void,
                }
                impl DNS_SERVICE_BROWSE_REQUEST {}
                #[repr(C)]
                #[doc(hidden)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_SERVICE_BROWSE_REQUEST_abi {
                    pub Version: u32,
                    pub InterfaceIndex: u32,
                    pub QueryName: super::super::Foundation::PWSTR,
                    pub Anonymous: DNS_SERVICE_BROWSE_REQUEST_0_abi,
                    pub pQueryContext: *mut ::std::ffi::c_void,
                }
                unsafe impl ::windows::Abi for DNS_SERVICE_BROWSE_REQUEST {
                    type Abi = DNS_SERVICE_BROWSE_REQUEST_abi;
                }
                #[repr(C)]
                pub union DNS_SERVICE_BROWSE_REQUEST_0 {
                    pub pBrowseCallback: ::windows::RawPtr,
                    pub pBrowseCallbackV2: ::windows::RawPtr,
                }
                impl DNS_SERVICE_BROWSE_REQUEST_0 {}
                #[repr(C)]
                #[doc(hidden)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub union DNS_SERVICE_BROWSE_REQUEST_0_abi {
                    pub pBrowseCallback: ::windows::RawPtr,
                    pub pBrowseCallbackV2: ::windows::RawPtr,
                }
                unsafe impl ::windows::Abi for DNS_SERVICE_BROWSE_REQUEST_0 {
                    type Abi = DNS_SERVICE_BROWSE_REQUEST_0_abi;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_SERVICE_CANCEL {
                    pub reserved: *mut ::std::ffi::c_void,
                }
                impl DNS_SERVICE_CANCEL {}
                impl ::std::default::Default for DNS_SERVICE_CANCEL {
                    fn default() -> Self {
                        Self {
                            reserved: ::std::ptr::null_mut(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_SERVICE_CANCEL {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_SERVICE_CANCEL")
                            .field("reserved", &self.reserved)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_SERVICE_CANCEL {
                    fn eq(&self, other: &Self) -> bool {
                        self.reserved == other.reserved
                    }
                }
                impl ::std::cmp::Eq for DNS_SERVICE_CANCEL {}
                unsafe impl ::windows::Abi for DNS_SERVICE_CANCEL {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_SERVICE_INSTANCE {
                    pub pszInstanceName: super::super::Foundation::PWSTR,
                    pub pszHostName: super::super::Foundation::PWSTR,
                    pub ip4Address: *mut u32,
                    pub ip6Address: *mut IP6_ADDRESS,
                    pub wPort: u16,
                    pub wPriority: u16,
                    pub wWeight: u16,
                    pub dwPropertyCount: u32,
                    pub keys: *mut super::super::Foundation::PWSTR,
                    pub values: *mut super::super::Foundation::PWSTR,
                    pub dwInterfaceIndex: u32,
                }
                impl DNS_SERVICE_INSTANCE {}
                impl ::std::default::Default for DNS_SERVICE_INSTANCE {
                    fn default() -> Self {
                        Self {
                            pszInstanceName: ::std::default::Default::default(
                            ),
                            pszHostName: ::std::default::Default::default(),
                            ip4Address: ::std::ptr::null_mut(),
                            ip6Address: ::std::ptr::null_mut(),
                            wPort: 0,
                            wPriority: 0,
                            wWeight: 0,
                            dwPropertyCount: 0,
                            keys: ::std::ptr::null_mut(),
                            values: ::std::ptr::null_mut(),
                            dwInterfaceIndex: 0,
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_SERVICE_INSTANCE {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_SERVICE_INSTANCE")
                            .field("pszInstanceName", &self.pszInstanceName)
                            .field("pszHostName", &self.pszHostName)
                            .field("ip4Address", &self.ip4Address)
                            .field("ip6Address", &self.ip6Address)
                            .field("wPort", &self.wPort)
                            .field("wPriority", &self.wPriority)
                            .field("wWeight", &self.wWeight)
                            .field("dwPropertyCount", &self.dwPropertyCount)
                            .field("keys", &self.keys)
                            .field("values", &self.values)
                            .field("dwInterfaceIndex", &self.dwInterfaceIndex)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_SERVICE_INSTANCE {
                    fn eq(&self, other: &Self) -> bool {
                        self.pszInstanceName == other.pszInstanceName
                            && self.pszHostName == other.pszHostName
                            && self.ip4Address == other.ip4Address
                            && self.ip6Address == other.ip6Address
                            && self.wPort == other.wPort
                            && self.wPriority == other.wPriority
                            && self.wWeight == other.wWeight
                            && self.dwPropertyCount == other.dwPropertyCount
                            && self.keys == other.keys
                            && self.values == other.values
                            && self.dwInterfaceIndex == other.dwInterfaceIndex
                    }
                }
                impl ::std::cmp::Eq for DNS_SERVICE_INSTANCE {}
                unsafe impl ::windows::Abi for DNS_SERVICE_INSTANCE {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(:: std :: clone :: Clone)]
                pub struct DNS_SERVICE_REGISTER_REQUEST {
                    pub Version: u32,
                    pub InterfaceIndex: u32,
                    pub pServiceInstance: *mut DNS_SERVICE_INSTANCE,
                    pub pRegisterCompletionCallback:
                        ::std::option::Option<PDNS_SERVICE_REGISTER_COMPLETE>,
                    pub pQueryContext: *mut ::std::ffi::c_void,
                    pub hCredentials: super::super::Foundation::HANDLE,
                    pub unicastEnabled: super::super::Foundation::BOOL,
                }
                impl DNS_SERVICE_REGISTER_REQUEST {}
                impl ::std::default::Default for DNS_SERVICE_REGISTER_REQUEST {
                    fn default() -> Self {
                        Self {
                            Version: 0,
                            InterfaceIndex: 0,
                            pServiceInstance: ::std::ptr::null_mut(),
                            pRegisterCompletionCallback:
                                ::std::default::Default::default(),
                            pQueryContext: ::std::ptr::null_mut(),
                            hCredentials: ::std::default::Default::default(),
                            unicastEnabled: ::std::default::Default::default(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_SERVICE_REGISTER_REQUEST {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_SERVICE_REGISTER_REQUEST")
                            .field("Version", &self.Version)
                            .field("InterfaceIndex", &self.InterfaceIndex)
                            .field("pServiceInstance", &self.pServiceInstance)
                            .field("pQueryContext", &self.pQueryContext)
                            .field("hCredentials", &self.hCredentials)
                            .field("unicastEnabled", &self.unicastEnabled)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_SERVICE_REGISTER_REQUEST {
                    fn eq(&self, other: &Self) -> bool {
                        self.Version == other.Version
                            && self.InterfaceIndex == other.InterfaceIndex
                            && self.pServiceInstance == other.pServiceInstance
                            && self
                                .pRegisterCompletionCallback
                                .map(|f| f as usize)
                                == other
                                    .pRegisterCompletionCallback
                                    .map(|f| f as usize)
                            && self.pQueryContext == other.pQueryContext
                            && self.hCredentials == other.hCredentials
                            && self.unicastEnabled == other.unicastEnabled
                    }
                }
                impl ::std::cmp::Eq for DNS_SERVICE_REGISTER_REQUEST {}
                #[repr(C)]
                #[doc(hidden)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_SERVICE_REGISTER_REQUEST_abi {
                    pub Version: u32,
                    pub InterfaceIndex: u32,
                    pub pServiceInstance: *mut DNS_SERVICE_INSTANCE,
                    pub pRegisterCompletionCallback: ::windows::RawPtr,
                    pub pQueryContext: *mut ::std::ffi::c_void,
                    pub hCredentials: super::super::Foundation::HANDLE,
                    pub unicastEnabled: super::super::Foundation::BOOL,
                }
                unsafe impl ::windows::Abi for DNS_SERVICE_REGISTER_REQUEST {
                    type Abi = DNS_SERVICE_REGISTER_REQUEST_abi;
                }
                #[repr(C)]
                #[derive(:: std :: clone :: Clone)]
                pub struct DNS_SERVICE_RESOLVE_REQUEST {
                    pub Version: u32,
                    pub InterfaceIndex: u32,
                    pub QueryName: super::super::Foundation::PWSTR,
                    pub pResolveCompletionCallback:
                        ::std::option::Option<PDNS_SERVICE_RESOLVE_COMPLETE>,
                    pub pQueryContext: *mut ::std::ffi::c_void,
                }
                impl DNS_SERVICE_RESOLVE_REQUEST {}
                impl ::std::default::Default for DNS_SERVICE_RESOLVE_REQUEST {
                    fn default() -> Self {
                        Self {
                            Version: 0,
                            InterfaceIndex: 0,
                            QueryName: ::std::default::Default::default(),
                            pResolveCompletionCallback:
                                ::std::default::Default::default(),
                            pQueryContext: ::std::ptr::null_mut(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_SERVICE_RESOLVE_REQUEST {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_SERVICE_RESOLVE_REQUEST")
                            .field("Version", &self.Version)
                            .field("InterfaceIndex", &self.InterfaceIndex)
                            .field("QueryName", &self.QueryName)
                            .field("pQueryContext", &self.pQueryContext)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_SERVICE_RESOLVE_REQUEST {
                    fn eq(&self, other: &Self) -> bool {
                        self.Version == other.Version
                            && self.InterfaceIndex == other.InterfaceIndex
                            && self.QueryName == other.QueryName
                            && self
                                .pResolveCompletionCallback
                                .map(|f| f as usize)
                                == other
                                    .pResolveCompletionCallback
                                    .map(|f| f as usize)
                            && self.pQueryContext == other.pQueryContext
                    }
                }
                impl ::std::cmp::Eq for DNS_SERVICE_RESOLVE_REQUEST {}
                #[repr(C)]
                #[doc(hidden)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_SERVICE_RESOLVE_REQUEST_abi {
                    pub Version: u32,
                    pub InterfaceIndex: u32,
                    pub QueryName: super::super::Foundation::PWSTR,
                    pub pResolveCompletionCallback: ::windows::RawPtr,
                    pub pQueryContext: *mut ::std::ffi::c_void,
                }
                unsafe impl ::windows::Abi for DNS_SERVICE_RESOLVE_REQUEST {
                    type Abi = DNS_SERVICE_RESOLVE_REQUEST_abi;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_SIG_DATAA {
                    pub wTypeCovered: u16,
                    pub chAlgorithm: u8,
                    pub chLabelCount: u8,
                    pub dwOriginalTtl: u32,
                    pub dwExpiration: u32,
                    pub dwTimeSigned: u32,
                    pub wKeyTag: u16,
                    pub wSignatureLength: u16,
                    pub pNameSigner: super::super::Foundation::PSTR,
                    pub Signature: [u8; 1],
                }
                impl DNS_SIG_DATAA {}
                impl ::std::default::Default for DNS_SIG_DATAA {
                    fn default() -> Self {
                        Self {
                            wTypeCovered: 0,
                            chAlgorithm: 0,
                            chLabelCount: 0,
                            dwOriginalTtl: 0,
                            dwExpiration: 0,
                            dwTimeSigned: 0,
                            wKeyTag: 0,
                            wSignatureLength: 0,
                            pNameSigner: ::std::default::Default::default(),
                            Signature: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_SIG_DATAA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_SIG_DATAA")
                            .field("wTypeCovered", &self.wTypeCovered)
                            .field("chAlgorithm", &self.chAlgorithm)
                            .field("chLabelCount", &self.chLabelCount)
                            .field("dwOriginalTtl", &self.dwOriginalTtl)
                            .field("dwExpiration", &self.dwExpiration)
                            .field("dwTimeSigned", &self.dwTimeSigned)
                            .field("wKeyTag", &self.wKeyTag)
                            .field("wSignatureLength", &self.wSignatureLength)
                            .field("pNameSigner", &self.pNameSigner)
                            .field("Signature", &self.Signature)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_SIG_DATAA {
                    fn eq(&self, other: &Self) -> bool {
                        self.wTypeCovered == other.wTypeCovered
                            && self.chAlgorithm == other.chAlgorithm
                            && self.chLabelCount == other.chLabelCount
                            && self.dwOriginalTtl == other.dwOriginalTtl
                            && self.dwExpiration == other.dwExpiration
                            && self.dwTimeSigned == other.dwTimeSigned
                            && self.wKeyTag == other.wKeyTag
                            && self.wSignatureLength == other.wSignatureLength
                            && self.pNameSigner == other.pNameSigner
                            && self.Signature == other.Signature
                    }
                }
                impl ::std::cmp::Eq for DNS_SIG_DATAA {}
                unsafe impl ::windows::Abi for DNS_SIG_DATAA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_SIG_DATAW {
                    pub wTypeCovered: u16,
                    pub chAlgorithm: u8,
                    pub chLabelCount: u8,
                    pub dwOriginalTtl: u32,
                    pub dwExpiration: u32,
                    pub dwTimeSigned: u32,
                    pub wKeyTag: u16,
                    pub wSignatureLength: u16,
                    pub pNameSigner: super::super::Foundation::PWSTR,
                    pub Signature: [u8; 1],
                }
                impl DNS_SIG_DATAW {}
                impl ::std::default::Default for DNS_SIG_DATAW {
                    fn default() -> Self {
                        Self {
                            wTypeCovered: 0,
                            chAlgorithm: 0,
                            chLabelCount: 0,
                            dwOriginalTtl: 0,
                            dwExpiration: 0,
                            dwTimeSigned: 0,
                            wKeyTag: 0,
                            wSignatureLength: 0,
                            pNameSigner: ::std::default::Default::default(),
                            Signature: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_SIG_DATAW {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_SIG_DATAW")
                            .field("wTypeCovered", &self.wTypeCovered)
                            .field("chAlgorithm", &self.chAlgorithm)
                            .field("chLabelCount", &self.chLabelCount)
                            .field("dwOriginalTtl", &self.dwOriginalTtl)
                            .field("dwExpiration", &self.dwExpiration)
                            .field("dwTimeSigned", &self.dwTimeSigned)
                            .field("wKeyTag", &self.wKeyTag)
                            .field("wSignatureLength", &self.wSignatureLength)
                            .field("pNameSigner", &self.pNameSigner)
                            .field("Signature", &self.Signature)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_SIG_DATAW {
                    fn eq(&self, other: &Self) -> bool {
                        self.wTypeCovered == other.wTypeCovered
                            && self.chAlgorithm == other.chAlgorithm
                            && self.chLabelCount == other.chLabelCount
                            && self.dwOriginalTtl == other.dwOriginalTtl
                            && self.dwExpiration == other.dwExpiration
                            && self.dwTimeSigned == other.dwTimeSigned
                            && self.wKeyTag == other.wKeyTag
                            && self.wSignatureLength == other.wSignatureLength
                            && self.pNameSigner == other.pNameSigner
                            && self.Signature == other.Signature
                    }
                }
                impl ::std::cmp::Eq for DNS_SIG_DATAW {}
                unsafe impl ::windows::Abi for DNS_SIG_DATAW {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_SOA_DATAA {
                    pub pNamePrimaryServer: super::super::Foundation::PSTR,
                    pub pNameAdministrator: super::super::Foundation::PSTR,
                    pub dwSerialNo: u32,
                    pub dwRefresh: u32,
                    pub dwRetry: u32,
                    pub dwExpire: u32,
                    pub dwDefaultTtl: u32,
                }
                impl DNS_SOA_DATAA {}
                impl ::std::default::Default for DNS_SOA_DATAA {
                    fn default() -> Self {
                        Self {
                            pNamePrimaryServer:
                                ::std::default::Default::default(),
                            pNameAdministrator:
                                ::std::default::Default::default(),
                            dwSerialNo: 0,
                            dwRefresh: 0,
                            dwRetry: 0,
                            dwExpire: 0,
                            dwDefaultTtl: 0,
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_SOA_DATAA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_SOA_DATAA")
                            .field(
                                "pNamePrimaryServer",
                                &self.pNamePrimaryServer,
                            )
                            .field(
                                "pNameAdministrator",
                                &self.pNameAdministrator,
                            )
                            .field("dwSerialNo", &self.dwSerialNo)
                            .field("dwRefresh", &self.dwRefresh)
                            .field("dwRetry", &self.dwRetry)
                            .field("dwExpire", &self.dwExpire)
                            .field("dwDefaultTtl", &self.dwDefaultTtl)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_SOA_DATAA {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNamePrimaryServer == other.pNamePrimaryServer
                            && self.pNameAdministrator
                                == other.pNameAdministrator
                            && self.dwSerialNo == other.dwSerialNo
                            && self.dwRefresh == other.dwRefresh
                            && self.dwRetry == other.dwRetry
                            && self.dwExpire == other.dwExpire
                            && self.dwDefaultTtl == other.dwDefaultTtl
                    }
                }
                impl ::std::cmp::Eq for DNS_SOA_DATAA {}
                unsafe impl ::windows::Abi for DNS_SOA_DATAA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_SOA_DATAW {
                    pub pNamePrimaryServer: super::super::Foundation::PWSTR,
                    pub pNameAdministrator: super::super::Foundation::PWSTR,
                    pub dwSerialNo: u32,
                    pub dwRefresh: u32,
                    pub dwRetry: u32,
                    pub dwExpire: u32,
                    pub dwDefaultTtl: u32,
                }
                impl DNS_SOA_DATAW {}
                impl ::std::default::Default for DNS_SOA_DATAW {
                    fn default() -> Self {
                        Self {
                            pNamePrimaryServer:
                                ::std::default::Default::default(),
                            pNameAdministrator:
                                ::std::default::Default::default(),
                            dwSerialNo: 0,
                            dwRefresh: 0,
                            dwRetry: 0,
                            dwExpire: 0,
                            dwDefaultTtl: 0,
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_SOA_DATAW {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_SOA_DATAW")
                            .field(
                                "pNamePrimaryServer",
                                &self.pNamePrimaryServer,
                            )
                            .field(
                                "pNameAdministrator",
                                &self.pNameAdministrator,
                            )
                            .field("dwSerialNo", &self.dwSerialNo)
                            .field("dwRefresh", &self.dwRefresh)
                            .field("dwRetry", &self.dwRetry)
                            .field("dwExpire", &self.dwExpire)
                            .field("dwDefaultTtl", &self.dwDefaultTtl)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_SOA_DATAW {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNamePrimaryServer == other.pNamePrimaryServer
                            && self.pNameAdministrator
                                == other.pNameAdministrator
                            && self.dwSerialNo == other.dwSerialNo
                            && self.dwRefresh == other.dwRefresh
                            && self.dwRetry == other.dwRetry
                            && self.dwExpire == other.dwExpire
                            && self.dwDefaultTtl == other.dwDefaultTtl
                    }
                }
                impl ::std::cmp::Eq for DNS_SOA_DATAW {}
                unsafe impl ::windows::Abi for DNS_SOA_DATAW {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_SRV_DATAA {
                    pub pNameTarget: super::super::Foundation::PSTR,
                    pub wPriority: u16,
                    pub wWeight: u16,
                    pub wPort: u16,
                    pub Pad: u16,
                }
                impl DNS_SRV_DATAA {}
                impl ::std::default::Default for DNS_SRV_DATAA {
                    fn default() -> Self {
                        Self {
                            pNameTarget: ::std::default::Default::default(),
                            wPriority: 0,
                            wWeight: 0,
                            wPort: 0,
                            Pad: 0,
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_SRV_DATAA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_SRV_DATAA")
                            .field("pNameTarget", &self.pNameTarget)
                            .field("wPriority", &self.wPriority)
                            .field("wWeight", &self.wWeight)
                            .field("wPort", &self.wPort)
                            .field("Pad", &self.Pad)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_SRV_DATAA {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNameTarget == other.pNameTarget
                            && self.wPriority == other.wPriority
                            && self.wWeight == other.wWeight
                            && self.wPort == other.wPort
                            && self.Pad == other.Pad
                    }
                }
                impl ::std::cmp::Eq for DNS_SRV_DATAA {}
                unsafe impl ::windows::Abi for DNS_SRV_DATAA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_SRV_DATAW {
                    pub pNameTarget: super::super::Foundation::PWSTR,
                    pub wPriority: u16,
                    pub wWeight: u16,
                    pub wPort: u16,
                    pub Pad: u16,
                }
                impl DNS_SRV_DATAW {}
                impl ::std::default::Default for DNS_SRV_DATAW {
                    fn default() -> Self {
                        Self {
                            pNameTarget: ::std::default::Default::default(),
                            wPriority: 0,
                            wWeight: 0,
                            wPort: 0,
                            Pad: 0,
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_SRV_DATAW {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_SRV_DATAW")
                            .field("pNameTarget", &self.pNameTarget)
                            .field("wPriority", &self.wPriority)
                            .field("wWeight", &self.wWeight)
                            .field("wPort", &self.wPort)
                            .field("Pad", &self.Pad)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_SRV_DATAW {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNameTarget == other.pNameTarget
                            && self.wPriority == other.wPriority
                            && self.wWeight == other.wWeight
                            && self.wPort == other.wPort
                            && self.Pad == other.Pad
                    }
                }
                impl ::std::cmp::Eq for DNS_SRV_DATAW {}
                unsafe impl ::windows::Abi for DNS_SRV_DATAW {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_TKEY_DATAA {
                    pub pNameAlgorithm: super::super::Foundation::PSTR,
                    pub pAlgorithmPacket: *mut u8,
                    pub pKey: *mut u8,
                    pub pOtherData: *mut u8,
                    pub dwCreateTime: u32,
                    pub dwExpireTime: u32,
                    pub wMode: u16,
                    pub wError: u16,
                    pub wKeyLength: u16,
                    pub wOtherLength: u16,
                    pub cAlgNameLength: u8,
                    pub bPacketPointers: super::super::Foundation::BOOL,
                }
                impl DNS_TKEY_DATAA {}
                impl ::std::default::Default for DNS_TKEY_DATAA {
                    fn default() -> Self {
                        Self {
                            pNameAlgorithm: ::std::default::Default::default(),
                            pAlgorithmPacket: ::std::ptr::null_mut(),
                            pKey: ::std::ptr::null_mut(),
                            pOtherData: ::std::ptr::null_mut(),
                            dwCreateTime: 0,
                            dwExpireTime: 0,
                            wMode: 0,
                            wError: 0,
                            wKeyLength: 0,
                            wOtherLength: 0,
                            cAlgNameLength: 0,
                            bPacketPointers: ::std::default::Default::default(
                            ),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_TKEY_DATAA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_TKEY_DATAA")
                            .field("pNameAlgorithm", &self.pNameAlgorithm)
                            .field("pAlgorithmPacket", &self.pAlgorithmPacket)
                            .field("pKey", &self.pKey)
                            .field("pOtherData", &self.pOtherData)
                            .field("dwCreateTime", &self.dwCreateTime)
                            .field("dwExpireTime", &self.dwExpireTime)
                            .field("wMode", &self.wMode)
                            .field("wError", &self.wError)
                            .field("wKeyLength", &self.wKeyLength)
                            .field("wOtherLength", &self.wOtherLength)
                            .field("cAlgNameLength", &self.cAlgNameLength)
                            .field("bPacketPointers", &self.bPacketPointers)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_TKEY_DATAA {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNameAlgorithm == other.pNameAlgorithm
                            && self.pAlgorithmPacket == other.pAlgorithmPacket
                            && self.pKey == other.pKey
                            && self.pOtherData == other.pOtherData
                            && self.dwCreateTime == other.dwCreateTime
                            && self.dwExpireTime == other.dwExpireTime
                            && self.wMode == other.wMode
                            && self.wError == other.wError
                            && self.wKeyLength == other.wKeyLength
                            && self.wOtherLength == other.wOtherLength
                            && self.cAlgNameLength == other.cAlgNameLength
                            && self.bPacketPointers == other.bPacketPointers
                    }
                }
                impl ::std::cmp::Eq for DNS_TKEY_DATAA {}
                unsafe impl ::windows::Abi for DNS_TKEY_DATAA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_TKEY_DATAW {
                    pub pNameAlgorithm: super::super::Foundation::PWSTR,
                    pub pAlgorithmPacket: *mut u8,
                    pub pKey: *mut u8,
                    pub pOtherData: *mut u8,
                    pub dwCreateTime: u32,
                    pub dwExpireTime: u32,
                    pub wMode: u16,
                    pub wError: u16,
                    pub wKeyLength: u16,
                    pub wOtherLength: u16,
                    pub cAlgNameLength: u8,
                    pub bPacketPointers: super::super::Foundation::BOOL,
                }
                impl DNS_TKEY_DATAW {}
                impl ::std::default::Default for DNS_TKEY_DATAW {
                    fn default() -> Self {
                        Self {
                            pNameAlgorithm: ::std::default::Default::default(),
                            pAlgorithmPacket: ::std::ptr::null_mut(),
                            pKey: ::std::ptr::null_mut(),
                            pOtherData: ::std::ptr::null_mut(),
                            dwCreateTime: 0,
                            dwExpireTime: 0,
                            wMode: 0,
                            wError: 0,
                            wKeyLength: 0,
                            wOtherLength: 0,
                            cAlgNameLength: 0,
                            bPacketPointers: ::std::default::Default::default(
                            ),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_TKEY_DATAW {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_TKEY_DATAW")
                            .field("pNameAlgorithm", &self.pNameAlgorithm)
                            .field("pAlgorithmPacket", &self.pAlgorithmPacket)
                            .field("pKey", &self.pKey)
                            .field("pOtherData", &self.pOtherData)
                            .field("dwCreateTime", &self.dwCreateTime)
                            .field("dwExpireTime", &self.dwExpireTime)
                            .field("wMode", &self.wMode)
                            .field("wError", &self.wError)
                            .field("wKeyLength", &self.wKeyLength)
                            .field("wOtherLength", &self.wOtherLength)
                            .field("cAlgNameLength", &self.cAlgNameLength)
                            .field("bPacketPointers", &self.bPacketPointers)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_TKEY_DATAW {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNameAlgorithm == other.pNameAlgorithm
                            && self.pAlgorithmPacket == other.pAlgorithmPacket
                            && self.pKey == other.pKey
                            && self.pOtherData == other.pOtherData
                            && self.dwCreateTime == other.dwCreateTime
                            && self.dwExpireTime == other.dwExpireTime
                            && self.wMode == other.wMode
                            && self.wError == other.wError
                            && self.wKeyLength == other.wKeyLength
                            && self.wOtherLength == other.wOtherLength
                            && self.cAlgNameLength == other.cAlgNameLength
                            && self.bPacketPointers == other.bPacketPointers
                    }
                }
                impl ::std::cmp::Eq for DNS_TKEY_DATAW {}
                unsafe impl ::windows::Abi for DNS_TKEY_DATAW {
                    type Abi = Self;
                }
                pub const DNS_TKEY_MODE_DIFFIE_HELLMAN: u32 = 2u32;
                pub const DNS_TKEY_MODE_GSS: u32 = 3u32;
                pub const DNS_TKEY_MODE_RESOLVER_ASSIGN: u32 = 4u32;
                pub const DNS_TKEY_MODE_SERVER_ASSIGN: u32 = 1u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_TLSA_DATA {
                    pub bCertUsage: u8,
                    pub bSelector: u8,
                    pub bMatchingType: u8,
                    pub bCertificateAssociationDataLength: u16,
                    pub bPad: [u8; 3],
                    pub bCertificateAssociationData: [u8; 1],
                }
                impl DNS_TLSA_DATA {}
                impl ::std::default::Default for DNS_TLSA_DATA {
                    fn default() -> Self {
                        Self {
                            bCertUsage: 0,
                            bSelector: 0,
                            bMatchingType: 0,
                            bCertificateAssociationDataLength: 0,
                            bPad: [0; 3],
                            bCertificateAssociationData: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_TLSA_DATA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_TLSA_DATA")
                            .field("bCertUsage", &self.bCertUsage)
                            .field("bSelector", &self.bSelector)
                            .field("bMatchingType", &self.bMatchingType)
                            .field(
                                "bCertificateAssociationDataLength",
                                &self.bCertificateAssociationDataLength,
                            )
                            .field("bPad", &self.bPad)
                            .field(
                                "bCertificateAssociationData",
                                &self.bCertificateAssociationData,
                            )
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_TLSA_DATA {
                    fn eq(&self, other: &Self) -> bool {
                        self.bCertUsage == other.bCertUsage
                            && self.bSelector == other.bSelector
                            && self.bMatchingType == other.bMatchingType
                            && self.bCertificateAssociationDataLength
                                == other.bCertificateAssociationDataLength
                            && self.bPad == other.bPad
                            && self.bCertificateAssociationData
                                == other.bCertificateAssociationData
                    }
                }
                impl ::std::cmp::Eq for DNS_TLSA_DATA {}
                unsafe impl ::windows::Abi for DNS_TLSA_DATA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_TSIG_DATAA {
                    pub pNameAlgorithm: super::super::Foundation::PSTR,
                    pub pAlgorithmPacket: *mut u8,
                    pub pSignature: *mut u8,
                    pub pOtherData: *mut u8,
                    pub i64CreateTime: i64,
                    pub wFudgeTime: u16,
                    pub wOriginalXid: u16,
                    pub wError: u16,
                    pub wSigLength: u16,
                    pub wOtherLength: u16,
                    pub cAlgNameLength: u8,
                    pub bPacketPointers: super::super::Foundation::BOOL,
                }
                impl DNS_TSIG_DATAA {}
                impl ::std::default::Default for DNS_TSIG_DATAA {
                    fn default() -> Self {
                        Self {
                            pNameAlgorithm: ::std::default::Default::default(),
                            pAlgorithmPacket: ::std::ptr::null_mut(),
                            pSignature: ::std::ptr::null_mut(),
                            pOtherData: ::std::ptr::null_mut(),
                            i64CreateTime: 0,
                            wFudgeTime: 0,
                            wOriginalXid: 0,
                            wError: 0,
                            wSigLength: 0,
                            wOtherLength: 0,
                            cAlgNameLength: 0,
                            bPacketPointers: ::std::default::Default::default(
                            ),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_TSIG_DATAA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_TSIG_DATAA")
                            .field("pNameAlgorithm", &self.pNameAlgorithm)
                            .field("pAlgorithmPacket", &self.pAlgorithmPacket)
                            .field("pSignature", &self.pSignature)
                            .field("pOtherData", &self.pOtherData)
                            .field("i64CreateTime", &self.i64CreateTime)
                            .field("wFudgeTime", &self.wFudgeTime)
                            .field("wOriginalXid", &self.wOriginalXid)
                            .field("wError", &self.wError)
                            .field("wSigLength", &self.wSigLength)
                            .field("wOtherLength", &self.wOtherLength)
                            .field("cAlgNameLength", &self.cAlgNameLength)
                            .field("bPacketPointers", &self.bPacketPointers)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_TSIG_DATAA {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNameAlgorithm == other.pNameAlgorithm
                            && self.pAlgorithmPacket == other.pAlgorithmPacket
                            && self.pSignature == other.pSignature
                            && self.pOtherData == other.pOtherData
                            && self.i64CreateTime == other.i64CreateTime
                            && self.wFudgeTime == other.wFudgeTime
                            && self.wOriginalXid == other.wOriginalXid
                            && self.wError == other.wError
                            && self.wSigLength == other.wSigLength
                            && self.wOtherLength == other.wOtherLength
                            && self.cAlgNameLength == other.cAlgNameLength
                            && self.bPacketPointers == other.bPacketPointers
                    }
                }
                impl ::std::cmp::Eq for DNS_TSIG_DATAA {}
                unsafe impl ::windows::Abi for DNS_TSIG_DATAA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_TSIG_DATAW {
                    pub pNameAlgorithm: super::super::Foundation::PWSTR,
                    pub pAlgorithmPacket: *mut u8,
                    pub pSignature: *mut u8,
                    pub pOtherData: *mut u8,
                    pub i64CreateTime: i64,
                    pub wFudgeTime: u16,
                    pub wOriginalXid: u16,
                    pub wError: u16,
                    pub wSigLength: u16,
                    pub wOtherLength: u16,
                    pub cAlgNameLength: u8,
                    pub bPacketPointers: super::super::Foundation::BOOL,
                }
                impl DNS_TSIG_DATAW {}
                impl ::std::default::Default for DNS_TSIG_DATAW {
                    fn default() -> Self {
                        Self {
                            pNameAlgorithm: ::std::default::Default::default(),
                            pAlgorithmPacket: ::std::ptr::null_mut(),
                            pSignature: ::std::ptr::null_mut(),
                            pOtherData: ::std::ptr::null_mut(),
                            i64CreateTime: 0,
                            wFudgeTime: 0,
                            wOriginalXid: 0,
                            wError: 0,
                            wSigLength: 0,
                            wOtherLength: 0,
                            cAlgNameLength: 0,
                            bPacketPointers: ::std::default::Default::default(
                            ),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_TSIG_DATAW {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_TSIG_DATAW")
                            .field("pNameAlgorithm", &self.pNameAlgorithm)
                            .field("pAlgorithmPacket", &self.pAlgorithmPacket)
                            .field("pSignature", &self.pSignature)
                            .field("pOtherData", &self.pOtherData)
                            .field("i64CreateTime", &self.i64CreateTime)
                            .field("wFudgeTime", &self.wFudgeTime)
                            .field("wOriginalXid", &self.wOriginalXid)
                            .field("wError", &self.wError)
                            .field("wSigLength", &self.wSigLength)
                            .field("wOtherLength", &self.wOtherLength)
                            .field("cAlgNameLength", &self.cAlgNameLength)
                            .field("bPacketPointers", &self.bPacketPointers)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_TSIG_DATAW {
                    fn eq(&self, other: &Self) -> bool {
                        self.pNameAlgorithm == other.pNameAlgorithm
                            && self.pAlgorithmPacket == other.pAlgorithmPacket
                            && self.pSignature == other.pSignature
                            && self.pOtherData == other.pOtherData
                            && self.i64CreateTime == other.i64CreateTime
                            && self.wFudgeTime == other.wFudgeTime
                            && self.wOriginalXid == other.wOriginalXid
                            && self.wError == other.wError
                            && self.wSigLength == other.wSigLength
                            && self.wOtherLength == other.wOtherLength
                            && self.cAlgNameLength == other.cAlgNameLength
                            && self.bPacketPointers == other.bPacketPointers
                    }
                }
                impl ::std::cmp::Eq for DNS_TSIG_DATAW {}
                unsafe impl ::windows::Abi for DNS_TSIG_DATAW {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_TXT_DATAA {
                    pub dwStringCount: u32,
                    pub pStringArray: [super::super::Foundation::PSTR; 1],
                }
                impl DNS_TXT_DATAA {}
                impl ::std::default::Default for DNS_TXT_DATAA {
                    fn default() -> Self {
                        Self {
                            dwStringCount: 0,
                            pStringArray: [::std::default::Default::default();
                                1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_TXT_DATAA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_TXT_DATAA")
                            .field("dwStringCount", &self.dwStringCount)
                            .field("pStringArray", &self.pStringArray)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_TXT_DATAA {
                    fn eq(&self, other: &Self) -> bool {
                        self.dwStringCount == other.dwStringCount
                            && self.pStringArray == other.pStringArray
                    }
                }
                impl ::std::cmp::Eq for DNS_TXT_DATAA {}
                unsafe impl ::windows::Abi for DNS_TXT_DATAA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_TXT_DATAW {
                    pub dwStringCount: u32,
                    pub pStringArray: [super::super::Foundation::PWSTR; 1],
                }
                impl DNS_TXT_DATAW {}
                impl ::std::default::Default for DNS_TXT_DATAW {
                    fn default() -> Self {
                        Self {
                            dwStringCount: 0,
                            pStringArray: [::std::default::Default::default();
                                1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_TXT_DATAW {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_TXT_DATAW")
                            .field("dwStringCount", &self.dwStringCount)
                            .field("pStringArray", &self.pStringArray)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_TXT_DATAW {
                    fn eq(&self, other: &Self) -> bool {
                        self.dwStringCount == other.dwStringCount
                            && self.pStringArray == other.pStringArray
                    }
                }
                impl ::std::cmp::Eq for DNS_TXT_DATAW {}
                unsafe impl ::windows::Abi for DNS_TXT_DATAW {
                    type Abi = Self;
                }
                pub const DNS_TYPE_A: u32 = 1u32;
                pub const DNS_TYPE_A6: u32 = 38u32;
                pub const DNS_TYPE_AAAA: u32 = 28u32;
                pub const DNS_TYPE_ADDRS: u32 = 248u32;
                pub const DNS_TYPE_AFSDB: u32 = 18u32;
                pub const DNS_TYPE_ALL: u32 = 255u32;
                pub const DNS_TYPE_ANY: u32 = 255u32;
                pub const DNS_TYPE_ATMA: u32 = 34u32;
                pub const DNS_TYPE_AXFR: u32 = 252u32;
                pub const DNS_TYPE_CERT: u32 = 37u32;
                pub const DNS_TYPE_CNAME: u32 = 5u32;
                pub const DNS_TYPE_DHCID: u32 = 49u32;
                pub const DNS_TYPE_DNAME: u32 = 39u32;
                pub const DNS_TYPE_DNSKEY: u32 = 48u32;
                pub const DNS_TYPE_DS: u32 = 43u32;
                pub const DNS_TYPE_EID: u32 = 31u32;
                pub const DNS_TYPE_GID: u32 = 102u32;
                pub const DNS_TYPE_GPOS: u32 = 27u32;
                pub const DNS_TYPE_HINFO: u32 = 13u32;
                pub const DNS_TYPE_ISDN: u32 = 20u32;
                pub const DNS_TYPE_IXFR: u32 = 251u32;
                pub const DNS_TYPE_KEY: u32 = 25u32;
                pub const DNS_TYPE_KX: u32 = 36u32;
                pub const DNS_TYPE_LOC: u32 = 29u32;
                pub const DNS_TYPE_MAILA: u32 = 254u32;
                pub const DNS_TYPE_MAILB: u32 = 253u32;
                pub const DNS_TYPE_MB: u32 = 7u32;
                pub const DNS_TYPE_MD: u32 = 3u32;
                pub const DNS_TYPE_MF: u32 = 4u32;
                pub const DNS_TYPE_MG: u32 = 8u32;
                pub const DNS_TYPE_MINFO: u32 = 14u32;
                pub const DNS_TYPE_MR: u32 = 9u32;
                pub const DNS_TYPE_MX: u32 = 15u32;
                pub const DNS_TYPE_NAPTR: u32 = 35u32;
                pub const DNS_TYPE_NIMLOC: u32 = 32u32;
                pub const DNS_TYPE_NS: u32 = 2u32;
                pub const DNS_TYPE_NSAP: u32 = 22u32;
                pub const DNS_TYPE_NSAPPTR: u32 = 23u32;
                pub const DNS_TYPE_NSEC: u32 = 47u32;
                pub const DNS_TYPE_NSEC3: u32 = 50u32;
                pub const DNS_TYPE_NSEC3PARAM: u32 = 51u32;
                pub const DNS_TYPE_NULL: u32 = 10u32;
                pub const DNS_TYPE_NXT: u32 = 30u32;
                pub const DNS_TYPE_OPT: u32 = 41u32;
                pub const DNS_TYPE_PTR: u32 = 12u32;
                pub const DNS_TYPE_PX: u32 = 26u32;
                pub const DNS_TYPE_RP: u32 = 17u32;
                pub const DNS_TYPE_RRSIG: u32 = 46u32;
                pub const DNS_TYPE_RT: u32 = 21u32;
                pub const DNS_TYPE_SIG: u32 = 24u32;
                pub const DNS_TYPE_SINK: u32 = 40u32;
                pub const DNS_TYPE_SOA: u32 = 6u32;
                pub const DNS_TYPE_SRV: u32 = 33u32;
                pub const DNS_TYPE_TEXT: u32 = 16u32;
                pub const DNS_TYPE_TKEY: u32 = 249u32;
                pub const DNS_TYPE_TLSA: u32 = 52u32;
                pub const DNS_TYPE_TSIG: u32 = 250u32;
                pub const DNS_TYPE_UID: u32 = 101u32;
                pub const DNS_TYPE_UINFO: u32 = 100u32;
                pub const DNS_TYPE_UNSPEC: u32 = 103u32;
                pub const DNS_TYPE_WINS: u32 = 65281u32;
                pub const DNS_TYPE_WINSR: u32 = 65282u32;
                pub const DNS_TYPE_WKS: u32 = 11u32;
                pub const DNS_TYPE_X25: u32 = 19u32;
                pub const DNS_TYPE_ZERO: u32 = 0u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_UNKNOWN_DATA {
                    pub dwByteCount: u32,
                    pub bData: [u8; 1],
                }
                impl DNS_UNKNOWN_DATA {}
                impl ::std::default::Default for DNS_UNKNOWN_DATA {
                    fn default() -> Self {
                        Self {
                            dwByteCount: 0,
                            bData: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_UNKNOWN_DATA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_UNKNOWN_DATA")
                            .field("dwByteCount", &self.dwByteCount)
                            .field("bData", &self.bData)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_UNKNOWN_DATA {
                    fn eq(&self, other: &Self) -> bool {
                        self.dwByteCount == other.dwByteCount
                            && self.bData == other.bData
                    }
                }
                impl ::std::cmp::Eq for DNS_UNKNOWN_DATA {}
                unsafe impl ::windows::Abi for DNS_UNKNOWN_DATA {
                    type Abi = Self;
                }
                pub const DNS_UPDATE_CACHE_SECURITY_CONTEXT: u32 = 512u32;
                pub const DNS_UPDATE_FORCE_SECURITY_NEGO: u32 = 2048u32;
                pub const DNS_UPDATE_REMOTE_SERVER: u32 = 16384u32;
                pub const DNS_UPDATE_RESERVED: u32 = 4294901760u32;
                pub const DNS_UPDATE_SECURITY_OFF: u32 = 16u32;
                pub const DNS_UPDATE_SECURITY_ON: u32 = 32u32;
                pub const DNS_UPDATE_SECURITY_ONLY: u32 = 256u32;
                pub const DNS_UPDATE_SECURITY_USE_DEFAULT: u32 = 0u32;
                pub const DNS_UPDATE_SKIP_NO_UPDATE_ADAPTERS: u32 = 8192u32;
                pub const DNS_UPDATE_TEST_USE_LOCAL_SYS_ACCT: u32 = 1024u32;
                pub const DNS_UPDATE_TRY_ALL_MASTER_SERVERS: u32 = 4096u32;
                pub const DNS_VALSVR_ERROR_INVALID_ADDR: u32 = 1u32;
                pub const DNS_VALSVR_ERROR_INVALID_NAME: u32 = 2u32;
                pub const DNS_VALSVR_ERROR_NO_AUTH: u32 = 5u32;
                pub const DNS_VALSVR_ERROR_NO_RESPONSE: u32 = 4u32;
                pub const DNS_VALSVR_ERROR_NO_TCP: u32 = 16u32;
                pub const DNS_VALSVR_ERROR_REFUSED: u32 = 6u32;
                pub const DNS_VALSVR_ERROR_UNKNOWN: u32 = 255u32;
                pub const DNS_VALSVR_ERROR_UNREACHABLE: u32 = 3u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_WINSR_DATAA {
                    pub dwMappingFlag: u32,
                    pub dwLookupTimeout: u32,
                    pub dwCacheTimeout: u32,
                    pub pNameResultDomain: super::super::Foundation::PSTR,
                }
                impl DNS_WINSR_DATAA {}
                impl ::std::default::Default for DNS_WINSR_DATAA {
                    fn default() -> Self {
                        Self {
                            dwMappingFlag: 0,
                            dwLookupTimeout: 0,
                            dwCacheTimeout: 0,
                            pNameResultDomain:
                                ::std::default::Default::default(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_WINSR_DATAA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_WINSR_DATAA")
                            .field("dwMappingFlag", &self.dwMappingFlag)
                            .field("dwLookupTimeout", &self.dwLookupTimeout)
                            .field("dwCacheTimeout", &self.dwCacheTimeout)
                            .field(
                                "pNameResultDomain",
                                &self.pNameResultDomain,
                            )
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_WINSR_DATAA {
                    fn eq(&self, other: &Self) -> bool {
                        self.dwMappingFlag == other.dwMappingFlag
                            && self.dwLookupTimeout == other.dwLookupTimeout
                            && self.dwCacheTimeout == other.dwCacheTimeout
                            && self.pNameResultDomain
                                == other.pNameResultDomain
                    }
                }
                impl ::std::cmp::Eq for DNS_WINSR_DATAA {}
                unsafe impl ::windows::Abi for DNS_WINSR_DATAA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_WINSR_DATAW {
                    pub dwMappingFlag: u32,
                    pub dwLookupTimeout: u32,
                    pub dwCacheTimeout: u32,
                    pub pNameResultDomain: super::super::Foundation::PWSTR,
                }
                impl DNS_WINSR_DATAW {}
                impl ::std::default::Default for DNS_WINSR_DATAW {
                    fn default() -> Self {
                        Self {
                            dwMappingFlag: 0,
                            dwLookupTimeout: 0,
                            dwCacheTimeout: 0,
                            pNameResultDomain:
                                ::std::default::Default::default(),
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_WINSR_DATAW {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_WINSR_DATAW")
                            .field("dwMappingFlag", &self.dwMappingFlag)
                            .field("dwLookupTimeout", &self.dwLookupTimeout)
                            .field("dwCacheTimeout", &self.dwCacheTimeout)
                            .field(
                                "pNameResultDomain",
                                &self.pNameResultDomain,
                            )
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_WINSR_DATAW {
                    fn eq(&self, other: &Self) -> bool {
                        self.dwMappingFlag == other.dwMappingFlag
                            && self.dwLookupTimeout == other.dwLookupTimeout
                            && self.dwCacheTimeout == other.dwCacheTimeout
                            && self.pNameResultDomain
                                == other.pNameResultDomain
                    }
                }
                impl ::std::cmp::Eq for DNS_WINSR_DATAW {}
                unsafe impl ::windows::Abi for DNS_WINSR_DATAW {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_WINS_DATA {
                    pub dwMappingFlag: u32,
                    pub dwLookupTimeout: u32,
                    pub dwCacheTimeout: u32,
                    pub cWinsServerCount: u32,
                    pub WinsServers: [u32; 1],
                }
                impl DNS_WINS_DATA {}
                impl ::std::default::Default for DNS_WINS_DATA {
                    fn default() -> Self {
                        Self {
                            dwMappingFlag: 0,
                            dwLookupTimeout: 0,
                            dwCacheTimeout: 0,
                            cWinsServerCount: 0,
                            WinsServers: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_WINS_DATA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_WINS_DATA")
                            .field("dwMappingFlag", &self.dwMappingFlag)
                            .field("dwLookupTimeout", &self.dwLookupTimeout)
                            .field("dwCacheTimeout", &self.dwCacheTimeout)
                            .field("cWinsServerCount", &self.cWinsServerCount)
                            .field("WinsServers", &self.WinsServers)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_WINS_DATA {
                    fn eq(&self, other: &Self) -> bool {
                        self.dwMappingFlag == other.dwMappingFlag
                            && self.dwLookupTimeout == other.dwLookupTimeout
                            && self.dwCacheTimeout == other.dwCacheTimeout
                            && self.cWinsServerCount == other.cWinsServerCount
                            && self.WinsServers == other.WinsServers
                    }
                }
                impl ::std::cmp::Eq for DNS_WINS_DATA {}
                unsafe impl ::windows::Abi for DNS_WINS_DATA {
                    type Abi = Self;
                }
                pub const DNS_WINS_FLAG_LOCAL: u32 = 65536u32;
                pub const DNS_WINS_FLAG_SCOPE: u32 = 2147483648u32;
                #[repr(C, packed(1))]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_WIRE_QUESTION {
                    pub QuestionType: u16,
                    pub QuestionClass: u16,
                }
                impl DNS_WIRE_QUESTION {}
                unsafe impl ::windows::Abi for DNS_WIRE_QUESTION {
                    type Abi = Self;
                }
                #[repr(C, packed(1))]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_WIRE_RECORD {
                    pub RecordType: u16,
                    pub RecordClass: u16,
                    pub TimeToLive: u32,
                    pub DataLength: u16,
                }
                impl DNS_WIRE_RECORD {}
                unsafe impl ::windows::Abi for DNS_WIRE_RECORD {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DNS_WKS_DATA {
                    pub IpAddress: u32,
                    pub chProtocol: u8,
                    pub BitMask: [u8; 1],
                }
                impl DNS_WKS_DATA {}
                impl ::std::default::Default for DNS_WKS_DATA {
                    fn default() -> Self {
                        Self {
                            IpAddress: 0,
                            chProtocol: 0,
                            BitMask: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for DNS_WKS_DATA {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DNS_WKS_DATA")
                            .field("IpAddress", &self.IpAddress)
                            .field("chProtocol", &self.chProtocol)
                            .field("BitMask", &self.BitMask)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DNS_WKS_DATA {
                    fn eq(&self, other: &Self) -> bool {
                        self.IpAddress == other.IpAddress
                            && self.chProtocol == other.chProtocol
                            && self.BitMask == other.BitMask
                    }
                }
                impl ::std::cmp::Eq for DNS_WKS_DATA {}
                unsafe impl ::windows::Abi for DNS_WKS_DATA {
                    type Abi = Self;
                }
                pub unsafe fn DnsAcquireContextHandle_A(
                    credentialflags: u32,
                    credentials: *mut ::std::ffi::c_void,
                    pcontext: *mut DnsContextHandle,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsAcquireContextHandle_A(
                                credentialflags: u32,
                                credentials: *mut ::std::ffi::c_void,
                                pcontext: *mut DnsContextHandle,
                            ) -> i32;
                        }
                        DnsAcquireContextHandle_A(
                            ::std::mem::transmute(credentialflags),
                            ::std::mem::transmute(credentials),
                            ::std::mem::transmute(pcontext),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsAcquireContextHandle_W(
                    credentialflags: u32,
                    credentials: *mut ::std::ffi::c_void,
                    pcontext: *mut DnsContextHandle,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsAcquireContextHandle_W(
                                credentialflags: u32,
                                credentials: *mut ::std::ffi::c_void,
                                pcontext: *mut DnsContextHandle,
                            ) -> i32;
                        }
                        DnsAcquireContextHandle_W(
                            ::std::mem::transmute(credentialflags),
                            ::std::mem::transmute(credentials),
                            ::std::mem::transmute(pcontext),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsCancelQuery(
                    pcancelhandle: *mut DNS_QUERY_CANCEL,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsCancelQuery(
                                pcancelhandle: *mut DNS_QUERY_CANCEL,
                            ) -> i32;
                        }
                        DnsCancelQuery(::std::mem::transmute(pcancelhandle))
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsConnectionDeletePolicyEntries(
                    policyentrytag: DNS_CONNECTION_POLICY_TAG,
                ) -> u32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsConnectionDeletePolicyEntries(
                                policyentrytag: DNS_CONNECTION_POLICY_TAG,
                            ) -> u32;
                        }
                        DnsConnectionDeletePolicyEntries(
                            ::std::mem::transmute(policyentrytag),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsConnectionDeleteProxyInfo<'a>(
                    pwszconnectionname: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PWSTR,
                    >,
                    r#type: DNS_CONNECTION_PROXY_TYPE,
                ) -> u32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsConnectionDeleteProxyInfo(
                                pwszconnectionname : super::super::Foundation:: PWSTR,
                                r#type: DNS_CONNECTION_PROXY_TYPE,
                            ) -> u32;
                        }
                        DnsConnectionDeleteProxyInfo(
                            pwszconnectionname.into_param().abi(),
                            ::std::mem::transmute(r#type),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsConnectionFreeNameList(
                    pnamelist: *mut DNS_CONNECTION_NAME_LIST,
                ) {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsConnectionFreeNameList(
                                pnamelist: *mut DNS_CONNECTION_NAME_LIST,
                            );
                        }
                        DnsConnectionFreeNameList(::std::mem::transmute(
                            pnamelist,
                        ))
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsConnectionFreeProxyInfo(
                    pproxyinfo: *mut DNS_CONNECTION_PROXY_INFO,
                ) {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsConnectionFreeProxyInfo(
                                pproxyinfo: *mut DNS_CONNECTION_PROXY_INFO,
                            );
                        }
                        DnsConnectionFreeProxyInfo(::std::mem::transmute(
                            pproxyinfo,
                        ))
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsConnectionFreeProxyInfoEx(
                    pproxyinfoex: *mut DNS_CONNECTION_PROXY_INFO_EX,
                ) {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsConnectionFreeProxyInfoEx(
                                pproxyinfoex : * mut DNS_CONNECTION_PROXY_INFO_EX,
                            );
                        }
                        DnsConnectionFreeProxyInfoEx(::std::mem::transmute(
                            pproxyinfoex,
                        ))
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsConnectionFreeProxyList(
                    pproxylist: *mut DNS_CONNECTION_PROXY_LIST,
                ) {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsConnectionFreeProxyList(
                                pproxylist: *mut DNS_CONNECTION_PROXY_LIST,
                            );
                        }
                        DnsConnectionFreeProxyList(::std::mem::transmute(
                            pproxylist,
                        ))
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsConnectionGetNameList(
                    pnamelist: *mut DNS_CONNECTION_NAME_LIST,
                ) -> u32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsConnectionGetNameList(
                                pnamelist: *mut DNS_CONNECTION_NAME_LIST,
                            ) -> u32;
                        }
                        DnsConnectionGetNameList(::std::mem::transmute(
                            pnamelist,
                        ))
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsConnectionGetProxyInfo<'a>(
                    pwszconnectionname: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PWSTR,
                    >,
                    r#type: DNS_CONNECTION_PROXY_TYPE,
                    pproxyinfo: *mut DNS_CONNECTION_PROXY_INFO,
                ) -> u32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsConnectionGetProxyInfo(
                                pwszconnectionname : super::super::Foundation:: PWSTR,
                                r#type: DNS_CONNECTION_PROXY_TYPE,
                                pproxyinfo: *mut DNS_CONNECTION_PROXY_INFO,
                            ) -> u32;
                        }
                        DnsConnectionGetProxyInfo(
                            pwszconnectionname.into_param().abi(),
                            ::std::mem::transmute(r#type),
                            ::std::mem::transmute(pproxyinfo),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsConnectionGetProxyInfoForHostUrl<'a>(
                    pwszhosturl: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PWSTR,
                    >,
                    pselectioncontext: *mut u8,
                    dwselectioncontextlength: u32,
                    dwexplicitinterfaceindex: u32,
                    pproxyinfoex: *mut DNS_CONNECTION_PROXY_INFO_EX,
                ) -> u32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsConnectionGetProxyInfoForHostUrl(
                                pwszhosturl: super::super::Foundation::PWSTR,
                                pselectioncontext: *mut u8,
                                dwselectioncontextlength: u32,
                                dwexplicitinterfaceindex: u32,
                                pproxyinfoex : * mut DNS_CONNECTION_PROXY_INFO_EX,
                            ) -> u32;
                        }
                        DnsConnectionGetProxyInfoForHostUrl(
                            pwszhosturl.into_param().abi(),
                            ::std::mem::transmute(pselectioncontext),
                            ::std::mem::transmute(dwselectioncontextlength),
                            ::std::mem::transmute(dwexplicitinterfaceindex),
                            ::std::mem::transmute(pproxyinfoex),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsConnectionGetProxyList<'a>(
                    pwszconnectionname: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PWSTR,
                    >,
                    pproxylist: *mut DNS_CONNECTION_PROXY_LIST,
                ) -> u32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsConnectionGetProxyList(
                                pwszconnectionname : super::super::Foundation:: PWSTR,
                                pproxylist: *mut DNS_CONNECTION_PROXY_LIST,
                            ) -> u32;
                        }
                        DnsConnectionGetProxyList(
                            pwszconnectionname.into_param().abi(),
                            ::std::mem::transmute(pproxylist),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsConnectionSetPolicyEntries(
                    policyentrytag: DNS_CONNECTION_POLICY_TAG,
                    ppolicyentrylist: *mut DNS_CONNECTION_POLICY_ENTRY_LIST,
                ) -> u32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsConnectionSetPolicyEntries(
                                policyentrytag: DNS_CONNECTION_POLICY_TAG,
                                ppolicyentrylist : * mut DNS_CONNECTION_POLICY_ENTRY_LIST,
                            ) -> u32;
                        }
                        DnsConnectionSetPolicyEntries(
                            ::std::mem::transmute(policyentrytag),
                            ::std::mem::transmute(ppolicyentrylist),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsConnectionSetProxyInfo<'a>(
                    pwszconnectionname: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PWSTR,
                    >,
                    r#type: DNS_CONNECTION_PROXY_TYPE,
                    pproxyinfo: *const DNS_CONNECTION_PROXY_INFO,
                ) -> u32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsConnectionSetProxyInfo(
                                pwszconnectionname : super::super::Foundation:: PWSTR,
                                r#type: DNS_CONNECTION_PROXY_TYPE,
                                pproxyinfo: *const DNS_CONNECTION_PROXY_INFO,
                            ) -> u32;
                        }
                        DnsConnectionSetProxyInfo(
                            pwszconnectionname.into_param().abi(),
                            ::std::mem::transmute(r#type),
                            ::std::mem::transmute(pproxyinfo),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsConnectionUpdateIfIndexTable(
                    pconnectionifindexentries : * mut DNS_CONNECTION_IFINDEX_LIST,
                ) -> u32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsConnectionUpdateIfIndexTable(
                                pconnectionifindexentries : * mut DNS_CONNECTION_IFINDEX_LIST,
                            ) -> u32;
                        }
                        DnsConnectionUpdateIfIndexTable(::std::mem::transmute(
                            pconnectionifindexentries,
                        ))
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                #[repr(transparent)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct DnsContextHandle(pub isize);
                impl DnsContextHandle {}
                impl ::std::default::Default for DnsContextHandle {
                    fn default() -> Self {
                        Self(0)
                    }
                }
                impl DnsContextHandle {
                    pub const NULL: Self = Self(0);
                    pub fn is_null(&self) -> bool {
                        self.0 == 0
                    }
                }
                impl ::std::fmt::Debug for DnsContextHandle {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("DnsContextHandle")
                            .field("Value", &self.0)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for DnsContextHandle {
                    fn eq(&self, other: &Self) -> bool {
                        self.0 == other.0
                    }
                }
                impl ::std::cmp::Eq for DnsContextHandle {}
                unsafe impl ::windows::Abi for DnsContextHandle {
                    type Abi = Self;
                }
                pub unsafe fn DnsExtractRecordsFromMessage_UTF8(
                    pdnsbuffer: *mut DNS_MESSAGE_BUFFER,
                    wmessagelength: u16,
                    pprecord: *mut *mut DNS_RECORDA,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsExtractRecordsFromMessage_UTF8(
                                pdnsbuffer: *mut DNS_MESSAGE_BUFFER,
                                wmessagelength: u16,
                                pprecord: *mut *mut DNS_RECORDA,
                            ) -> i32;
                        }
                        DnsExtractRecordsFromMessage_UTF8(
                            ::std::mem::transmute(pdnsbuffer),
                            ::std::mem::transmute(wmessagelength),
                            ::std::mem::transmute(pprecord),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsExtractRecordsFromMessage_W(
                    pdnsbuffer: *mut DNS_MESSAGE_BUFFER,
                    wmessagelength: u16,
                    pprecord: *mut *mut DNS_RECORDA,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsExtractRecordsFromMessage_W(
                                pdnsbuffer: *mut DNS_MESSAGE_BUFFER,
                                wmessagelength: u16,
                                pprecord: *mut *mut DNS_RECORDA,
                            ) -> i32;
                        }
                        DnsExtractRecordsFromMessage_W(
                            ::std::mem::transmute(pdnsbuffer),
                            ::std::mem::transmute(wmessagelength),
                            ::std::mem::transmute(pprecord),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsFree(
                    pdata: *mut ::std::ffi::c_void,
                    freetype: DNS_FREE_TYPE,
                ) {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsFree(
                                pdata: *mut ::std::ffi::c_void,
                                freetype: DNS_FREE_TYPE,
                            );
                        }
                        DnsFree(
                            ::std::mem::transmute(pdata),
                            ::std::mem::transmute(freetype),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsFreeProxyName(
                    proxyname: super::super::Foundation::PWSTR,
                ) {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsFreeProxyName(
                                proxyname: super::super::Foundation::PWSTR,
                            );
                        }
                        DnsFreeProxyName(::std::mem::transmute(proxyname))
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsGetProxyInformation<'a>(
                    hostname: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PWSTR,
                    >,
                    proxyinformation: *mut DNS_PROXY_INFORMATION,
                    defaultproxyinformation: *mut DNS_PROXY_INFORMATION,
                    completionroutine: ::std::option::Option<
                        DNS_PROXY_COMPLETION_ROUTINE,
                    >,
                    completioncontext: *mut ::std::ffi::c_void,
                ) -> u32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsGetProxyInformation(
                                hostname: super::super::Foundation::PWSTR,
                                proxyinformation: *mut DNS_PROXY_INFORMATION,
                                defaultproxyinformation : * mut DNS_PROXY_INFORMATION,
                                completionroutine: ::windows::RawPtr,
                                completioncontext: *mut ::std::ffi::c_void,
                            ) -> u32;
                        }
                        DnsGetProxyInformation(
                            hostname.into_param().abi(),
                            ::std::mem::transmute(proxyinformation),
                            ::std::mem::transmute(defaultproxyinformation),
                            ::std::mem::transmute(completionroutine),
                            ::std::mem::transmute(completioncontext),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsModifyRecordsInSet_A<'a>(
                    paddrecords: *mut DNS_RECORDA,
                    pdeleterecords: *mut DNS_RECORDA,
                    options: u32,
                    hcredentials: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::HANDLE,
                    >,
                    pextralist: *mut ::std::ffi::c_void,
                    preserved: *mut ::std::ffi::c_void,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsModifyRecordsInSet_A(
                                paddrecords: *mut DNS_RECORDA,
                                pdeleterecords: *mut DNS_RECORDA,
                                options: u32,
                                hcredentials: super::super::Foundation::HANDLE,
                                pextralist: *mut ::std::ffi::c_void,
                                preserved: *mut ::std::ffi::c_void,
                            ) -> i32;
                        }
                        DnsModifyRecordsInSet_A(
                            ::std::mem::transmute(paddrecords),
                            ::std::mem::transmute(pdeleterecords),
                            ::std::mem::transmute(options),
                            hcredentials.into_param().abi(),
                            ::std::mem::transmute(pextralist),
                            ::std::mem::transmute(preserved),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsModifyRecordsInSet_UTF8<'a>(
                    paddrecords: *mut DNS_RECORDA,
                    pdeleterecords: *mut DNS_RECORDA,
                    options: u32,
                    hcredentials: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::HANDLE,
                    >,
                    pextralist: *mut ::std::ffi::c_void,
                    preserved: *mut ::std::ffi::c_void,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsModifyRecordsInSet_UTF8(
                                paddrecords: *mut DNS_RECORDA,
                                pdeleterecords: *mut DNS_RECORDA,
                                options: u32,
                                hcredentials: super::super::Foundation::HANDLE,
                                pextralist: *mut ::std::ffi::c_void,
                                preserved: *mut ::std::ffi::c_void,
                            ) -> i32;
                        }
                        DnsModifyRecordsInSet_UTF8(
                            ::std::mem::transmute(paddrecords),
                            ::std::mem::transmute(pdeleterecords),
                            ::std::mem::transmute(options),
                            hcredentials.into_param().abi(),
                            ::std::mem::transmute(pextralist),
                            ::std::mem::transmute(preserved),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsModifyRecordsInSet_W<'a>(
                    paddrecords: *mut DNS_RECORDA,
                    pdeleterecords: *mut DNS_RECORDA,
                    options: u32,
                    hcredentials: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::HANDLE,
                    >,
                    pextralist: *mut ::std::ffi::c_void,
                    preserved: *mut ::std::ffi::c_void,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsModifyRecordsInSet_W(
                                paddrecords: *mut DNS_RECORDA,
                                pdeleterecords: *mut DNS_RECORDA,
                                options: u32,
                                hcredentials: super::super::Foundation::HANDLE,
                                pextralist: *mut ::std::ffi::c_void,
                                preserved: *mut ::std::ffi::c_void,
                            ) -> i32;
                        }
                        DnsModifyRecordsInSet_W(
                            ::std::mem::transmute(paddrecords),
                            ::std::mem::transmute(pdeleterecords),
                            ::std::mem::transmute(options),
                            hcredentials.into_param().abi(),
                            ::std::mem::transmute(pextralist),
                            ::std::mem::transmute(preserved),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsNameCompare_A<'a>(
                    pname1: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PSTR,
                    >,
                    pname2: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PSTR,
                    >,
                ) -> super::super::Foundation::BOOL {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsNameCompare_A(
                                pname1: super::super::Foundation::PSTR,
                                pname2: super::super::Foundation::PSTR,
                            ) -> super::super::Foundation::BOOL;
                        }
                        DnsNameCompare_A(
                            pname1.into_param().abi(),
                            pname2.into_param().abi(),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsNameCompare_W<'a>(
                    pname1: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PWSTR,
                    >,
                    pname2: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PWSTR,
                    >,
                ) -> super::super::Foundation::BOOL {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsNameCompare_W(
                                pname1: super::super::Foundation::PWSTR,
                                pname2: super::super::Foundation::PWSTR,
                            ) -> super::super::Foundation::BOOL;
                        }
                        DnsNameCompare_W(
                            pname1.into_param().abi(),
                            pname2.into_param().abi(),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsQueryConfig<'a>(
                    config: DNS_CONFIG_TYPE,
                    flag: u32,
                    pwsadaptername: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PWSTR,
                    >,
                    preserved: *mut ::std::ffi::c_void,
                    pbuffer: *mut ::std::ffi::c_void,
                    pbuflen: *mut u32,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsQueryConfig(
                                config: DNS_CONFIG_TYPE,
                                flag: u32,
                                pwsadaptername : super::super::Foundation:: PWSTR,
                                preserved: *mut ::std::ffi::c_void,
                                pbuffer: *mut ::std::ffi::c_void,
                                pbuflen: *mut u32,
                            ) -> i32;
                        }
                        DnsQueryConfig(
                            ::std::mem::transmute(config),
                            ::std::mem::transmute(flag),
                            pwsadaptername.into_param().abi(),
                            ::std::mem::transmute(preserved),
                            ::std::mem::transmute(pbuffer),
                            ::std::mem::transmute(pbuflen),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsQueryEx(
                    pqueryrequest: *mut DNS_QUERY_REQUEST,
                    pqueryresults: *mut DNS_QUERY_RESULT,
                    pcancelhandle: *mut DNS_QUERY_CANCEL,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsQueryEx(
                                pqueryrequest: *mut DNS_QUERY_REQUEST_abi,
                                pqueryresults: *mut DNS_QUERY_RESULT,
                                pcancelhandle: *mut DNS_QUERY_CANCEL,
                            ) -> i32;
                        }
                        DnsQueryEx(
                            ::std::mem::transmute(pqueryrequest),
                            ::std::mem::transmute(pqueryresults),
                            ::std::mem::transmute(pcancelhandle),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsQuery_A<'a>(
                    pszname: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PSTR,
                    >,
                    wtype: u16,
                    options: u32,
                    pextra: *mut ::std::ffi::c_void,
                    ppqueryresults: *mut *mut DNS_RECORDA,
                    preserved: *mut *mut ::std::ffi::c_void,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsQuery_A(
                                pszname: super::super::Foundation::PSTR,
                                wtype: u16,
                                options: u32,
                                pextra: *mut ::std::ffi::c_void,
                                ppqueryresults: *mut *mut DNS_RECORDA,
                                preserved: *mut *mut ::std::ffi::c_void,
                            ) -> i32;
                        }
                        DnsQuery_A(
                            pszname.into_param().abi(),
                            ::std::mem::transmute(wtype),
                            ::std::mem::transmute(options),
                            ::std::mem::transmute(pextra),
                            ::std::mem::transmute(ppqueryresults),
                            ::std::mem::transmute(preserved),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsQuery_UTF8<'a>(
                    pszname: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PSTR,
                    >,
                    wtype: u16,
                    options: u32,
                    pextra: *mut ::std::ffi::c_void,
                    ppqueryresults: *mut *mut DNS_RECORDA,
                    preserved: *mut *mut ::std::ffi::c_void,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsQuery_UTF8(
                                pszname: super::super::Foundation::PSTR,
                                wtype: u16,
                                options: u32,
                                pextra: *mut ::std::ffi::c_void,
                                ppqueryresults: *mut *mut DNS_RECORDA,
                                preserved: *mut *mut ::std::ffi::c_void,
                            ) -> i32;
                        }
                        DnsQuery_UTF8(
                            pszname.into_param().abi(),
                            ::std::mem::transmute(wtype),
                            ::std::mem::transmute(options),
                            ::std::mem::transmute(pextra),
                            ::std::mem::transmute(ppqueryresults),
                            ::std::mem::transmute(preserved),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsQuery_W<'a>(
                    pszname: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PWSTR,
                    >,
                    wtype: u16,
                    options: u32,
                    pextra: *mut ::std::ffi::c_void,
                    ppqueryresults: *mut *mut DNS_RECORDA,
                    preserved: *mut *mut ::std::ffi::c_void,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsQuery_W(
                                pszname: super::super::Foundation::PWSTR,
                                wtype: u16,
                                options: u32,
                                pextra: *mut ::std::ffi::c_void,
                                ppqueryresults: *mut *mut DNS_RECORDA,
                                preserved: *mut *mut ::std::ffi::c_void,
                            ) -> i32;
                        }
                        DnsQuery_W(
                            pszname.into_param().abi(),
                            ::std::mem::transmute(wtype),
                            ::std::mem::transmute(options),
                            ::std::mem::transmute(pextra),
                            ::std::mem::transmute(ppqueryresults),
                            ::std::mem::transmute(preserved),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsRecordCompare(
                    precord1: *mut DNS_RECORDA,
                    precord2: *mut DNS_RECORDA,
                ) -> super::super::Foundation::BOOL {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsRecordCompare(
                                precord1: *mut DNS_RECORDA,
                                precord2: *mut DNS_RECORDA,
                            ) -> super::super::Foundation::BOOL;
                        }
                        DnsRecordCompare(
                            ::std::mem::transmute(precord1),
                            ::std::mem::transmute(precord2),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsRecordCopyEx(
                    precord: *mut DNS_RECORDA,
                    charsetin: DNS_CHARSET,
                    charsetout: DNS_CHARSET,
                ) -> *mut DNS_RECORDA {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsRecordCopyEx(
                                precord: *mut DNS_RECORDA,
                                charsetin: DNS_CHARSET,
                                charsetout: DNS_CHARSET,
                            ) -> *mut DNS_RECORDA;
                        }
                        DnsRecordCopyEx(
                            ::std::mem::transmute(precord),
                            ::std::mem::transmute(charsetin),
                            ::std::mem::transmute(charsetout),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsRecordSetCompare(
                    prr1: *mut DNS_RECORDA,
                    prr2: *mut DNS_RECORDA,
                    ppdiff1: *mut *mut DNS_RECORDA,
                    ppdiff2: *mut *mut DNS_RECORDA,
                ) -> super::super::Foundation::BOOL {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsRecordSetCompare(
                                prr1: *mut DNS_RECORDA,
                                prr2: *mut DNS_RECORDA,
                                ppdiff1: *mut *mut DNS_RECORDA,
                                ppdiff2: *mut *mut DNS_RECORDA,
                            ) -> super::super::Foundation::BOOL;
                        }
                        DnsRecordSetCompare(
                            ::std::mem::transmute(prr1),
                            ::std::mem::transmute(prr2),
                            ::std::mem::transmute(ppdiff1),
                            ::std::mem::transmute(ppdiff2),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsRecordSetCopyEx(
                    precordset: *mut DNS_RECORDA,
                    charsetin: DNS_CHARSET,
                    charsetout: DNS_CHARSET,
                ) -> *mut DNS_RECORDA {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsRecordSetCopyEx(
                                precordset: *mut DNS_RECORDA,
                                charsetin: DNS_CHARSET,
                                charsetout: DNS_CHARSET,
                            ) -> *mut DNS_RECORDA;
                        }
                        DnsRecordSetCopyEx(
                            ::std::mem::transmute(precordset),
                            ::std::mem::transmute(charsetin),
                            ::std::mem::transmute(charsetout),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsRecordSetDetach(
                    precordlist: *mut DNS_RECORDA,
                ) -> *mut DNS_RECORDA {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsRecordSetDetach(
                                precordlist: *mut DNS_RECORDA,
                            ) -> *mut DNS_RECORDA;
                        }
                        DnsRecordSetDetach(::std::mem::transmute(precordlist))
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsReleaseContextHandle<'a>(
                    hcontext: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::HANDLE,
                    >,
                ) {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsReleaseContextHandle(
                                hcontext: super::super::Foundation::HANDLE,
                            );
                        }
                        DnsReleaseContextHandle(hcontext.into_param().abi())
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsReplaceRecordSetA<'a>(
                    preplaceset: *mut DNS_RECORDA,
                    options: u32,
                    hcontext: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::HANDLE,
                    >,
                    pextrainfo: *mut ::std::ffi::c_void,
                    preserved: *mut ::std::ffi::c_void,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsReplaceRecordSetA(
                                preplaceset: *mut DNS_RECORDA,
                                options: u32,
                                hcontext: super::super::Foundation::HANDLE,
                                pextrainfo: *mut ::std::ffi::c_void,
                                preserved: *mut ::std::ffi::c_void,
                            ) -> i32;
                        }
                        DnsReplaceRecordSetA(
                            ::std::mem::transmute(preplaceset),
                            ::std::mem::transmute(options),
                            hcontext.into_param().abi(),
                            ::std::mem::transmute(pextrainfo),
                            ::std::mem::transmute(preserved),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsReplaceRecordSetUTF8<'a>(
                    preplaceset: *mut DNS_RECORDA,
                    options: u32,
                    hcontext: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::HANDLE,
                    >,
                    pextrainfo: *mut ::std::ffi::c_void,
                    preserved: *mut ::std::ffi::c_void,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsReplaceRecordSetUTF8(
                                preplaceset: *mut DNS_RECORDA,
                                options: u32,
                                hcontext: super::super::Foundation::HANDLE,
                                pextrainfo: *mut ::std::ffi::c_void,
                                preserved: *mut ::std::ffi::c_void,
                            ) -> i32;
                        }
                        DnsReplaceRecordSetUTF8(
                            ::std::mem::transmute(preplaceset),
                            ::std::mem::transmute(options),
                            hcontext.into_param().abi(),
                            ::std::mem::transmute(pextrainfo),
                            ::std::mem::transmute(preserved),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsReplaceRecordSetW<'a>(
                    preplaceset: *mut DNS_RECORDA,
                    options: u32,
                    hcontext: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::HANDLE,
                    >,
                    pextrainfo: *mut ::std::ffi::c_void,
                    preserved: *mut ::std::ffi::c_void,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsReplaceRecordSetW(
                                preplaceset: *mut DNS_RECORDA,
                                options: u32,
                                hcontext: super::super::Foundation::HANDLE,
                                pextrainfo: *mut ::std::ffi::c_void,
                                preserved: *mut ::std::ffi::c_void,
                            ) -> i32;
                        }
                        DnsReplaceRecordSetW(
                            ::std::mem::transmute(preplaceset),
                            ::std::mem::transmute(options),
                            hcontext.into_param().abi(),
                            ::std::mem::transmute(pextrainfo),
                            ::std::mem::transmute(preserved),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsServiceBrowse(
                    prequest: *mut DNS_SERVICE_BROWSE_REQUEST,
                    pcancel: *mut DNS_SERVICE_CANCEL,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsServiceBrowse(
                                prequest: *mut DNS_SERVICE_BROWSE_REQUEST_abi,
                                pcancel: *mut DNS_SERVICE_CANCEL,
                            ) -> i32;
                        }
                        DnsServiceBrowse(
                            ::std::mem::transmute(prequest),
                            ::std::mem::transmute(pcancel),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsServiceBrowseCancel(
                    pcancelhandle: *mut DNS_SERVICE_CANCEL,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsServiceBrowseCancel(
                                pcancelhandle: *mut DNS_SERVICE_CANCEL,
                            ) -> i32;
                        }
                        DnsServiceBrowseCancel(::std::mem::transmute(
                            pcancelhandle,
                        ))
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsServiceConstructInstance<'a>(
                    pservicename: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PWSTR,
                    >,
                    phostname: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PWSTR,
                    >,
                    pip4: *mut u32,
                    pip6: *mut IP6_ADDRESS,
                    wport: u16,
                    wpriority: u16,
                    wweight: u16,
                    dwpropertiescount: u32,
                    keys: *mut super::super::Foundation::PWSTR,
                    values: *mut super::super::Foundation::PWSTR,
                ) -> *mut DNS_SERVICE_INSTANCE {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsServiceConstructInstance(
                                pservicename: super::super::Foundation::PWSTR,
                                phostname: super::super::Foundation::PWSTR,
                                pip4: *mut u32,
                                pip6: *mut IP6_ADDRESS,
                                wport: u16,
                                wpriority: u16,
                                wweight: u16,
                                dwpropertiescount: u32,
                                keys: *mut super::super::Foundation::PWSTR,
                                values: *mut super::super::Foundation::PWSTR,
                            ) -> *mut DNS_SERVICE_INSTANCE;
                        }
                        DnsServiceConstructInstance(
                            pservicename.into_param().abi(),
                            phostname.into_param().abi(),
                            ::std::mem::transmute(pip4),
                            ::std::mem::transmute(pip6),
                            ::std::mem::transmute(wport),
                            ::std::mem::transmute(wpriority),
                            ::std::mem::transmute(wweight),
                            ::std::mem::transmute(dwpropertiescount),
                            ::std::mem::transmute(keys),
                            ::std::mem::transmute(values),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsServiceCopyInstance(
                    porig: *mut DNS_SERVICE_INSTANCE,
                ) -> *mut DNS_SERVICE_INSTANCE {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsServiceCopyInstance(
                                porig: *mut DNS_SERVICE_INSTANCE,
                            ) -> *mut DNS_SERVICE_INSTANCE;
                        }
                        DnsServiceCopyInstance(::std::mem::transmute(porig))
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsServiceDeRegister(
                    prequest: *mut DNS_SERVICE_REGISTER_REQUEST,
                    pcancel: *mut DNS_SERVICE_CANCEL,
                ) -> u32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsServiceDeRegister(
                                prequest : * mut DNS_SERVICE_REGISTER_REQUEST_abi,
                                pcancel: *mut DNS_SERVICE_CANCEL,
                            ) -> u32;
                        }
                        DnsServiceDeRegister(
                            ::std::mem::transmute(prequest),
                            ::std::mem::transmute(pcancel),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsServiceFreeInstance(
                    pinstance: *mut DNS_SERVICE_INSTANCE,
                ) {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsServiceFreeInstance(
                                pinstance: *mut DNS_SERVICE_INSTANCE,
                            );
                        }
                        DnsServiceFreeInstance(::std::mem::transmute(
                            pinstance,
                        ))
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsServiceRegister(
                    prequest: *mut DNS_SERVICE_REGISTER_REQUEST,
                    pcancel: *mut DNS_SERVICE_CANCEL,
                ) -> u32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsServiceRegister(
                                prequest : * mut DNS_SERVICE_REGISTER_REQUEST_abi,
                                pcancel: *mut DNS_SERVICE_CANCEL,
                            ) -> u32;
                        }
                        DnsServiceRegister(
                            ::std::mem::transmute(prequest),
                            ::std::mem::transmute(pcancel),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsServiceRegisterCancel(
                    pcancelhandle: *mut DNS_SERVICE_CANCEL,
                ) -> u32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsServiceRegisterCancel(
                                pcancelhandle: *mut DNS_SERVICE_CANCEL,
                            ) -> u32;
                        }
                        DnsServiceRegisterCancel(::std::mem::transmute(
                            pcancelhandle,
                        ))
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsServiceResolve(
                    prequest: *mut DNS_SERVICE_RESOLVE_REQUEST,
                    pcancel: *mut DNS_SERVICE_CANCEL,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsServiceResolve(
                                prequest: *mut DNS_SERVICE_RESOLVE_REQUEST_abi,
                                pcancel: *mut DNS_SERVICE_CANCEL,
                            ) -> i32;
                        }
                        DnsServiceResolve(
                            ::std::mem::transmute(prequest),
                            ::std::mem::transmute(pcancel),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsServiceResolveCancel(
                    pcancelhandle: *mut DNS_SERVICE_CANCEL,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsServiceResolveCancel(
                                pcancelhandle: *mut DNS_SERVICE_CANCEL,
                            ) -> i32;
                        }
                        DnsServiceResolveCancel(::std::mem::transmute(
                            pcancelhandle,
                        ))
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsStartMulticastQuery(
                    pqueryrequest: *mut MDNS_QUERY_REQUEST,
                    phandle: *mut MDNS_QUERY_HANDLE,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsStartMulticastQuery(
                                pqueryrequest: *mut MDNS_QUERY_REQUEST_abi,
                                phandle: *mut MDNS_QUERY_HANDLE,
                            ) -> i32;
                        }
                        DnsStartMulticastQuery(
                            ::std::mem::transmute(pqueryrequest),
                            ::std::mem::transmute(phandle),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsStopMulticastQuery(
                    phandle: *mut MDNS_QUERY_HANDLE,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsStopMulticastQuery(
                                phandle: *mut MDNS_QUERY_HANDLE,
                            ) -> i32;
                        }
                        DnsStopMulticastQuery(::std::mem::transmute(phandle))
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsValidateName_A<'a>(
                    pszname: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PSTR,
                    >,
                    format: DNS_NAME_FORMAT,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsValidateName_A(
                                pszname: super::super::Foundation::PSTR,
                                format: DNS_NAME_FORMAT,
                            ) -> i32;
                        }
                        DnsValidateName_A(
                            pszname.into_param().abi(),
                            ::std::mem::transmute(format),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsValidateName_UTF8<'a>(
                    pszname: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PSTR,
                    >,
                    format: DNS_NAME_FORMAT,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsValidateName_UTF8(
                                pszname: super::super::Foundation::PSTR,
                                format: DNS_NAME_FORMAT,
                            ) -> i32;
                        }
                        DnsValidateName_UTF8(
                            pszname.into_param().abi(),
                            ::std::mem::transmute(format),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsValidateName_W<'a>(
                    pszname: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PWSTR,
                    >,
                    format: DNS_NAME_FORMAT,
                ) -> i32 {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsValidateName_W(
                                pszname: super::super::Foundation::PWSTR,
                                format: DNS_NAME_FORMAT,
                            ) -> i32;
                        }
                        DnsValidateName_W(
                            pszname.into_param().abi(),
                            ::std::mem::transmute(format),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsWriteQuestionToBuffer_UTF8<'a>(
                    pdnsbuffer: *mut DNS_MESSAGE_BUFFER,
                    pdwbuffersize: *mut u32,
                    pszname: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PSTR,
                    >,
                    wtype: u16,
                    xid: u16,
                    frecursiondesired: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::BOOL,
                    >,
                ) -> super::super::Foundation::BOOL {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsWriteQuestionToBuffer_UTF8(
                                pdnsbuffer: *mut DNS_MESSAGE_BUFFER,
                                pdwbuffersize: *mut u32,
                                pszname: super::super::Foundation::PSTR,
                                wtype: u16,
                                xid: u16,
                                frecursiondesired : super::super::Foundation:: BOOL,
                            ) -> super::super::Foundation::BOOL;
                        }
                        DnsWriteQuestionToBuffer_UTF8(
                            ::std::mem::transmute(pdnsbuffer),
                            ::std::mem::transmute(pdwbuffersize),
                            pszname.into_param().abi(),
                            ::std::mem::transmute(wtype),
                            ::std::mem::transmute(xid),
                            frecursiondesired.into_param().abi(),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub unsafe fn DnsWriteQuestionToBuffer_W<'a>(
                    pdnsbuffer: *mut DNS_MESSAGE_BUFFER,
                    pdwbuffersize: *mut u32,
                    pszname: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::PWSTR,
                    >,
                    wtype: u16,
                    xid: u16,
                    frecursiondesired: impl ::windows::IntoParam<
                        'a,
                        super::super::Foundation::BOOL,
                    >,
                ) -> super::super::Foundation::BOOL {
                    #[cfg(windows)]
                    {
                        #[link(name = "DNSAPI")]
                        extern "system" {
                            fn DnsWriteQuestionToBuffer_W(
                                pdnsbuffer: *mut DNS_MESSAGE_BUFFER,
                                pdwbuffersize: *mut u32,
                                pszname: super::super::Foundation::PWSTR,
                                wtype: u16,
                                xid: u16,
                                frecursiondesired : super::super::Foundation:: BOOL,
                            ) -> super::super::Foundation::BOOL;
                        }
                        DnsWriteQuestionToBuffer_W(
                            ::std::mem::transmute(pdnsbuffer),
                            ::std::mem::transmute(pdwbuffersize),
                            pszname.into_param().abi(),
                            ::std::mem::transmute(wtype),
                            ::std::mem::transmute(xid),
                            frecursiondesired.into_param().abi(),
                        )
                    }
                    #[cfg(not(windows))]
                    unimplemented!("Unsupported target OS");
                }
                pub const IP4_ADDRESS_STRING_BUFFER_LENGTH: u32 = 16u32;
                pub const IP4_ADDRESS_STRING_LENGTH: u32 = 16u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct IP4_ARRAY {
                    pub AddrCount: u32,
                    pub AddrArray: [u32; 1],
                }
                impl IP4_ARRAY {}
                impl ::std::default::Default for IP4_ARRAY {
                    fn default() -> Self {
                        Self {
                            AddrCount: 0,
                            AddrArray: [0; 1],
                        }
                    }
                }
                impl ::std::fmt::Debug for IP4_ARRAY {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("IP4_ARRAY")
                            .field("AddrCount", &self.AddrCount)
                            .field("AddrArray", &self.AddrArray)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for IP4_ARRAY {
                    fn eq(&self, other: &Self) -> bool {
                        self.AddrCount == other.AddrCount
                            && self.AddrArray == other.AddrArray
                    }
                }
                impl ::std::cmp::Eq for IP4_ARRAY {}
                unsafe impl ::windows::Abi for IP4_ARRAY {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub union IP6_ADDRESS {
                    pub IP6Qword: [u64; 2],
                    pub IP6Dword: [u32; 4],
                    pub IP6Word: [u16; 8],
                    pub IP6Byte: [u8; 16],
                }
                impl IP6_ADDRESS {}
                unsafe impl ::windows::Abi for IP6_ADDRESS {
                    type Abi = Self;
                }
                pub const IP6_ADDRESS_STRING_BUFFER_LENGTH: u32 = 65u32;
                pub const IP6_ADDRESS_STRING_LENGTH: u32 = 65u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct MDNS_QUERY_HANDLE {
                    pub nameBuf: [u16; 256],
                    pub wType: u16,
                    pub pSubscription: *mut ::std::ffi::c_void,
                    pub pWnfCallbackParams: *mut ::std::ffi::c_void,
                    pub stateNameData: [u32; 2],
                }
                impl MDNS_QUERY_HANDLE {}
                impl ::std::default::Default for MDNS_QUERY_HANDLE {
                    fn default() -> Self {
                        Self {
                            nameBuf: [0; 256],
                            wType: 0,
                            pSubscription: ::std::ptr::null_mut(),
                            pWnfCallbackParams: ::std::ptr::null_mut(),
                            stateNameData: [0; 2],
                        }
                    }
                }
                impl ::std::fmt::Debug for MDNS_QUERY_HANDLE {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("MDNS_QUERY_HANDLE")
                            .field("nameBuf", &self.nameBuf)
                            .field("wType", &self.wType)
                            .field("pSubscription", &self.pSubscription)
                            .field(
                                "pWnfCallbackParams",
                                &self.pWnfCallbackParams,
                            )
                            .field("stateNameData", &self.stateNameData)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for MDNS_QUERY_HANDLE {
                    fn eq(&self, other: &Self) -> bool {
                        self.nameBuf == other.nameBuf
                            && self.wType == other.wType
                            && self.pSubscription == other.pSubscription
                            && self.pWnfCallbackParams
                                == other.pWnfCallbackParams
                            && self.stateNameData == other.stateNameData
                    }
                }
                impl ::std::cmp::Eq for MDNS_QUERY_HANDLE {}
                unsafe impl ::windows::Abi for MDNS_QUERY_HANDLE {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(:: std :: clone :: Clone)]
                pub struct MDNS_QUERY_REQUEST {
                    pub Version: u32,
                    pub ulRefCount: u32,
                    pub Query: super::super::Foundation::PWSTR,
                    pub QueryType: u16,
                    pub QueryOptions: u64,
                    pub InterfaceIndex: u32,
                    pub pQueryCallback:
                        ::std::option::Option<PMDNS_QUERY_CALLBACK>,
                    pub pQueryContext: *mut ::std::ffi::c_void,
                    pub fAnswerReceived: super::super::Foundation::BOOL,
                    pub ulResendCount: u32,
                }
                impl MDNS_QUERY_REQUEST {}
                impl ::std::default::Default for MDNS_QUERY_REQUEST {
                    fn default() -> Self {
                        Self {
                            Version: 0,
                            ulRefCount: 0,
                            Query: ::std::default::Default::default(),
                            QueryType: 0,
                            QueryOptions: 0,
                            InterfaceIndex: 0,
                            pQueryCallback: ::std::default::Default::default(),
                            pQueryContext: ::std::ptr::null_mut(),
                            fAnswerReceived: ::std::default::Default::default(
                            ),
                            ulResendCount: 0,
                        }
                    }
                }
                impl ::std::fmt::Debug for MDNS_QUERY_REQUEST {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("MDNS_QUERY_REQUEST")
                            .field("Version", &self.Version)
                            .field("ulRefCount", &self.ulRefCount)
                            .field("Query", &self.Query)
                            .field("QueryType", &self.QueryType)
                            .field("QueryOptions", &self.QueryOptions)
                            .field("InterfaceIndex", &self.InterfaceIndex)
                            .field("pQueryContext", &self.pQueryContext)
                            .field("fAnswerReceived", &self.fAnswerReceived)
                            .field("ulResendCount", &self.ulResendCount)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for MDNS_QUERY_REQUEST {
                    fn eq(&self, other: &Self) -> bool {
                        self.Version == other.Version
                            && self.ulRefCount == other.ulRefCount
                            && self.Query == other.Query
                            && self.QueryType == other.QueryType
                            && self.QueryOptions == other.QueryOptions
                            && self.InterfaceIndex == other.InterfaceIndex
                            && self.pQueryCallback.map(|f| f as usize)
                                == other.pQueryCallback.map(|f| f as usize)
                            && self.pQueryContext == other.pQueryContext
                            && self.fAnswerReceived == other.fAnswerReceived
                            && self.ulResendCount == other.ulResendCount
                    }
                }
                impl ::std::cmp::Eq for MDNS_QUERY_REQUEST {}
                #[repr(C)]
                #[doc(hidden)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct MDNS_QUERY_REQUEST_abi {
                    pub Version: u32,
                    pub ulRefCount: u32,
                    pub Query: super::super::Foundation::PWSTR,
                    pub QueryType: u16,
                    pub QueryOptions: u64,
                    pub InterfaceIndex: u32,
                    pub pQueryCallback: ::windows::RawPtr,
                    pub pQueryContext: *mut ::std::ffi::c_void,
                    pub fAnswerReceived: super::super::Foundation::BOOL,
                    pub ulResendCount: u32,
                }
                unsafe impl ::windows::Abi for MDNS_QUERY_REQUEST {
                    type Abi = MDNS_QUERY_REQUEST_abi;
                }
                pub type PDNS_QUERY_COMPLETION_ROUTINE =
                    unsafe extern "system" fn(
                        pquerycontext: *mut ::std::ffi::c_void,
                        pqueryresults: *mut DNS_QUERY_RESULT,
                    );
                pub type PDNS_SERVICE_BROWSE_CALLBACK =
                    unsafe extern "system" fn(
                        status: u32,
                        pquerycontext: *mut ::std::ffi::c_void,
                        pdnsrecord: *mut DNS_RECORDA,
                    );
                pub type PDNS_SERVICE_REGISTER_COMPLETE =
                    unsafe extern "system" fn(
                        status: u32,
                        pquerycontext: *mut ::std::ffi::c_void,
                        pinstance: *mut DNS_SERVICE_INSTANCE,
                    );
                pub type PDNS_SERVICE_RESOLVE_COMPLETE =
                    unsafe extern "system" fn(
                        status: u32,
                        pquerycontext: *mut ::std::ffi::c_void,
                        pinstance: *mut DNS_SERVICE_INSTANCE,
                    );
                pub type PMDNS_QUERY_CALLBACK = unsafe extern "system" fn(
                    pquerycontext: *mut ::std::ffi::c_void,
                    pqueryhandle: *mut MDNS_QUERY_HANDLE,
                    pqueryresults: *mut DNS_QUERY_RESULT,
                );
                pub const SIZEOF_IP4_ADDRESS: u32 = 4u32;
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct _DnsRecordOptA {
                    pub pNext: *mut DNS_RECORDA,
                    pub pName: super::super::Foundation::PSTR,
                    pub wType: u16,
                    pub wDataLength: u16,
                    pub Flags: _DnsRecordOptA_1,
                    pub ExtHeader: DNS_HEADER_EXT,
                    pub wPayloadSize: u16,
                    pub wReserved: u16,
                    pub Data: _DnsRecordOptA_0,
                }
                impl _DnsRecordOptA {}
                unsafe impl ::windows::Abi for _DnsRecordOptA {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub union _DnsRecordOptA_0 {
                    pub OPT: DNS_OPT_DATA,
                    pub Opt: DNS_OPT_DATA,
                }
                impl _DnsRecordOptA_0 {}
                unsafe impl ::windows::Abi for _DnsRecordOptA_0 {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub union _DnsRecordOptA_1 {
                    pub DW: u32,
                    pub S: DNS_RECORD_FLAGS,
                }
                impl _DnsRecordOptA_1 {}
                unsafe impl ::windows::Abi for _DnsRecordOptA_1 {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct _DnsRecordOptW {
                    pub pNext: *mut DNS_RECORDW,
                    pub pName: super::super::Foundation::PWSTR,
                    pub wType: u16,
                    pub wDataLength: u16,
                    pub Flags: _DnsRecordOptW_1,
                    pub ExtHeader: DNS_HEADER_EXT,
                    pub wPayloadSize: u16,
                    pub wReserved: u16,
                    pub Data: _DnsRecordOptW_0,
                }
                impl _DnsRecordOptW {}
                unsafe impl ::windows::Abi for _DnsRecordOptW {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub union _DnsRecordOptW_0 {
                    pub OPT: DNS_OPT_DATA,
                    pub Opt: DNS_OPT_DATA,
                }
                impl _DnsRecordOptW_0 {}
                unsafe impl ::windows::Abi for _DnsRecordOptW_0 {
                    type Abi = Self;
                }
                #[repr(C)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub union _DnsRecordOptW_1 {
                    pub DW: u32,
                    pub S: DNS_RECORD_FLAGS,
                }
                impl _DnsRecordOptW_1 {}
                unsafe impl ::windows::Abi for _DnsRecordOptW_1 {
                    type Abi = Self;
                }
            }
        }
        #[allow(
            unused_variables,
            non_upper_case_globals,
            non_snake_case,
            unused_unsafe,
            non_camel_case_types,
            dead_code,
            clippy::all
        )]
        pub mod System {
            #[allow(
                unused_variables,
                non_upper_case_globals,
                non_snake_case,
                unused_unsafe,
                non_camel_case_types,
                dead_code,
                clippy::all
            )]
            pub mod SystemServices {
                #[repr(transparent)]
                #[derive(
                    :: std :: clone :: Clone, :: std :: marker :: Copy,
                )]
                pub struct CHAR(pub u8);
                impl CHAR {}
                impl ::std::default::Default for CHAR {
                    fn default() -> Self {
                        Self(0)
                    }
                }
                impl CHAR {
                    pub const NULL: Self = Self(0);
                    pub fn is_null(&self) -> bool {
                        self.0 == 0
                    }
                }
                impl ::std::fmt::Debug for CHAR {
                    fn fmt(
                        &self,
                        fmt: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        fmt.debug_struct("CHAR")
                            .field("Value", &self.0)
                            .finish()
                    }
                }
                impl ::std::cmp::PartialEq for CHAR {
                    fn eq(&self, other: &Self) -> bool {
                        self.0 == other.0
                    }
                }
                impl ::std::cmp::Eq for CHAR {}
                unsafe impl ::windows::Abi for CHAR {
                    type Abi = Self;
                }
            }
        }
    }
}
