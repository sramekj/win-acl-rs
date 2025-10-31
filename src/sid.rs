//! TODO

use crate::error::WinError;
use crate::sid::account::{AccountLookup, lookup_account_name, lookup_account_sid};
use crate::trustee::Trustee;
use crate::utils::WideCString;
use crate::{assert_free, winapi_bool_call};
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;
use std::marker::PhantomData;
use std::ptr::null_mut;
use std::str::FromStr;
use windows_sys::Win32::Foundation::{ERROR_OUTOFMEMORY, FALSE, GetLastError};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, GetLengthSid, IsValidSid, PSID, SECURITY_MAX_SID_SIZE, SID, WELL_KNOWN_SID_TYPE,
};
use windows_sys::Win32::System::Memory::{LMEM_FIXED, LocalAlloc};

pub trait AsSidRef<'a> {
    fn as_sid_ref(&'a self) -> SidRef<'a>;
}

/// Owned SID
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct Sid {
    data: Vec<u8>,
}

/// Borrowed SID
#[derive(Clone, Copy)]
pub struct SidRef<'a> {
    ptr: *const SID,
    _p: PhantomData<&'a SID>,
}

impl FromStr for Sid {
    type Err = WinError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Sid::from_string(s)
    }
}

impl Display for Sid {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = self.to_string().unwrap_or_else(|_| "<invalid sid>".into());
        f.write_str(&str)
    }
}

impl TryFrom<&[u8]> for Sid {
    type Error = WinError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl From<Sid> for Vec<u8> {
    fn from(sid: Sid) -> Self {
        sid.to_vec()
    }
}

impl Sid {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WinError> {
        Ok(Self { data: bytes.to_vec() })
    }

    pub fn from_string<S>(s: S) -> Result<Self, WinError>
    where
        S: AsRef<str>,
    {
        let wide = WideCString::new(s.as_ref());
        let mut sid_ptr: PSID = null_mut();
        let err = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid_ptr) };
        if err == FALSE || sid_ptr.is_null() {
            return Err(unsafe { GetLastError().into() });
        }
        let len = unsafe { GetLengthSid(sid_ptr) as usize };
        let data = unsafe { std::slice::from_raw_parts(sid_ptr as *const u8, len) }.to_vec();

        unsafe { assert_free!(sid_ptr, "Sid::from_string") };

        Ok(Sid { data })
    }

    pub fn from_well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> Result<Self, WinError> {
        Self::from_well_known_sid_and_domain(kind, None)
    }

    pub fn from_well_known_sid_and_domain(
        kind: WELL_KNOWN_SID_TYPE,
        domain_sid_ptr: Option<SidRef>,
    ) -> Result<Self, WinError> {
        let mut buf = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = buf.len() as u32;
        let domain = match domain_sid_ptr {
            None => null_mut() as PSID,
            Some(sid_ref) => sid_ref.ptr as PSID,
        };
        unsafe { winapi_bool_call!(CreateWellKnownSid(kind, domain, buf.as_mut_ptr() as PSID, &mut size)) };
        Self::from_bytes(&buf[..size as usize])
    }

    pub fn from_account_name<S>(name: S) -> Result<Self, WinError>
    where
        S: AsRef<str>,
    {
        unsafe { lookup_account_name(name).map(|a| Self::from_string(&a.name).unwrap()) }
    }

    pub fn lookup_name(&self) -> Result<AccountLookup, WinError> {
        unsafe { lookup_account_sid(self.data.as_ptr() as PSID) }
    }

    pub fn is_valid(&self) -> bool {
        unsafe { IsValidSid(self.data.as_ptr() as PSID) != FALSE }
    }

    pub fn len(&self) -> usize {
        unsafe { GetLengthSid(self.data.as_ptr() as PSID) as usize }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn to_string(&self) -> Result<String, WinError> {
        let mut str_ptr: *mut u16 = null_mut();
        unsafe { winapi_bool_call!(ConvertSidToStringSidW(self.data.as_ptr() as PSID, &mut str_ptr)) }
        let result = WideCString::from_wide_null_ptr(str_ptr).as_string();
        unsafe { assert_free!(str_ptr, "Sid::to_string") };
        Ok(result)
    }

    pub fn as_trustee(&'_ self) -> Trustee<'_> {
        Trustee::from_sid_ref(self.as_sid_ref())
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.data.clone()
    }
}

impl<'a> AsSidRef<'a> for Sid {
    fn as_sid_ref(&self) -> SidRef<'a> {
        unsafe { SidRef::from_ptr(self.data.as_ptr() as _) }
    }
}

impl Debug for Sid {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let account = match &self.lookup_name() {
            Ok(acc) => format!("{}/{}", acc.domain, acc.name),
            Err(_) => "<ACCOUNT LOOKUP ERROR>".to_string(),
        };
        f.debug_struct("Sid")
            .field(
                "as_string",
                &self.to_string().unwrap_or_else(|_| "<INVALID SID>".to_string()),
            )
            .field("is_valid", &self.is_valid())
            .field("data", &self.data)
            .field("len", &self.len())
            .field("account", &account)
            .finish()
    }
}

impl<'a, T: AsSidRef<'a> + ?Sized> AsSidRef<'a> for &T {
    fn as_sid_ref(&'a self) -> SidRef<'a> {
        (*self).as_sid_ref()
    }
}

impl<'a> SidRef<'a> {
    /// # Safety
    ///
    /// TODO!
    pub unsafe fn from_ptr(ptr: *const SID) -> Self {
        Self { ptr, _p: PhantomData }
    }

    /// # Safety
    ///
    /// TODO!
    pub unsafe fn lookup_name(&self) -> Result<AccountLookup, WinError> {
        unsafe { lookup_account_sid(self.ptr as PSID) }
    }

    /// # Safety
    ///
    /// TODO!
    pub unsafe fn is_valid(&self) -> bool {
        unsafe { IsValidSid(self.ptr as PSID) != FALSE }
    }

    /// # Safety
    ///
    /// TODO!
    pub unsafe fn len(&self) -> usize {
        unsafe { GetLengthSid(self.ptr as PSID) as usize }
    }

    /// # Safety
    ///
    /// TODO!
    pub unsafe fn is_empty(&self) -> bool {
        unsafe { self.len() == 0 }
    }

    pub fn to_string(&self) -> Result<String, WinError> {
        let mut str_ptr: *mut u16 = null_mut();
        unsafe { winapi_bool_call!(ConvertSidToStringSidW(self.ptr as PSID, &mut str_ptr)) }
        let result = WideCString::from_wide_null_ptr(str_ptr).as_string();
        unsafe {
            assert_free!(str_ptr, "SidRef<'a>::to_string");
        }
        Ok(result)
    }

    pub fn as_trustee(&'_ self) -> Trustee<'_> {
        let sid_ref = self.as_sid_ref();
        Trustee::from_sid_ref(sid_ref)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len()) }.to_vec()
    }

    pub fn as_ptr(&self) -> *const SID {
        self.ptr
    }
}

impl<'a> AsSidRef<'a> for SidRef<'a> {
    fn as_sid_ref(&'a self) -> SidRef<'a> {
        *self
    }
}

impl<'a> Display for SidRef<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = self.to_string().unwrap_or_else(|_| "<invalid sid>".into());
        f.write_str(&str)
    }
}

impl<'a> Debug for SidRef<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let lookup = unsafe { &self.lookup_name() };
        let is_valid = unsafe { &self.is_valid() };
        let len = unsafe { &self.len() };
        let account = match lookup {
            Ok(acc) => format!("{}/{}", acc.domain, acc.name),
            Err(_) => "<ACCOUNT LOOKUP ERROR>".to_string(),
        };
        f.debug_struct("SidRef<'a>")
            .field(
                "as_string",
                &self.to_string().unwrap_or_else(|_| "<INVALID SID>".to_string()),
            )
            .field("is_valid", is_valid)
            .field("ptr", &self.ptr)
            .field("len", len)
            .field("account", &account)
            .finish()
    }
}

pub mod account {
    use super::*;
    use windows_sys::Win32::Security::{LookupAccountNameW, LookupAccountSidW, SID_NAME_USE};

    #[derive(Debug, Clone)]
    pub struct AccountLookup {
        pub name: String,
        pub domain: String,
        pub sid_type: SID_NAME_USE,
    }

    /// # Safety
    ///
    /// TODO!
    pub(crate) unsafe fn lookup_account_name<S>(account: S) -> Result<AccountLookup, WinError>
    where
        S: AsRef<str>,
    {
        let wide_account = WideCString::new(account.as_ref());

        let mut sid_size = 0u32;
        let mut domain_size = 0u32;
        let mut sid_type: SID_NAME_USE = 0;

        unsafe {
            LookupAccountNameW(
                null_mut(),
                wide_account.as_ptr(),
                null_mut(),
                &mut sid_size,
                null_mut(),
                &mut domain_size,
                &mut sid_type,
            );
        }

        let err = unsafe { GetLastError() };
        if err != windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER {
            return Err(err.into());
        }

        let sid = unsafe { LocalAlloc(LMEM_FIXED, sid_size as usize) as PSID };
        if sid.is_null() {
            return Err(ERROR_OUTOFMEMORY.into());
        }

        let mut domain_buf = vec![0u16; domain_size as usize];

        unsafe {
            winapi_bool_call!(
                LookupAccountNameW(
                    null_mut(),
                    wide_account.as_ptr(),
                    sid,
                    &mut sid_size,
                    domain_buf.as_mut_ptr(),
                    &mut domain_size,
                    &mut sid_type,
                ),
                {
                    assert_free!(sid, "account::lookup_account_name()");
                }
            )
        };

        let domain = String::from_utf16_lossy(&domain_buf[..domain_size as usize]);

        let sid_ref = unsafe { SidRef::from_ptr(sid as *const SID) };
        let name = sid_ref.to_string()?;

        unsafe {
            assert_free!(sid, "account::lookup_account_name()");
        };

        Ok(AccountLookup { name, domain, sid_type })
    }

    /// # Safety
    ///
    /// TODO!
    pub(crate) unsafe fn lookup_account_sid(sid: PSID) -> Result<AccountLookup, WinError> {
        let mut name_size = 0u32;
        let mut domain_size = 0u32;
        let mut sid_type: SID_NAME_USE = 0;

        unsafe {
            LookupAccountSidW(
                null_mut(),
                sid,
                null_mut(),
                &mut name_size,
                null_mut(),
                &mut domain_size,
                &mut sid_type,
            );
        }

        let err = unsafe { GetLastError() };
        if err != windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER {
            return Err(err.into());
        }

        let mut name_buf = vec![0u16; name_size as usize];
        let mut domain_buf = vec![0u16; domain_size as usize];

        unsafe {
            winapi_bool_call!(LookupAccountSidW(
                null_mut(),
                sid,
                name_buf.as_mut_ptr(),
                &mut name_size,
                domain_buf.as_mut_ptr(),
                &mut domain_size,
                &mut sid_type,
            ))
        }

        Ok(AccountLookup {
            name: String::from_utf16_lossy(&name_buf[..name_size as usize]),
            domain: String::from_utf16_lossy(&domain_buf[..domain_size as usize]),
            sid_type,
        })
    }
}
