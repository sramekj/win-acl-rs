//! TODO

use crate::error::WinError;
use crate::sid::account::{AccountLookup, lookup_account_name, lookup_account_sid};
use crate::trustee::Trustee;
use crate::utils::WideCString;
use crate::{assert_free, winapi_bool_call};
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::ops::Deref;
use std::ptr::{copy_nonoverlapping, null_mut};
use std::str::FromStr;
use windows_sys::Win32::Foundation::{ERROR_OUTOFMEMORY, FALSE, GetLastError};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{
    CopySid, CreateWellKnownSid, GetLengthSid, IsValidSid, PSID, SECURITY_MAX_SID_SIZE, SID, WELL_KNOWN_SID_TYPE,
};
use windows_sys::Win32::System::Memory::{LMEM_FIXED, LocalAlloc};

/// Owned SID structure, opaque
#[derive(Debug)]
pub struct Sid {
    psid: PSID,
    len: usize,
}

/// Borrowed SID
#[derive(Debug)]
pub struct SidRef<'a> {
    ptr: *const SID,
    _p: PhantomData<&'a SID>,
}

impl Drop for Sid {
    fn drop(&mut self) {
        unsafe {
            assert_free!(self.psid, "Sid::drop");
        }
    }
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

impl Clone for Sid {
    fn clone(&self) -> Self {
        Sid::from_bytes(&self.to_vec()).unwrap()
    }
}

impl PartialEq<Self> for Sid {
    fn eq(&self, other: &Self) -> bool {
        self.to_vec() == other.to_vec()
    }
}

impl Eq for Sid {}

impl Hash for Sid {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_vec().hash(state);
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
    /// # Safety
    ///
    /// TODO!
    pub unsafe fn from_ptr_clone(psid: PSID) -> Result<Self, WinError> {
        unsafe {
            if psid.is_null() || IsValidSid(psid) == FALSE {
                return Err("Either psid is null or is not valid".into());
            }
            let len = GetLengthSid(psid) as usize;
            let dst = LocalAlloc(LMEM_FIXED, len) as PSID;
            if dst.is_null() {
                return Err(ERROR_OUTOFMEMORY.into());
            }
            winapi_bool_call!(CopySid(len as u32, dst, psid), {
                assert_free!(dst, "Sid::from_ptr_clone");
            });
            Ok(Self { psid: dst, len })
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WinError> {
        unsafe {
            let len = bytes.len();
            let dst = LocalAlloc(LMEM_FIXED, len) as PSID;
            if dst.is_null() {
                return Err(ERROR_OUTOFMEMORY.into());
            }
            copy_nonoverlapping(bytes.as_ptr(), dst as _, len);
            Ok(Self { psid: dst, len })
        }
    }

    pub fn from_string<S>(s: S) -> Result<Self, WinError>
    where
        S: AsRef<str>,
    {
        let wide = WideCString::new(s.as_ref());
        let mut sid_ptr: PSID = null_mut();
        let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid_ptr) };
        if ok == FALSE || sid_ptr.is_null() {
            return Err(unsafe { GetLastError().into() });
        }
        let len = unsafe { GetLengthSid(sid_ptr) as usize };
        Ok(Sid { psid: sid_ptr, len })
    }

    pub fn from_well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> Result<Self, WinError> {
        let mut buf = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = buf.len() as u32;
        unsafe {
            winapi_bool_call!(CreateWellKnownSid(
                kind,
                null_mut() as PSID,
                buf.as_mut_ptr() as PSID,
                &mut size
            ))
        };
        Self::from_bytes(&buf[..size as usize])
    }

    pub fn from_account_name<S>(name: S) -> Result<Self, WinError>
    where
        S: AsRef<str>,
    {
        unsafe { lookup_account_name(name).map(|a| Self::from_string(&a.name).unwrap()) }
    }

    pub fn lookup_name(&self) -> Result<AccountLookup, WinError> {
        unsafe { lookup_account_sid(self.psid) }
    }

    pub fn is_valid(&self) -> bool {
        unsafe { IsValidSid(self.psid) != FALSE }
    }

    pub fn to_string(&self) -> Result<String, WinError> {
        let mut str_ptr: *mut u16 = null_mut();
        unsafe { winapi_bool_call!(ConvertSidToStringSidW(self.psid, &mut str_ptr)) }
        let s = WideCString::from_wide_null_ptr(str_ptr).as_string();
        unsafe { assert_free!(str_ptr, "Sid::to_string") };
        Ok(s)
    }

    pub fn as_trustee(&'_ self) -> Trustee<'_> {
        Trustee::from_sid(self)
    }

    pub fn as_ptr(&self) -> *const SID {
        self.psid as *const _
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = vec![0u8; self.len];
        unsafe { CopySid(self.len as u32, v.as_mut_ptr() as *mut _, self.psid) };
        v
    }
}

impl AsRef<PSID> for Sid {
    fn as_ref(&self) -> &PSID {
        &self.psid
    }
}

impl Deref for Sid {
    type Target = PSID;
    fn deref(&self) -> &Self::Target {
        &self.psid
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
        let s = WideCString::from_wide_null_ptr(str_ptr).as_string();
        unsafe {
            assert_free!(str_ptr, "SidRef<'a>::to_string");
        }
        Ok(s)
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
        let sid_obj = unsafe { Sid::from_ptr_clone(sid) }?;

        unsafe {
            assert_free!(sid, "account::lookup_account_name()");
        };

        Ok(AccountLookup {
            name: sid_obj.to_string()?,
            domain,
            sid_type,
        })
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
