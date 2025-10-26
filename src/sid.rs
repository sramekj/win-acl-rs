//! TODO

use crate::error::WinError;
use crate::utils::WideCString;
use crate::winapi_bool_call;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::ptr::{copy_nonoverlapping, null_mut};
use std::str::FromStr;
use windows_sys::Win32::Foundation::{FALSE, GetLastError, LocalFree};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{
    CopySid, CreateWellKnownSid, GetLengthSid, IsValidSid, PSID, SECURITY_MAX_SID_SIZE, SID,
    WELL_KNOWN_SID_TYPE,
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
            if !self.psid.is_null() {
                let freed = LocalFree(self.psid as _);
                debug_assert!(freed.is_null(), "LocalFree failed in Drop!");
            }
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
    pub unsafe fn from_ptr_clone(psid: PSID) -> Option<Self> {
        if psid.is_null() {
            return None;
        }
        unsafe {
            if IsValidSid(psid) == FALSE {
                return None;
            }
            let len = GetLengthSid(psid) as usize;
            let dst = LocalAlloc(LMEM_FIXED, len) as PSID;
            if dst.is_null() {
                return None;
            }
            if CopySid(len as u32, dst, psid) == FALSE {
                LocalFree(dst as _);
                return None;
            }
            Some(Self { psid: dst, len })
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WinError> {
        unsafe {
            let len = bytes.len();
            let dst = LocalAlloc(LMEM_FIXED, len) as PSID;
            if dst.is_null() {
                return Err(GetLastError().into());
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

    pub fn is_valid(&self) -> bool {
        unsafe { IsValidSid(self.psid) != FALSE }
    }

    pub fn to_string(&self) -> Result<String, WinError> {
        let mut str_ptr: *mut u16 = null_mut();
        let ok = unsafe { ConvertSidToStringSidW(self.psid, &mut str_ptr) };
        if ok == FALSE {
            return Err(unsafe { GetLastError().into() });
        }
        let s = WideCString::from_wide_null_ptr(str_ptr).as_string();
        unsafe { LocalFree(str_ptr as _) };
        Ok(s)
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

impl<'a> SidRef<'a> {
    /// # Safety
    ///
    /// TODO!
    pub unsafe fn from_ptr(ptr: *const SID) -> Self {
        Self {
            ptr,
            _p: PhantomData,
        }
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
        let ok = unsafe { ConvertSidToStringSidW(self.ptr as PSID, &mut str_ptr) };
        if ok == 0 {
            return Err(unsafe { GetLastError().into() });
        }
        let s = WideCString::from_wide_null_ptr(str_ptr).as_string();
        unsafe { LocalFree(str_ptr as _) };
        Ok(s)
    }
}
