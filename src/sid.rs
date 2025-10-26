//! TODO

use crate::error::WinError;
use crate::utils::WideCString;
use std::marker::PhantomData;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{FALSE, GetLastError, LocalFree};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{CopySid, GetLengthSid, IsValidSid, PSID, SID};
use windows_sys::Win32::System::Memory::LocalAlloc;

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
            let dst = LocalAlloc(0, len) as PSID;
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

    pub fn from_string(s: &str) -> Result<Self, WinError> {
        let wide = WideCString::new(s);
        let mut sid_ptr: PSID = null_mut();
        let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid_ptr) };
        if ok == FALSE || sid_ptr.is_null() {
            return Err(unsafe { GetLastError().into() });
        }
        let len = unsafe { GetLengthSid(sid_ptr) as usize };
        Ok(Sid { psid: sid_ptr, len })
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
