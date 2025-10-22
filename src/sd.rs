#![allow(non_snake_case)]

use crate::error::WinError;
use crate::utils::WideCString;
use std::ffi::OsStr;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SACL_SECURITY_INFORMATION,
};

#[must_use]
pub struct SecurityDescriptor {
    p_sd: PSECURITY_DESCRIPTOR,
    p_owner_sid: PSID,
    p_group_sid: PSID,
    p_dacl: *mut ACL,
    p_sacl: *mut ACL,
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            if !self.p_sd.is_null() {
                let freed = LocalFree(self.p_sd as _);
                debug_assert!(freed.is_null(), "LocalFree failed in Drop!");
            }
        }
    }
}

impl std::fmt::Debug for SecurityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityDescriptor")
            .field("p_sd", &self.p_sd)
            .field("p_owner_sid", &self.p_owner_sid)
            .field("p_group_sid", &self.p_group_sid)
            .field("p_dacl", &self.p_dacl)
            .field("p_sacl", &self.p_sacl)
            .finish()
    }
}

impl SecurityDescriptor {
    pub fn from_path<P>(path: P) -> Result<Self, WinError>
    where
        P: AsRef<Path>,
    {
        let wide_path = WideCString::new(OsStr::new(path.as_ref()));
        let mut sd_ptr: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let mut dacl_ptr: *mut ACL = ptr::null_mut();
        let mut sacl_ptr: *mut ACL = ptr::null_mut();
        let mut owner_ptr: PSID = ptr::null_mut();
        let mut group_ptr: PSID = ptr::null_mut();
        let err = unsafe {
            GetNamedSecurityInfoW(
                wide_path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION
                    // would return WIN32_ERROR(1314) => "A required privilege is not held by the client"
                    //| SACL_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | OWNER_SECURITY_INFORMATION,
                &mut owner_ptr,
                &mut group_ptr,
                &mut dacl_ptr,
                &mut sacl_ptr,
                &mut sd_ptr,
            )
        };

        if err != ERROR_SUCCESS {
            return Err(err.into());
        }

        Ok(Self {
            p_sd: sd_ptr,
            p_dacl: dacl_ptr,
            p_sacl: sacl_ptr,
            p_owner_sid: owner_ptr,
            p_group_sid: group_ptr,
        })
    }
}
