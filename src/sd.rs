#![allow(non_snake_case)]

use crate::error::WinError;
use crate::utils::WideCString;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::ptr::null_mut;
use std::slice::from_raw_parts;
use std::str::FromStr;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GetLastError, LocalFree, TRUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SE_OBJECT_TYPE,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
    GetSecurityDescriptorGroup, GetSecurityDescriptorOwner, IsValidSecurityDescriptor,
    OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SACL_SECURITY_INFORMATION,
};
use windows_sys::core::{BOOL, PCWSTR};

/// A Windows security descriptor.
#[must_use]
pub struct SecurityDescriptor {
    sd_ptr: PSECURITY_DESCRIPTOR,
    owner_sid_ptr: PSID,
    group_sid_ptr: PSID,
    dacl_ptr: *mut ACL,
    sacl_ptr: *mut ACL,
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            if !self.sd_ptr.is_null() {
                let freed = LocalFree(self.sd_ptr as _);
                debug_assert!(freed.is_null(), "LocalFree failed in Drop!");
            }
        }
    }
}
impl FromStr for SecurityDescriptor {
    type Err = WinError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_sd_string(OsStr::new(s))
    }
}

impl std::fmt::Debug for SecurityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityDescriptor")
            .field("sd_ptr", &self.sd_ptr)
            .field("owner_sid_ptr", &self.owner_sid_ptr)
            .field("group_sid_ptr", &self.group_sid_ptr)
            .field("dacl_ptr", &self.dacl_ptr)
            .field("sacl_ptr", &self.sacl_ptr)
            .finish()
    }
}

impl SecurityDescriptor {
    /// Creates a SecurityDescriptor from path to the "file object"
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file.
    ///
    /// # Returns
    ///
    /// A `SecurityDescriptor` on success.
    pub fn from_path<P>(path: P) -> Result<Self, WinError>
    where
        P: AsRef<Path>,
    {
        let wide_path = WideCString::new(OsStr::new(path.as_ref()));

        Self::create_sd(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            OBJECT_SECURITY_INFORMATION::get_safe(),
        )
    }

    pub fn is_valid(&self) -> bool {
        Self::is_sd_valid(self.sd_ptr)
    }

    fn is_sd_valid(psd: PSECURITY_DESCRIPTOR) -> bool {
        unsafe { IsValidSecurityDescriptor(psd) == TRUE }
    }

    pub fn from_sd_string<S>(sd_string: &S) -> Result<Self, WinError>
    where
        S: AsRef<OsStr> + ?Sized,
    {
        let wide_str = WideCString::new(sd_string.as_ref());

        let mut sd_ptr: PSECURITY_DESCRIPTOR = null_mut();
        let mut dacl_ptr: *mut ACL = null_mut();
        let mut owner_sid_ptr: PSID = null_mut();
        let mut group_sid_ptr: PSID = null_mut();

        let err = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_str.as_ptr(),
                SDDL_REVISION_1,
                &mut sd_ptr,
                null_mut(),
            )
        };

        if err == 0 {
            return Err(unsafe { GetLastError().into() });
        }

        #[cfg(debug_assertions)]
        println!("IsValidSecurityDescriptor: {}", Self::is_sd_valid(sd_ptr));

        let mut _owner_defaulted: BOOL = 0;
        let mut _group_defaulted: BOOL = 0;
        let mut _dacl_present: BOOL = 0;
        let mut _dacl_defaulted: BOOL = 0;

        let err = unsafe {
            GetSecurityDescriptorOwner(sd_ptr, &mut owner_sid_ptr, &mut _owner_defaulted)
        };
        if err == 0 {
            return Err(unsafe { GetLastError().into() });
        }

        let err = unsafe {
            GetSecurityDescriptorGroup(sd_ptr, &mut group_sid_ptr, &mut _group_defaulted)
        };
        if err == 0 {
            return Err(unsafe { GetLastError().into() });
        }

        let err = unsafe {
            GetSecurityDescriptorDacl(
                sd_ptr,
                &mut _dacl_present,
                &mut dacl_ptr,
                &mut _dacl_defaulted,
            )
        };
        if err == 0 {
            return Err(unsafe { GetLastError().into() });
        }

        Ok(Self {
            sd_ptr,
            dacl_ptr,
            // need to use elevated variant
            sacl_ptr: null_mut(),
            owner_sid_ptr,
            group_sid_ptr,
        })
    }

    pub fn as_sd_string(&self) -> Result<OsString, WinError> {
        let mut buf_ptr: *mut u16 = null_mut();
        let mut buf_len: u32 = 0;

        let err = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                self.sd_ptr,
                SDDL_REVISION_1,
                OBJECT_SECURITY_INFORMATION::get_all(),
                &mut buf_ptr,
                &mut buf_len,
            )
        };
        if err == 0 {
            return Err(unsafe { GetLastError().into() });
        }

        let slice = unsafe { from_raw_parts(buf_ptr, buf_len as usize) };
        let string = WideCString::from_wide_slice(slice);

        if !self.sd_ptr.is_null() {
            let freed = unsafe { LocalFree(buf_ptr as _) };
            debug_assert!(freed.is_null(), "LocalFree failed in as_sd_string()!");
        }

        Ok(string.as_os_string())
    }

    pub(crate) fn create_sd(
        obj_name: PCWSTR,
        obj_type: SE_OBJECT_TYPE,
        flags: OBJECT_SECURITY_INFORMATION,
    ) -> Result<Self, WinError> {
        let mut sd_ptr: PSECURITY_DESCRIPTOR = null_mut();
        let mut dacl_ptr: *mut ACL = null_mut();
        let mut sacl_ptr: *mut ACL = null_mut();
        let mut owner_sid_ptr: PSID = null_mut();
        let mut group_sid_ptr: PSID = null_mut();
        let err = unsafe {
            GetNamedSecurityInfoW(
                obj_name,
                obj_type,
                flags,
                &mut owner_sid_ptr,
                &mut group_sid_ptr,
                &mut dacl_ptr,
                &mut sacl_ptr,
                &mut sd_ptr,
            )
        };

        if err != ERROR_SUCCESS {
            return Err(err.into());
        }

        Ok(Self {
            sd_ptr,
            dacl_ptr,
            sacl_ptr,
            owner_sid_ptr,
            group_sid_ptr,
        })
    }
}

pub(crate) trait ObjectSecurityEx {
    fn get_elevated() -> OBJECT_SECURITY_INFORMATION;
    fn get_safe() -> OBJECT_SECURITY_INFORMATION;
    fn get_all() -> OBJECT_SECURITY_INFORMATION;
}

impl ObjectSecurityEx for OBJECT_SECURITY_INFORMATION {
    fn get_elevated() -> OBJECT_SECURITY_INFORMATION {
        SACL_SECURITY_INFORMATION
    }

    fn get_safe() -> OBJECT_SECURITY_INFORMATION {
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
    }

    fn get_all() -> OBJECT_SECURITY_INFORMATION {
        Self::get_elevated() | Self::get_safe()
    }
}
