use crate::utils::path_to_wide_ptr;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree, WIN32_ERROR};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

#[must_use]
pub struct SecurityDescriptor {
    _opaque: PSECURITY_DESCRIPTOR,
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            if !self._opaque.is_null() {
                LocalFree(self._opaque as _);
            }
        }
    }
}

impl std::fmt::Debug for SecurityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecurityDescriptor({:p})", self._opaque)
    }
}

impl SecurityDescriptor {
    pub fn from_path<P>(path: P) -> Result<Self, WIN32_ERROR>
    where
        P: AsRef<Path>,
    {
        let path_ptr = path_to_wide_ptr(path);
        let mut sd_ptr: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let err = unsafe {
            GetNamedSecurityInfoW(
                path_ptr,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(), // owner SID
                ptr::null_mut(), // group SID
                ptr::null_mut(), // DACL
                ptr::null_mut(), // SACL
                &mut sd_ptr,     // Security Descriptor
            )
        };

        if err != ERROR_SUCCESS {
            return Err(err);
        }

        Ok(Self { _opaque: sd_ptr })
    }
}
