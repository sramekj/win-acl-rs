//! TODO

#![allow(non_snake_case)]

use std::{ffi::OsStr, marker::PhantomData, path::Path, ptr::null_mut, slice::from_raw_parts, str::FromStr};

use windows_sys::{
    Win32::{
        Foundation::TRUE,
        Security::{
            ACL,
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW,
                ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
                SE_FILE_OBJECT, SE_OBJECT_TYPE,
            },
            DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
            GetSecurityDescriptorGroup, GetSecurityDescriptorOwner, GetSecurityDescriptorSacl,
            IsValidSecurityDescriptor, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            PSID, SACL_SECURITY_INFORMATION,
        },
    },
    core::{BOOL, PCWSTR},
};

use crate::{
    acl::Acl,
    assert_free,
    elevated::{Elevated, PrivilegeLevel, PrivilegeTokenImpl, Unprivileged},
    error::WinError,
    sid::SidRef,
    utils::WideCString,
    winapi_bool_call, winapi_call,
};

pub type SecurityDescriptor = SecurityDescriptorImpl<Unprivileged>;

/// A Windows security descriptor.
#[must_use]
pub struct SecurityDescriptorImpl<P: PrivilegeLevel = Unprivileged> {
    sd_ptr: PSECURITY_DESCRIPTOR,
    owner_sid_ptr: PSID,
    group_sid_ptr: PSID,
    dacl_ptr: *mut ACL,
    sacl_ptr: *mut ACL,
    _priv: PhantomData<P>,
}

impl SecurityDescriptorImpl<Unprivileged> {
    /// Upgrades security descriptor to elevated one that has access to SACL, for example
    ///
    /// Is guarded by the existence of elevated token
    pub fn upgrade(self, _token: &PrivilegeTokenImpl<Elevated>) -> SecurityDescriptorImpl<Elevated> {
        SecurityDescriptorImpl {
            sd_ptr: self.sd_ptr,
            owner_sid_ptr: self.owner_sid_ptr,
            group_sid_ptr: self.group_sid_ptr,
            dacl_ptr: self.dacl_ptr,
            sacl_ptr: self.sacl_ptr,
            _priv: PhantomData,
        }
    }

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

    /// Creates a SecurityDescriptor from object name and object type.
    ///
    /// # Arguments
    ///
    /// * `handle` - name of the object. This could be many things (path to the file or directory, to network share, name of the printer, registry key, ...)
    /// * `object_type` - a type of the object
    ///
    /// see [MSDN](https://learn.microsoft.com/en-us/windows/win32/api/accctrl/ne-accctrl-se_object_type)
    ///
    /// # Returns
    ///
    /// A `SecurityDescriptor` on success.
    pub fn from_handle<S>(handle: S, object_type: SE_OBJECT_TYPE) -> Result<Self, WinError>
    where
        S: AsRef<str>,
    {
        let wide_string = WideCString::new(handle.as_ref());
        Self::create_sd(
            wide_string.as_ptr(),
            object_type,
            OBJECT_SECURITY_INFORMATION::get_safe(),
        )
    }
}

impl<P: PrivilegeLevel> Drop for SecurityDescriptorImpl<P> {
    fn drop(&mut self) {
        unsafe {
            assert_free!(self.sd_ptr, "SecurityDescriptorImpl::drop");
        }
    }
}
impl<P: PrivilegeLevel> FromStr for SecurityDescriptorImpl<P> {
    type Err = WinError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_sd_string(s)
    }
}

impl<P: PrivilegeLevel> std::fmt::Debug for SecurityDescriptorImpl<P> {
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

impl<P: PrivilegeLevel> SecurityDescriptorImpl<P> {
    /// Validates a security descriptor.
    pub fn is_valid(&self) -> bool {
        Self::is_sd_valid(self.sd_ptr)
    }

    fn is_sd_valid(psd: PSECURITY_DESCRIPTOR) -> bool {
        unsafe { IsValidSecurityDescriptor(psd) == TRUE }
    }

    /// Indicates that the SID of the owner of the security descriptor was provided by a default mechanism.
    pub fn owner_defaulted(&self) -> Result<bool, WinError> {
        let mut _owner_sid_ptr: PSID = null_mut();
        let mut owner_defaulted: BOOL = 0;
        unsafe {
            winapi_bool_call!(GetSecurityDescriptorOwner(
                self.sd_ptr,
                &mut _owner_sid_ptr,
                &mut owner_defaulted
            ))
        };
        Ok(owner_defaulted == TRUE)
    }

    /// Indicates that the security identifier (SID) of the security descriptor group was provided by a default mechanism.
    pub fn group_defaulted(&self) -> Result<bool, WinError> {
        let mut _group_sid_ptr: PSID = null_mut();
        let mut group_defaulted: BOOL = 0;
        unsafe {
            winapi_bool_call!(GetSecurityDescriptorGroup(
                self.sd_ptr,
                &mut _group_sid_ptr,
                &mut group_defaulted
            ))
        };
        Ok(group_defaulted == TRUE)
    }

    /// Indicates a security descriptor with a default DACL.
    pub fn dacl_defaulted(&self) -> Result<bool, WinError> {
        let mut _dacl_ptr: *mut ACL = null_mut();
        let mut _dacl_present: BOOL = 0;
        let mut dacl_defaulted: BOOL = 0;
        unsafe {
            winapi_bool_call!(GetSecurityDescriptorDacl(
                self.sd_ptr,
                &mut _dacl_present,
                &mut _dacl_ptr,
                &mut dacl_defaulted,
            ))
        };
        Ok(dacl_defaulted == TRUE)
    }

    /// Indicates a security descriptor that has a DACL. If this flag is not set, or if this flag is set and the DACL is NULL, the security descriptor allows full access to everyone.
    pub fn dacl_present(&self) -> Result<bool, WinError> {
        let mut _dacl_ptr: *mut ACL = null_mut();
        let mut dacl_present: BOOL = 0;
        let mut _dacl_defaulted: BOOL = 0;
        unsafe {
            winapi_bool_call!(GetSecurityDescriptorDacl(
                self.sd_ptr,
                &mut dacl_present,
                &mut _dacl_ptr,
                &mut _dacl_defaulted,
            ))
        };
        Ok(dacl_present == TRUE)
    }

    /// Indicates a security descriptor with a default SACL.
    pub fn sacl_defaulted(&self) -> Result<bool, WinError> {
        let mut _sacl_ptr: *mut ACL = null_mut();
        let mut _sacl_present: BOOL = 0;
        let mut sacl_defaulted: BOOL = 0;
        unsafe {
            winapi_bool_call!(GetSecurityDescriptorSacl(
                self.sd_ptr,
                &mut _sacl_present,
                &mut _sacl_ptr,
                &mut sacl_defaulted,
            ))
        };
        Ok(sacl_defaulted == TRUE)
    }

    /// Indicates a security descriptor that has a SACL.
    pub fn sacl_present(&self) -> Result<bool, WinError> {
        let mut _sacl_ptr: *mut ACL = null_mut();
        let mut sacl_present: BOOL = 0;
        let mut _sacl_defaulted: BOOL = 0;
        unsafe {
            winapi_bool_call!(GetSecurityDescriptorSacl(
                self.sd_ptr,
                &mut sacl_present,
                &mut _sacl_ptr,
                &mut _sacl_defaulted,
            ))
        };
        Ok(sacl_present == TRUE)
    }

    /// Converts a string-format security descriptor into a valid, functional security descriptor.
    ///
    /// see [MSDN](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
    ///
    /// # Returns
    ///
    /// A `SecurityDescriptor` on success.
    pub fn from_sd_string<S>(sd_string: S) -> Result<Self, WinError>
    where
        S: AsRef<str>,
    {
        let wide_str = WideCString::new(sd_string.as_ref());

        let mut sd_ptr: PSECURITY_DESCRIPTOR = null_mut();
        let mut dacl_ptr: *mut ACL = null_mut();
        let mut sacl_ptr: *mut ACL = null_mut();
        let mut owner_sid_ptr: PSID = null_mut();
        let mut group_sid_ptr: PSID = null_mut();

        unsafe {
            winapi_bool_call!(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_str.as_ptr(),
                SDDL_REVISION_1,
                &mut sd_ptr,
                null_mut(),
            ))
        };

        #[cfg(debug_assertions)]
        println!("IsValidSecurityDescriptor: {}", Self::is_sd_valid(sd_ptr));

        let mut _owner_defaulted: BOOL = 0;
        let mut _group_defaulted: BOOL = 0;
        let mut _dacl_present: BOOL = 0;
        let mut _dacl_defaulted: BOOL = 0;
        let mut _sacl_present: BOOL = 0;
        let mut _sacl_defaulted: BOOL = 0;

        unsafe {
            winapi_bool_call!(GetSecurityDescriptorOwner(
                sd_ptr,
                &mut owner_sid_ptr,
                &mut _owner_defaulted
            ));

            winapi_bool_call!(GetSecurityDescriptorGroup(
                sd_ptr,
                &mut group_sid_ptr,
                &mut _group_defaulted
            ));

            winapi_bool_call!(GetSecurityDescriptorDacl(
                sd_ptr,
                &mut _dacl_present,
                &mut dacl_ptr,
                &mut _dacl_defaulted,
            ));

            winapi_bool_call!(GetSecurityDescriptorSacl(
                sd_ptr,
                &mut _sacl_present,
                &mut sacl_ptr,
                &mut _sacl_defaulted,
            ))
        };

        Ok(Self {
            sd_ptr,
            dacl_ptr,
            sacl_ptr,
            owner_sid_ptr,
            group_sid_ptr,
            _priv: PhantomData,
        })
    }

    /// Converts security descriptor into a string format
    ///
    /// see [MSDN](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
    ///
    /// # Returns
    ///
    /// A `String` on success.
    pub fn as_sd_string(&self) -> Result<String, WinError> {
        let mut buf_ptr: *mut u16 = null_mut();
        let mut buf_len: u32 = 0;

        unsafe {
            winapi_bool_call!(ConvertSecurityDescriptorToStringSecurityDescriptorW(
                self.sd_ptr,
                SDDL_REVISION_1,
                OBJECT_SECURITY_INFORMATION::get_all(),
                &mut buf_ptr,
                &mut buf_len,
            ))
        };

        let slice = unsafe { from_raw_parts(buf_ptr, buf_len as usize) };
        let string = WideCString::from_wide_slice(slice);

        if !buf_ptr.is_null() {
            unsafe { assert_free!(buf_ptr, "SecurityDescriptorImpl::as_sd_string()") };
        }

        Ok(string.as_string())
    }

    pub fn owner_sid(&self) -> Option<SidRef<'_>> {
        if self.owner_sid_ptr.is_null() {
            return None;
        }
        Some(unsafe { SidRef::from_ptr(self.owner_sid_ptr as _) })
    }

    pub fn group_sid(&self) -> Option<SidRef<'_>> {
        if self.group_sid_ptr.is_null() {
            return None;
        }
        Some(unsafe { SidRef::from_ptr(self.group_sid_ptr as _) })
    }

    pub fn dacl(&self) -> Option<Acl> {
        if self.dacl_ptr.is_null() {
            None
        } else {
            Some(unsafe { Acl::from_ptr(self.dacl_ptr) })
        }
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

        unsafe {
            winapi_call!(GetNamedSecurityInfoW(
                obj_name,
                obj_type,
                flags,
                &mut owner_sid_ptr,
                &mut group_sid_ptr,
                &mut dacl_ptr,
                &mut sacl_ptr,
                &mut sd_ptr,
            ))
        };

        Ok(Self {
            sd_ptr,
            dacl_ptr,
            sacl_ptr,
            owner_sid_ptr,
            group_sid_ptr,
            _priv: PhantomData,
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
