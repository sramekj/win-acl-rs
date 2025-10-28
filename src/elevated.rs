//! this module exposes functions that require elevated privileges
//! the process requires "SE_SECURITY_NAME" (*SeSecurityPrivilege*) privilege, would otherwise return WIN32_ERROR(1314) => "A required privilege is not held by the client"
//! you can run `whoami /priv` to check it. You typically need to run the process as an Administrator and enable it using enable_se_security_privilege().

use crate::error::WinError;
use crate::sd::{ObjectSecurityEx, SecurityDescriptorImpl};
use crate::utils::WideCString;
use crate::winapi_bool_call;
use std::ffi::OsStr;
use std::marker::PhantomData;
use std::path::Path;
use std::ptr;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, LUID};
use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SE_OBJECT_TYPE};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, OBJECT_SECURITY_INFORMATION,
    SE_PRIVILEGE_ENABLED, SE_SECURITY_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TokenElevation,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub type SecurityDescriptorElevated = SecurityDescriptorImpl<Elevated>;

/// Enables *SeSecurityPrivilege* privilege.
/// This typically needs a process running as an Administrator.
fn enable_se_security_privilege() -> Result<(), WinError> {
    unsafe {
        let mut token: HANDLE = null_mut();

        winapi_bool_call!(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ));

        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        winapi_bool_call!(LookupPrivilegeValueW(ptr::null(), SE_SECURITY_NAME, &mut luid), {
            CloseHandle(token);
        });

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        winapi_bool_call!(
            AdjustTokenPrivileges(token, 0, &tp as *const _ as _, 0, null_mut(), null_mut()),
            {
                CloseHandle(token);
            }
        );

        let err = GetLastError();
        CloseHandle(token);

        if err != ERROR_SUCCESS {
            return Err(err.into());
        }
    }
    Ok(())
}

/// Checks if the current process is running as an Administrator.
pub fn is_admin() -> Result<bool, WinError> {
    unsafe {
        let mut token_handle = null_mut();
        let mut token_elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };

        winapi_bool_call!(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle));

        let mut size = 0;

        winapi_bool_call!(
            GetTokenInformation(
                token_handle,
                TokenElevation,
                &mut token_elevation as *mut _ as *mut std::ffi::c_void,
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            ),
            {
                CloseHandle(token_handle);
            }
        );

        CloseHandle(token_handle);
        Ok(token_elevation.TokenIsElevated != 0)
    }
}

pub trait PrivilegeLevel {}
#[derive(Debug)]
pub struct Unprivileged;
#[derive(Debug)]
pub struct Elevated;
impl PrivilegeLevel for Unprivileged {}
impl PrivilegeLevel for Elevated {}

/// Represents the current privilege context.
pub type PrivilegeToken = PrivilegeTokenImpl<Unprivileged>;

#[derive(Debug)]
pub struct PrivilegeTokenImpl<P: PrivilegeLevel> {
    _marker: PhantomData<P>,
}

impl PrivilegeTokenImpl<Unprivileged> {
    pub fn new() -> Self {
        Self { _marker: PhantomData }
    }

    /// Try to elevate the current process.
    pub fn try_elevate(self) -> Result<PrivilegeTokenImpl<Elevated>, WinError> {
        enable_se_security_privilege()?;
        Ok(PrivilegeTokenImpl { _marker: PhantomData })
    }
}

impl Default for PrivilegeTokenImpl<Unprivileged> {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivilegeTokenImpl<Elevated> {
    /// Drop back to unprivileged state.
    pub fn drop_privileges(self) -> PrivilegeTokenImpl<Unprivileged> {
        PrivilegeTokenImpl::new()
    }
}

impl SecurityDescriptorImpl<Elevated> {
    /// Creates a SecurityDescriptor from path to the "file object"
    ///
    /// # Arguments
    ///
    /// * `_token` - an elevated privilege token.
    /// * `path` - Path to the file.
    ///
    /// # Returns
    ///
    /// A `SecurityDescriptor` on success.
    pub fn from_path<P>(_token: &PrivilegeTokenImpl<Elevated>, path: P) -> Result<Self, WinError>
    where
        P: AsRef<Path>,
    {
        let wide_path = WideCString::new(OsStr::new(path.as_ref()));

        Self::create_sd(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            OBJECT_SECURITY_INFORMATION::get_all(),
        )
    }

    /// Creates a SecurityDescriptor from object name and object type.
    ///
    /// # Arguments
    ///
    /// * `_token` - an elevated privilege token.
    /// * `handle` - name of the object. This could be many things (path to the file or directory, to network share, name of the printer, registry key, ...)
    /// * `object_type` - a type of the object
    ///
    /// see [MSDN](https://learn.microsoft.com/en-us/windows/win32/api/accctrl/ne-accctrl-se_object_type)
    ///
    /// # Returns
    ///
    /// A `SecurityDescriptor` on success.
    pub fn from_handle<S>(
        _token: &PrivilegeTokenImpl<Elevated>,
        handle: S,
        object_type: SE_OBJECT_TYPE,
    ) -> Result<Self, WinError>
    where
        S: AsRef<str>,
    {
        let wide_string = WideCString::new(handle.as_ref());
        Self::create_sd(
            wide_string.as_ptr(),
            object_type,
            OBJECT_SECURITY_INFORMATION::get_all(),
        )
    }
}
