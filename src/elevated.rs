//! this module exposes functions that require elevated privileges
//! the process requires "SE_SECURITY_NAME" (*SeSecurityPrivilege*) privilege, would otherwise return WIN32_ERROR(1314) => "A required privilege is not held by the client"
//! you can run `whoami /priv` to check it. You typically need to run the process as an Administrator and enable it using enable_se_security_privilege().

use crate::error::WinError;
use crate::winapi_bool_call;
use std::ptr;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    SE_SECURITY_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TokenElevation,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Enables *SeSecurityPrivilege* privilege.
/// This typically needs a process running as an Administrator.
pub fn enable_se_security_privilege() -> Result<(), WinError> {
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
        winapi_bool_call!(
            LookupPrivilegeValueW(ptr::null(), SE_SECURITY_NAME, &mut luid),
            {
                CloseHandle(token);
            }
        );

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

        winapi_bool_call!(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token_handle
        ));

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

pub mod sd {
    use crate::error::WinError;
    use crate::sd::{ObjectSecurityEx, SecurityDescriptor};
    use crate::utils::WideCString;
    use std::ffi::OsStr;
    use std::path::Path;
    use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
    use windows_sys::Win32::Security::OBJECT_SECURITY_INFORMATION;

    /// SecurityDescriptor wrapper with functions that require *SeSecurityPrivilege* privilege.
    pub struct ElevatedSecurityDescriptor;

    impl ElevatedSecurityDescriptor {
        /// Creates a SecurityDescriptor from path to the "file object"
        ///
        /// # Arguments
        ///
        /// * `path` - Path to the file.
        ///
        /// # Returns
        ///
        /// A `SecurityDescriptor` on success.
        pub fn from_path<P>(path: P) -> Result<SecurityDescriptor, WinError>
        where
            P: AsRef<Path>,
        {
            let wide_path = WideCString::new(OsStr::new(path.as_ref()));

            SecurityDescriptor::create_sd(
                wide_path.as_ptr(),
                SE_FILE_OBJECT,
                OBJECT_SECURITY_INFORMATION::get_all(),
            )
        }
    }
}
