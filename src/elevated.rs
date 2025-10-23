//! this module exposes functions that require elevated privileges
//! the process requires "SE_SECURITY_NAME" (*SeSecurityPrivilege*) privilege, would otherwise return WIN32_ERROR(1314) => "A required privilege is not held by the client"
//! you can run `whoami /priv` to check it. You typically need to run the process as an Administrator and enable it using enable_se_security_privilege().

use crate::error::WinError;
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
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return Err(GetLastError().into());
        }

        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        if LookupPrivilegeValueW(ptr::null(), SE_SECURITY_NAME, &mut luid) == 0 {
            CloseHandle(token);
            return Err(GetLastError().into());
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        if AdjustTokenPrivileges(token, 0, &tp as *const _ as _, 0, null_mut(), null_mut()) == 0 {
            CloseHandle(token);
            return Err(GetLastError().into());
        }

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

        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == 0 {
            return Err(GetLastError().into());
        }

        let mut size = 0;
        if GetTokenInformation(
            token_handle,
            TokenElevation,
            &mut token_elevation as *mut _ as *mut std::ffi::c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        ) == 0
        {
            CloseHandle(token_handle);
            return Err(GetLastError().into());
        }

        CloseHandle(token_handle);
        Ok(token_elevation.TokenIsElevated != 0)
    }
}

pub mod sd {
    use crate::error::WinError;
    use crate::sd::SecurityDescriptor;
    use crate::utils::WideCString;
    use std::ffi::OsStr;
    use std::path::Path;
    use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        SACL_SECURITY_INFORMATION,
    };

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
                DACL_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | OWNER_SECURITY_INFORMATION
                    | SACL_SECURITY_INFORMATION,
            )
        }
    }
}
