//! this module exposes functions that require elevated privileges
//! the process requires "SE_SECURITY_NAME" (*SeSecurityPrivilege*) privilege, would otherwise return WIN32_ERROR(1314) => "A required privilege is not held by the client"
//! you can run `whoami /priv` to check it. You typically need to run the process as an Administrator and enable it using enable_se_security_privilege().

use std::{ffi::OsStr, marker::PhantomData, path::Path, ptr, ptr::null_mut};

use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, LUID},
    Security::{
        AdjustTokenPrivileges,
        Authorization::{SE_FILE_OBJECT, SE_OBJECT_TYPE},
        GetTokenInformation, LookupPrivilegeValueW, OBJECT_SECURITY_INFORMATION, SE_PRIVILEGE_ENABLED,
        SE_SECURITY_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenElevation,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

use crate::{
    error::WinError,
    sd::{ObjectSecurityEx, SecurityDescriptorImpl},
    utils::WideCString,
    winapi_bool_call,
};

/// A type alias for an elevated security descriptor.
///
/// This type can access all security information, including SACLs.
/// Requires an elevated privilege token to create. See `SecurityDescriptorImpl<Elevated>`
/// for available methods.
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

/// Checks if the current process is running with Administrator privileges.
///
/// This checks if the process token has the elevation flag set, which indicates
/// that the process is running with elevated privileges (typically as Administrator).
///
/// # Returns
///
/// `Ok(true)` if the process is running as Administrator, `Ok(false)` otherwise.
/// Returns an error if the check cannot be performed.
///
/// # Examples
///
/// ```no_run
/// use win_acl_rs::elevated::is_admin;
///
/// if is_admin()? {
///     println!("Running as Administrator");
/// } else {
///     println!("Not running as Administrator");
/// }
/// # Ok::<(), win_acl_rs::error::WinError>(())
/// ```
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

/// A marker trait for privilege levels.
///
/// Types implementing this trait represent different privilege levels for security operations.
/// This is used as a type parameter to security descriptor types to ensure that elevated
/// operations (like accessing SACLs) are only performed with proper privileges.
pub trait PrivilegeLevel {}

/// Marker type representing an unprivileged context.
///
/// Security descriptors with this privilege level can access standard security information
/// (owner, group, DACL) but cannot access SACLs.
#[derive(Debug)]
pub struct Unprivileged;

/// Marker type representing an elevated privilege context.
///
/// Security descriptors with this privilege level can access all security information,
/// including SACLs. Requires the `SE_SECURITY_NAME` privilege to be enabled.
#[derive(Debug)]
pub struct Elevated;

impl PrivilegeLevel for Unprivileged {}
impl PrivilegeLevel for Elevated {}

/// A type alias for an unprivileged privilege token.
///
/// This is the starting point for privilege management. Use `try_elevate()` to obtain
/// elevated privileges when needed.
pub type PrivilegeToken = PrivilegeTokenImpl<Unprivileged>;

/// Represents a privilege token with a specific privilege level.
///
/// This type is used to ensure that elevated operations (like accessing SACLs) are only
/// performed with proper privileges. The type parameter `P` indicates the privilege level:
/// - `Unprivileged`: Standard privileges (can access DACLs)
/// - `Elevated`: Elevated privileges (can access SACLs, requires `SE_SECURITY_NAME`)
///
/// # Examples
///
/// ```no_run
/// use win_acl_rs::elevated::PrivilegeToken;
///
/// let token = PrivilegeToken::new();
/// match token.try_elevate() {
///     Ok(elevated) => {
///         // Can now access SACLs
///         println!("Elevated privileges obtained");
///     }
///     Err(e) => {
///         println!("Failed to elevate: {}", e);
///     }
/// }
/// ```
#[derive(Debug)]
pub struct PrivilegeTokenImpl<P: PrivilegeLevel> {
    _marker: PhantomData<P>,
}

impl PrivilegeTokenImpl<Unprivileged> {
    /// Creates a new unprivileged token.
    ///
    /// This is the starting state for privilege management. Use `try_elevate()` to obtain
    /// elevated privileges when needed.
    pub fn new() -> Self {
        Self { _marker: PhantomData }
    }

    /// Attempts to elevate privileges to enable access to SACLs.
    ///
    /// This enables the `SE_SECURITY_NAME` privilege, which is required to read or modify
    /// System Access Control Lists (SACLs). The process typically needs to be running as
    /// Administrator for this to succeed.
    ///
    /// # Returns
    ///
    /// `Ok(PrivilegeTokenImpl<Elevated>)` if elevation succeeds, or an error if it fails
    /// (e.g., process is not running as Administrator, or privilege cannot be enabled).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use win_acl_rs::elevated::PrivilegeToken;
    ///
    /// let token = PrivilegeToken::new();
    /// let elevated = token.try_elevate()?;
    /// // Now can access SACLs
    /// # Ok::<(), win_acl_rs::error::WinError>(())
    /// ```
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
    /// Drops elevated privileges and returns to an unprivileged state.
    ///
    /// This disables the `SE_SECURITY_NAME` privilege and returns an unprivileged token.
    /// Useful for security best practices - only hold elevated privileges when needed.
    ///
    /// # Returns
    ///
    /// An `PrivilegeTokenImpl<Unprivileged>` representing the unprivileged state.
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
