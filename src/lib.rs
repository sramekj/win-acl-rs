//! This crate provides a simple and safe abstraction over Windows ACLs and security descriptors.
//!
//! See *examples* folder

#![warn(missing_docs, missing_debug_implementations)]
#![cfg(windows)]

pub mod acl;
pub mod elevated;
pub mod sd;
pub mod sid;
mod utils;

mod macros;

pub use windows_sys::Win32::Security::Authorization::{
    SE_DS_OBJECT, SE_DS_OBJECT_ALL, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_LMSHARE, SE_OBJECT_TYPE,
    SE_PRINTER, SE_PROVIDER_DEFINED_OBJECT, SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY,
    SE_REGISTRY_WOW64_64KEY, SE_SERVICE, SE_UNKNOWN_OBJECT_TYPE, SE_WINDOW_OBJECT,
};

/// Contains error definitions
pub mod error {
    use std::fmt::{Debug, Display, Formatter};
    use windows_sys::Win32::Foundation::WIN32_ERROR;

    /// Result helper type
    pub type Result<T> = std::result::Result<T, WinError>;

    /// WinError represents a WinAPI error, typically in hexadecimal format as an HRESULT
    ///
    /// see: [MSDN](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-)
    ///
    #[derive(Copy, Clone, Eq, PartialEq, Default)]
    pub struct WinError(pub u32);

    impl Display for WinError {
        fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
            write!(f, "{:#010x}", self.0)
        }
    }

    impl Debug for WinError {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("WinError")
                .field("HRESULT", &format_args!("{:#010x}", self.0))
                .finish()
        }
    }

    impl From<WIN32_ERROR> for WinError {
        fn from(value: WIN32_ERROR) -> Self {
            WinError(value)
        }
    }
}

#[cfg(test)]
mod tests;
