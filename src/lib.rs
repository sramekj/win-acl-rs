//! This crate provides a simple and safe abstraction over Windows ACLs and security descriptors.
//!
//! See *examples* folder

//#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![cfg(windows)]

pub mod acl;
pub mod elevated;
pub mod sd;
pub mod sid;
pub mod trustee;
mod utils;
pub mod wellknown;

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
    #[derive(Clone, Eq, PartialEq, Default)]
    pub struct WinError {
        pub code: u32,
        pub message: Option<String>,
    }

    impl Display for WinError {
        fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
            if let Some(msg) = &self.message {
                write!(f, "{}", msg)?
            }
            write!(f, "HRESULT: {:#010x}", self.code)
        }
    }

    impl Debug for WinError {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("WinError")
                .field("code", &format_args!("HRESULT: {:#010x}", self.code))
                .field("message", &format_args!("{:?}", self.message))
                .finish()
        }
    }

    impl From<WIN32_ERROR> for WinError {
        fn from(value: WIN32_ERROR) -> Self {
            WinError {
                code: value,
                message: None,
            }
        }
    }

    impl From<String> for WinError {
        fn from(value: String) -> Self {
            WinError {
                code: 0,
                message: Some(value),
            }
        }
    }

    impl From<&str> for WinError {
        fn from(value: &str) -> Self {
            WinError {
                code: 0,
                message: Some(value.to_owned()),
            }
        }
    }
}
