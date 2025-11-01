//! A simple and safe abstraction over Windows ACLs (Access Control Lists) and security descriptors.
//!
//! This crate provides Rust-friendly wrappers around Windows security APIs, allowing you to:
//! - Create and manipulate ACLs and ACEs (Access Control Entries)
//! - Work with security descriptors (SDs)
//! - Handle SIDs (Security Identifiers) and well-known security principals
//! - Query and modify file, registry, service, and other object permissions
//! - Support both standard and elevated privilege operations
//!
//! # Examples
//!
//! See the `examples` folder for usage examples.
//!
//! # Windows Only
//!
//! This crate is only available on Windows platforms.

//#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![cfg(windows)]

pub mod acl;
pub mod elevated;
pub mod mask;
pub mod sd;
pub mod sid;
pub mod trustee;
mod utils;
pub mod wellknown;

mod macros;

pub use windows_sys::Win32::Security::Authorization::{
    SE_DS_OBJECT, SE_DS_OBJECT_ALL, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_LMSHARE, SE_OBJECT_TYPE, SE_PRINTER,
    SE_PROVIDER_DEFINED_OBJECT, SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY, SE_REGISTRY_WOW64_64KEY, SE_SERVICE,
    SE_UNKNOWN_OBJECT_TYPE, SE_WINDOW_OBJECT,
};

/// Error definitions for Windows API operations.
pub mod error {
    use std::fmt::{Debug, Display, Formatter};

    use windows_sys::Win32::Foundation::WIN32_ERROR;

    /// A result type alias for operations that may fail with a Windows API error.
    ///
    /// This is a convenience alias for `std::result::Result<T, WinError>`.
    pub type Result<T> = std::result::Result<T, WinError>;

    /// Represents a Windows API error.
    ///
    /// This error type encapsulates Windows API error codes (HRESULT values) and optionally
    /// includes a human-readable error message for cases where the error code alone is insufficient.
    ///
    /// Error codes are typically displayed in hexadecimal format (e.g., `0x00000005` for
    /// `ERROR_ACCESS_DENIED`).
    ///
    /// See [MSDN](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-)
    /// for information about Windows error codes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use win_acl_rs::error::WinError;
    ///
    /// let error = WinError {
    ///     code: 0x00000005, // ERROR_ACCESS_DENIED
    ///     message: None,
    /// };
    /// println!("Error: {}", error);
    /// ```
    #[derive(Clone, Eq, PartialEq, Default)]
    pub struct WinError {
        /// The Windows error code (HRESULT) in hexadecimal format.
        pub code: u32,
        /// An optional human-readable error message, used when the error code alone is insufficient.
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
