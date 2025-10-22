#![cfg(windows)]

pub mod acl;
pub mod elevated;
pub mod sd;
pub mod sid;
mod utils;

pub mod error {
    use std::fmt::Formatter;
    use windows_sys::Win32::Foundation::WIN32_ERROR;

    pub type Result<T> = std::result::Result<T, WinError>;

    #[derive(Copy, Clone, Eq, PartialEq, Default)]
    pub struct WinError(pub u32);

    impl std::fmt::Display for WinError {
        fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
            write!(f, "{:#010x}", self.0)
        }
    }

    impl std::fmt::Debug for WinError {
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
