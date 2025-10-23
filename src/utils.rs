use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

pub struct WideCString {
    inner: Vec<u16>,
}

impl WideCString {
    pub fn new<S>(s: &S) -> Self
    where
        S: AsRef<OsStr> + ?Sized,
    {
        let inner = s.as_ref().encode_wide().chain(Some(0)).collect();
        Self { inner }
    }

    pub fn as_ptr(&self) -> *const u16 {
        self.inner.as_ptr()
    }

    pub fn from_wide_slice(slice: &[u16]) -> Self {
        let inner = slice
            .iter()
            .cloned()
            .take_while(|&n| n != 0)
            .collect::<Vec<u16>>();
        Self { inner }
    }

    pub fn as_os_string(&self) -> OsString {
        OsString::from_wide(self.inner.as_ref())
    }
}

impl AsRef<WideCString> for WideCString {
    fn as_ref(&self) -> &WideCString {
        self
    }
}
