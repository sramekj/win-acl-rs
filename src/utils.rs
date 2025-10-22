use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

pub struct WideCString {
    inner: Vec<u16>,
}

impl WideCString {
    pub fn new<S>(s: S) -> Self
    where
        S: AsRef<OsStr>,
    {
        let inner = s.as_ref().encode_wide().chain(Some(0)).collect();
        Self { inner }
    }

    pub fn as_ptr(&self) -> *const u16 {
        self.inner.as_ptr()
    }
}

impl AsRef<WideCString> for WideCString {
    fn as_ref(&self) -> &WideCString {
        self
    }
}
