use std::{
    ffi::{OsStr, OsString},
    os::windows::ffi::{OsStrExt, OsStringExt},
};

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
        let inner = slice.iter().cloned().take_while(|&n| n != 0).collect::<Vec<u16>>();
        Self { inner }
    }

    /// must LocalFree the pointer after using->and owning the value
    pub fn from_wide_null_ptr(ptr: *const u16) -> Self {
        if ptr.is_null() {
            return Self { inner: Vec::new() };
        }
        unsafe {
            let mut len = 0;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(ptr, len);
            Self { inner: slice.to_vec() }
        }
    }

    #[allow(dead_code)]
    pub fn as_os_string(&self) -> OsString {
        OsString::from_wide(self.inner.as_ref())
    }

    pub fn as_string(&self) -> String {
        String::from_utf16_lossy(self.inner.as_ref())
    }
}

impl AsRef<WideCString> for WideCString {
    fn as_ref(&self) -> &WideCString {
        self
    }
}
