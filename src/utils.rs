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

    /// Creates a `WideCString` from a null-terminated wide string pointer.
    ///
    /// The pointer must be valid and point to a null-terminated UTF-16 string.
    /// A maximum length limit is enforced to prevent unbounded reads from invalid pointers.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `ptr` points to a valid, null-terminated UTF-16 string
    /// - The string is properly null-terminated within the maximum length limit
    /// - The memory remains valid during the execution of this function
    ///
    /// # Arguments
    ///
    /// * `ptr` - A pointer to a null-terminated wide string (may be null).
    ///
    /// must LocalFree the pointer after using->and owning the value
    pub fn from_wide_null_ptr(ptr: *const u16) -> Self {
        if ptr.is_null() {
            return Self { inner: Vec::new() };
        }

        // Maximum length limit to prevent unbounded reads from invalid pointers.
        // Windows paths can be up to MAX_PATH (260) characters, extended paths up to 32767.
        // Using 8192 as a generous but safe upper bound for most Windows API strings.
        const MAX_LENGTH: usize = 8192;

        unsafe {
            let mut len = 0;
            while len < MAX_LENGTH {
                if *ptr.add(len) == 0 {
                    break;
                }
                len += 1;
            }

            // If we hit the limit without finding null terminator, truncate at max length
            // This prevents reading beyond potentially invalid memory
            if len >= MAX_LENGTH {
                // Log a warning in debug builds
                #[cfg(debug_assertions)]
                eprintln!(
                    "Warning: WideCString::from_wide_null_ptr hit maximum length limit ({}), string may not be null-terminated",
                    MAX_LENGTH
                );
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
