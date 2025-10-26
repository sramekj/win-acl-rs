/// Windows api call that returns boolean result
///
/// expands approximately to:
/// ```text
/// let err = unsafe_call();
/// if result = 0 {
///     { optional cleanup block }
///     return Err(unsafe { GetLastError().into() });
/// }
/// ```
///
#[macro_export]
macro_rules! winapi_bool_call {
    ($expr:expr, $cleanup:block) => {{
        let result = $expr;
        if result == windows_sys::Win32::Foundation::FALSE {
            $cleanup
            #[allow(unused_unsafe)]
            return core::result::Result::Err(unsafe { windows_sys::Win32::Foundation::GetLastError().into() });
        }
    }};
    ($expr:expr) => {{
        let result = $expr;
        if result == windows_sys::Win32::Foundation::FALSE {
            #[allow(unused_unsafe)]
            return core::result::Result::Err(unsafe { windows_sys::Win32::Foundation::GetLastError().into() });
        }
    }};
}

/// Windows api call that returns error code result
///
/// expands approximately to:
/// ```text
/// let err = unsafe_call();
/// if result != ERROR_SUCCESS {
///     { optional cleanup block }
///     return Err(result.into());
/// }
/// ```
///
#[macro_export]
macro_rules! winapi_call {
     ($expr:expr, $cleanup:block) => {{
        let result = $expr;
        if result != windows_sys::Win32::Foundation::ERROR_SUCCESS {
            $cleanup
            rreturn core::result::Result::Err(result.into());
        }
    }};
    ($expr:expr) => {{
        let result = $expr;
        if result != windows_sys::Win32::Foundation::ERROR_SUCCESS {
            return core::result::Result::Err(result.into());
        }
    }};
}

/// Calls LocalFree and asserts no errors
///
/// expands approximately to:
/// ```text
/// if !ptr.is_null {
///      let freed = LocalFree(ptr as _);
///      debug_assert!(freed.is_null(), concat!("LocalFree failed in ", loc, "!"));
/// } else {
///      #[cfg(debug_assertions)]
///      eprintln!("Pointer is already null in {}", loc);
/// }
/// ```
///
#[macro_export]
macro_rules! assert_free {
    ($ptr:expr, $loc:expr) => {{
        let ptr = $ptr;
        let loc = $loc;
        if !ptr.is_null() {
            let freed = windows_sys::Win32::Foundation::LocalFree(ptr as _);
            debug_assert!(freed.is_null(), concat!("LocalFree failed in ", $loc, "!"));
        } else {
            #[cfg(debug_assertions)]
            eprintln!("Pointer is already null in {}", loc);
        }
    }};
}
