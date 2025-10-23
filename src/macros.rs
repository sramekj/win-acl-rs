#[macro_export]
macro_rules! winapi_bool_call {
    ($expr:expr, $cleanup:block) => {{
        let result = $expr;
        if result == 0 {
            $cleanup
            #[allow(unused_unsafe)]
            return core::result::Result::Err(unsafe { windows_sys::Win32::Foundation::GetLastError().into() });
        }
    }};
    ($expr:expr) => {{
        let result = $expr;
        if result == 0 {
            #[allow(unused_unsafe)]
            return core::result::Result::Err(unsafe { windows_sys::Win32::Foundation::GetLastError().into() });
        }
    }};
}

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
