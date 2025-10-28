//! TODO

use crate::error::WinError;
use crate::sid::Sid;
use crate::utils::WideCString;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::ptr::null_mut;
use std::str::FromStr;
pub use windows_sys::Win32::Security::Authorization::TRUSTEE_TYPE;
use windows_sys::Win32::Security::Authorization::{
    NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_NAME, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::SID;

/// TODO
pub struct Trustee<'a> {
    inner: TRUSTEE_W,
    _inner_wide_name: Option<WideCString>,
    _phantom: PhantomData<&'a SID>,
}

impl<'a> Trustee<'a> {
    pub fn from_sid(sid: &'a Sid) -> Self {
        let trustee = TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.as_ptr() as *mut _,
        };
        Self {
            inner: trustee,
            _inner_wide_name: None,
            _phantom: PhantomData,
        }
    }

    pub fn from_name<S>(name: S) -> Self
    where
        S: AsRef<str>,
    {
        let wide_name = WideCString::new(name.as_ref());
        let trustee = TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_NAME,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: wide_name.as_ptr() as *mut _,
        };
        Self {
            inner: trustee,
            _inner_wide_name: Some(wide_name),
            _phantom: PhantomData,
        }
    }

    pub fn with_type(mut self, trustee_type: TRUSTEE_TYPE) -> Self {
        self.inner.TrusteeType = trustee_type;
        self
    }

    pub fn get_name(&self) -> Option<String> {
        self._inner_wide_name.as_ref().map(|s| s.as_string())
    }
}

impl<'a> From<&'a Sid> for Trustee<'a> {
    fn from(sid: &'a Sid) -> Self {
        sid.as_trustee()
    }
}

impl FromStr for Trustee<'_> {
    type Err = WinError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Trustee::from_name(s))
    }
}

impl Debug for Trustee<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trustee")
            .field("pMultipleTrustee", &self.inner.pMultipleTrustee)
            .field("MultipleTrusteeOperation", &self.inner.MultipleTrusteeOperation)
            .field("TrusteeForm", &self.inner.TrusteeForm)
            .field("TrusteeType", &self.inner.TrusteeType)
            .field("ptstrName", &self.inner.ptstrName)
            .finish()
    }
}
