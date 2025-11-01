//! Trustee representation for Windows security APIs.
//!
//! A trustee represents a security principal (user, group, or computer) that can be granted
//! or denied access rights. This module provides a safe wrapper around Windows trustee structures
//! that can reference security principals by SID or by name.

use std::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
    ptr::null_mut,
    str::FromStr,
};

pub use windows_sys::Win32::Security::Authorization::TRUSTEE_TYPE;
use windows_sys::Win32::Security::Authorization::{
    NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_NAME, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};

use crate::{
    error::WinError,
    sid::{AsSidRef, SidRef},
    utils::WideCString,
};

/// Represents a security principal (trustee) that can be granted or denied access.
///
/// A trustee can reference a security principal either by SID (Security Identifier) or by name.
/// This type is used when working with Windows security APIs that require trustee structures.
///
/// # Examples
///
/// ```no_run
/// use win_acl_rs::{trustee::Trustee, sid::Sid, wellknown::WinBuiltinAdministratorsSid};
///
/// // Create from well-known SID
/// let sid = Sid::from_well_known_sid(WinBuiltinAdministratorsSid)?;
/// let trustee = sid.as_trustee();
///
/// // Or create from string SID
/// let sid_str = Sid::from_string("S-1-5-32-544")?;
/// let trustee = sid_str.as_trustee();
///
/// // Create from name
/// let trustee = Trustee::from_name("BUILTIN\\Administrators");
/// # Ok::<(), win_acl_rs::error::WinError>(())
/// ```
pub struct Trustee<'a> {
    inner: TRUSTEE_W,
    _inner_wide_name: Option<WideCString>,
    _phantom: PhantomData<SidRef<'a>>,
}

impl<'a> Trustee<'a> {
    /// Creates a trustee from a SID reference.
    ///
    /// # Arguments
    ///
    /// * `sid_ref` - A reference to a SID (Security Identifier).
    ///
    /// # Returns
    ///
    /// A `Trustee` that references the security principal identified by the SID.
    pub fn from_sid_ref(sid_ref: SidRef<'a>) -> Self {
        let sid_ref = sid_ref.as_sid_ref();
        let trustee = TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid_ref.as_ptr() as *mut _,
        };
        Self {
            inner: trustee,
            _inner_wide_name: None,
            _phantom: PhantomData,
        }
    }

    /// Creates a trustee from an account name.
    ///
    /// The account name can be in formats like:
    /// - `"DOMAIN\\Username"` (domain-qualified)
    /// - `"Username"` (local account)
    /// - `"BUILTIN\\Administrators"` (built-in group)
    ///
    /// # Arguments
    ///
    /// * `name` - The account name string.
    ///
    /// # Returns
    ///
    /// A `Trustee` that references the security principal identified by the name.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use win_acl_rs::trustee::Trustee;
    ///
    /// let trustee = Trustee::from_name("BUILTIN\\Administrators");
    /// ```
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

    /// Sets the trustee type.
    ///
    /// The trustee type specifies what kind of security principal this is (user, group, etc.).
    ///
    /// # Arguments
    ///
    /// * `trustee_type` - The `TRUSTEE_TYPE` value.
    ///
    /// # Returns
    ///
    /// The `Trustee` with the type set (for method chaining).
    pub fn with_type(mut self, trustee_type: TRUSTEE_TYPE) -> Self {
        self.inner.TrusteeType = trustee_type;
        self
    }

    /// Returns the account name if this trustee was created from a name.
    ///
    /// If the trustee was created from a SID, this returns `None`.
    ///
    /// # Returns
    ///
    /// `Some(String)` containing the account name, or `None` if the trustee references a SID.
    pub fn get_name(&self) -> Option<String> {
        self._inner_wide_name.as_ref().map(|s| s.as_string())
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
