//! Security Identifier (SID) operations.
//!
//! A SID is a unique value of variable length used to identify a security principal or group
//! in Windows security contexts. This module provides safe wrappers for creating, parsing,
//! and manipulating SIDs, as well as looking up account names from SIDs and vice versa.
//!
//! # Examples
//!
//! ```no_run
//! use win_acl_rs::sid::Sid;
//! use win_acl_rs::wellknown::WinWorldSid;
//!
//! // Create a SID from a well-known SID constant
//! let sid = Sid::from_well_known_sid(WinWorldSid)?; // Everyone SID
//!
//! // Or create from a string representation
//! let admin_sid = Sid::from_string("S-1-5-32-544")?; // Administrators
//!
//! // Look up the account name
//! let lookup = sid.lookup_name()?;
//! println!("Account: {}/{}", lookup.domain, lookup.name);
//!
//! // Convert to string
//! let sid_string = sid.to_string()?;
//! println!("SID: {}", sid_string);
//! # Ok::<(), win_acl_rs::error::WinError>(())
//! ```

use std::{
    fmt::{Debug, Display, Formatter},
    hash::Hash,
    marker::PhantomData,
    ptr::null_mut,
    str::FromStr,
};

use windows_sys::Win32::{
    Foundation::{ERROR_OUTOFMEMORY, FALSE, GetLastError},
    Security::{
        Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW},
        CreateWellKnownSid, GetLengthSid, IsValidSid, PSID, SECURITY_MAX_SID_SIZE, SID, WELL_KNOWN_SID_TYPE,
    },
    System::Memory::{LMEM_FIXED, LocalAlloc},
};

use crate::{
    assert_free,
    error::WinError,
    sid::account::{AccountLookup, lookup_account_name, lookup_account_sid},
    trustee::Trustee,
    utils::WideCString,
    winapi_bool_call,
};

/// Trait for types that can be converted to a `SidRef`.
///
/// This trait allows flexible usage of both owned (`Sid`) and borrowed (`SidRef`) SIDs
/// in contexts where a SID reference is needed (e.g., when adding ACEs to an ACL).
pub trait AsSidRef<'a> {
    /// Converts this value to a `SidRef`.
    fn as_sid_ref(&'a self) -> SidRef<'a>;
}

/// An owned Security Identifier (SID).
///
/// A SID is a unique identifier for a security principal (user, group, computer, etc.)
/// in Windows. This type owns the SID data and can be used independently.
///
/// SIDs can be created from:
/// - String representation (e.g., "S-1-1-0")
/// - Raw bytes
/// - Well-known SID types
/// - Account names (requires lookup)
///
/// # Examples
///
/// ```no_run
/// use win_acl_rs::{sid::Sid, wellknown::WinBuiltinAdministratorsSid};
///
/// // From well-known SID (recommended)
/// let sid = Sid::from_well_known_sid(WinBuiltinAdministratorsSid)?;
///
/// // Or from string
/// let sid_str = Sid::from_string("S-1-5-32-544")?; // Administrators
/// # Ok::<(), win_acl_rs::error::WinError>(())
/// ```
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct Sid {
    data: Vec<u8>,
}

/// A borrowed reference to a Security Identifier (SID).
///
/// This type represents a non-owned reference to a SID structure. It's useful when
/// working with SIDs that are part of larger structures (like security descriptors)
/// where you don't want to copy the SID data.
///
/// # Safety
///
/// The underlying SID pointer must remain valid for the lifetime `'a`.
#[derive(Clone, Copy)]
pub struct SidRef<'a> {
    ptr: *const SID,
    _p: PhantomData<&'a SID>,
}

impl FromStr for Sid {
    type Err = WinError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Sid::from_string(s)
    }
}

impl Display for Sid {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = self.to_string().unwrap_or_else(|_| "<invalid sid>".into());
        f.write_str(&str)
    }
}

impl TryFrom<&[u8]> for Sid {
    type Error = WinError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl From<Sid> for Vec<u8> {
    fn from(sid: Sid) -> Self {
        sid.to_vec()
    }
}

impl Sid {
    /// Creates a SID from raw byte data.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw SID byte data.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte data does not represent a valid SID structure.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WinError> {
        Ok(Self { data: bytes.to_vec() })
    }

    /// Creates a SID from its string representation.
    ///
    /// The string format is typically "S-1-X-Y-Z..." where each component is a number.
    /// For example, "S-1-1-0" is the Everyone SID, and "S-1-5-32-544" is Administrators.
    ///
    /// # Arguments
    ///
    /// * `s` - A string or string-like type containing the SID string representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not a valid SID format or cannot be converted.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use win_acl_rs::sid::Sid;
    /// use win_acl_rs::wellknown::{WinWorldSid, WinBuiltinAdministratorsSid};
    ///
    /// // Using well-known SID constants
    /// let everyone = Sid::from_well_known_sid(WinWorldSid)?;
    /// let admins = Sid::from_well_known_sid(WinBuiltinAdministratorsSid)?;
    ///
    /// // Or using string representation
    /// let everyone_str = Sid::from_string("S-1-1-0")?;
    /// # Ok::<(), win_acl_rs::error::WinError>(())
    /// ```
    pub fn from_string<S>(s: S) -> Result<Self, WinError>
    where
        S: AsRef<str>,
    {
        let wide = WideCString::new(s.as_ref());
        let mut sid_ptr: PSID = null_mut();
        let err = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid_ptr) };
        if err == FALSE || sid_ptr.is_null() {
            return Err(unsafe { GetLastError().into() });
        }
        let len = unsafe { GetLengthSid(sid_ptr) as usize };
        let data = unsafe { std::slice::from_raw_parts(sid_ptr as *const u8, len) }.to_vec();

        unsafe { assert_free!(sid_ptr, "Sid::from_string") };

        Ok(Sid { data })
    }

    /// Creates a SID for a well-known security principal.
    ///
    /// Well-known SIDs are predefined by Windows for common principals like
    /// Everyone, Administrators, System, etc.
    ///
    /// # Arguments
    ///
    /// * `kind` - The well-known SID type (e.g., `WinBuiltinAdministratorsSid`, `WinWorldSid`).
    ///
    /// # Errors
    ///
    /// Returns an error if the well-known SID cannot be created.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use win_acl_rs::{sid::Sid, wellknown::WinBuiltinAdministratorsSid};
    ///
    /// let admin_sid = Sid::from_well_known_sid(WinBuiltinAdministratorsSid)?;
    /// # Ok::<(), win_acl_rs::error::WinError>(())
    /// ```
    pub fn from_well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> Result<Self, WinError> {
        Self::from_well_known_sid_and_domain(kind, None)
    }

    /// Creates a SID for a well-known security principal, optionally in a specific domain.
    ///
    /// This is useful for domain-relative well-known SIDs.
    ///
    /// # Arguments
    ///
    /// * `kind` - The well-known SID type.
    /// * `domain_sid_ptr` - Optional domain SID to scope the well-known SID to.
    ///
    /// # Errors
    ///
    /// Returns an error if the well-known SID cannot be created.
    pub fn from_well_known_sid_and_domain(
        kind: WELL_KNOWN_SID_TYPE,
        domain_sid_ptr: Option<SidRef>,
    ) -> Result<Self, WinError> {
        let mut buf = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = buf.len() as u32;
        let domain = match domain_sid_ptr {
            None => null_mut() as PSID,
            Some(sid_ref) => sid_ref.ptr as PSID,
        };
        unsafe { winapi_bool_call!(CreateWellKnownSid(kind, domain, buf.as_mut_ptr() as PSID, &mut size)) };
        Self::from_bytes(&buf[..size as usize])
    }

    /// Creates a SID by looking up an account name.
    ///
    /// The account name can be in formats like:
    /// - `"DOMAIN\\Username"` (domain-qualified)
    /// - `"Username"` (local account)
    /// - `"BUILTIN\\Administrators"` (built-in group)
    ///
    /// # Arguments
    ///
    /// * `name` - The account name to look up.
    ///
    /// # Errors
    ///
    /// Returns an error if the account name cannot be found or resolved to a SID.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use win_acl_rs::sid::Sid;
    ///
    /// // Look up by account name
    /// let sid = Sid::from_account_name("BUILTIN\\Administrators")?;
    /// # Ok::<(), win_acl_rs::error::WinError>(())
    /// ```
    pub fn from_account_name<S>(name: S) -> Result<Self, WinError>
    where
        S: AsRef<str>,
    {
        unsafe { lookup_account_name(name).map(|a| Self::from_string(&a.name).unwrap()) }
    }

    /// Looks up the account name and domain for this SID.
    ///
    /// Performs a reverse lookup from SID to account name using Windows account resolution APIs.
    ///
    /// # Returns
    ///
    /// An `AccountLookup` containing the account name, domain, and SID type, or an error
    /// if the lookup fails (e.g., if the SID doesn't correspond to a known account).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use win_acl_rs::{sid::Sid, wellknown::WinBuiltinAdministratorsSid};
    ///
    /// // Using well-known SID
    /// let sid = Sid::from_well_known_sid(WinBuiltinAdministratorsSid)?;
    /// let lookup = sid.lookup_name()?;
    /// println!("Account: {}\\{}", lookup.domain, lookup.name);
    ///
    /// // Or using string representation
    /// let sid_str = Sid::from_string("S-1-5-32-544")?;
    /// # Ok::<(), win_acl_rs::error::WinError>(())
    /// ```
    pub fn lookup_name(&self) -> Result<AccountLookup, WinError> {
        unsafe { lookup_account_sid(self.data.as_ptr() as PSID) }
    }

    /// Checks if this SID is valid.
    ///
    /// Validates that the SID structure is properly formatted according to Windows security APIs.
    ///
    /// # Returns
    ///
    /// `true` if the SID is valid, `false` otherwise.
    pub fn is_valid(&self) -> bool {
        unsafe { IsValidSid(self.data.as_ptr() as PSID) != FALSE }
    }

    /// Returns the length of the SID in bytes.
    ///
    /// # Returns
    ///
    /// The size of the SID structure in bytes.
    pub fn len(&self) -> usize {
        unsafe { GetLengthSid(self.data.as_ptr() as PSID) as usize }
    }

    /// Checks if the SID is empty (zero length).
    ///
    /// # Returns
    ///
    /// `true` if the SID has zero length, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Converts the SID to its string representation.
    ///
    /// The string format is "S-1-X-Y-Z..." where each component is a number.
    ///
    /// # Returns
    ///
    /// A string representation of the SID, or an error if conversion fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use win_acl_rs::{sid::Sid, wellknown::WinWorldSid};
    ///
    /// // Using well-known SID
    /// let sid = Sid::from_well_known_sid(WinWorldSid)?;
    /// let sid_string = sid.to_string()?;
    /// assert_eq!(sid_string, "S-1-1-0");
    ///
    /// // Or using string representation
    /// let sid_str = Sid::from_string("S-1-1-0")?;
    /// # Ok::<(), win_acl_rs::error::WinError>(())
    /// ```
    pub fn to_string(&self) -> Result<String, WinError> {
        let mut str_ptr: *mut u16 = null_mut();
        unsafe { winapi_bool_call!(ConvertSidToStringSidW(self.data.as_ptr() as PSID, &mut str_ptr)) }
        let result = WideCString::from_wide_null_ptr(str_ptr).as_string();
        unsafe { assert_free!(str_ptr, "Sid::to_string") };
        Ok(result)
    }

    /// Converts this SID to a `Trustee` for use with Windows trustee APIs.
    ///
    /// # Returns
    ///
    /// A `Trustee` that references this SID.
    pub fn as_trustee(&'_ self) -> Trustee<'_> {
        Trustee::from_sid_ref(self)
    }

    /// Converts the SID to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the raw SID byte data.
    pub fn to_vec(&self) -> Vec<u8> {
        self.data.clone()
    }
}

impl<'a> AsSidRef<'a> for Sid {
    fn as_sid_ref(&self) -> SidRef<'a> {
        unsafe { SidRef::from_ptr(self.data.as_ptr() as _) }
    }
}

impl Debug for Sid {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let account = match &self.lookup_name() {
            Ok(acc) => format!("{}/{}", acc.domain, acc.name),
            Err(_) => "<ACCOUNT LOOKUP ERROR>".to_string(),
        };
        f.debug_struct("Sid")
            .field(
                "as_string",
                &self.to_string().unwrap_or_else(|_| "<INVALID SID>".to_string()),
            )
            .field("is_valid", &self.is_valid())
            .field("data", &self.data)
            .field("len", &self.len())
            .field("account", &account)
            .finish()
    }
}

impl<'a, T: AsSidRef<'a> + ?Sized> AsSidRef<'a> for &T {
    fn as_sid_ref(&'a self) -> SidRef<'a> {
        (*self).as_sid_ref()
    }
}

impl<'a> SidRef<'a> {
    /// Creates a `SidRef` from a raw Windows SID pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `ptr` points to a valid, initialized SID structure
    /// - The SID remains valid for the lifetime `'a`
    /// - The SID is not freed while the `SidRef` is in use
    ///
    /// # Arguments
    ///
    /// * `ptr` - A pointer to a valid Windows `SID` structure.
    ///
    /// # Returns
    ///
    /// A `SidRef` that borrows the SID at `ptr`.
    pub unsafe fn from_ptr(ptr: *const SID) -> Self {
        Self { ptr, _p: PhantomData }
    }

    /// Looks up the account name and domain for this SID.
    ///
    /// # Safety
    ///
    /// The SID pointer must be valid and remain valid during the lookup operation.
    ///
    /// # Returns
    ///
    /// An `AccountLookup` containing the account name, domain, and SID type, or an error
    /// if the lookup fails.
    pub unsafe fn lookup_name(&self) -> Result<AccountLookup, WinError> {
        unsafe { lookup_account_sid(self.ptr as PSID) }
    }

    /// Checks if this SID is valid.
    ///
    /// # Safety
    ///
    /// The SID pointer must be valid.
    ///
    /// # Returns
    ///
    /// `true` if the SID is valid, `false` otherwise.
    pub unsafe fn is_valid(&self) -> bool {
        unsafe { IsValidSid(self.ptr as PSID) != FALSE }
    }

    /// Returns the length of the SID in bytes.
    ///
    /// # Safety
    ///
    /// The SID pointer must be valid.
    ///
    /// # Returns
    ///
    /// The size of the SID structure in bytes.
    pub unsafe fn len(&self) -> usize {
        unsafe { GetLengthSid(self.ptr as PSID) as usize }
    }

    /// Checks if the SID is empty (zero length).
    ///
    /// # Safety
    ///
    /// The SID pointer must be valid.
    ///
    /// # Returns
    ///
    /// `true` if the SID has zero length, `false` otherwise.
    pub unsafe fn is_empty(&self) -> bool {
        unsafe { self.len() == 0 }
    }

    /// Converts the SID to its string representation.
    ///
    /// # Returns
    ///
    /// A string representation of the SID, or an error if conversion fails.
    pub fn to_string(&self) -> Result<String, WinError> {
        let mut str_ptr: *mut u16 = null_mut();
        unsafe { winapi_bool_call!(ConvertSidToStringSidW(self.ptr as PSID, &mut str_ptr)) }
        let result = WideCString::from_wide_null_ptr(str_ptr).as_string();
        unsafe {
            assert_free!(str_ptr, "SidRef<'a>::to_string");
        }
        Ok(result)
    }

    /// Converts this SID to a `Trustee` for use with Windows trustee APIs.
    ///
    /// # Returns
    ///
    /// A `Trustee` that references this SID.
    pub fn as_trustee(&'_ self) -> Trustee<'_> {
        Trustee::from_sid_ref(self)
    }

    /// Converts the SID to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the raw SID byte data.
    pub fn to_vec(&self) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len()) }.to_vec()
    }

    /// Returns the raw pointer to the underlying SID structure.
    ///
    /// # Returns
    ///
    /// A pointer to the SID structure. The pointer is valid for the lifetime `'a`.
    pub fn as_ptr(&self) -> *const SID {
        self.ptr
    }
}

impl<'a> AsSidRef<'a> for SidRef<'a> {
    fn as_sid_ref(&'a self) -> SidRef<'a> {
        *self
    }
}

impl<'a> Display for SidRef<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = self.to_string().unwrap_or_else(|_| "<invalid sid>".into());
        f.write_str(&str)
    }
}

impl<'a> Debug for SidRef<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let lookup = unsafe { &self.lookup_name() };
        let is_valid = unsafe { &self.is_valid() };
        let len = unsafe { &self.len() };
        let account = match lookup {
            Ok(acc) => format!("{}/{}", acc.domain, acc.name),
            Err(_) => "<ACCOUNT LOOKUP ERROR>".to_string(),
        };
        f.debug_struct("SidRef<'a>")
            .field(
                "as_string",
                &self.to_string().unwrap_or_else(|_| "<INVALID SID>".to_string()),
            )
            .field("is_valid", is_valid)
            .field("ptr", &self.ptr)
            .field("len", len)
            .field("account", &account)
            .finish()
    }
}

pub mod account {
    use windows_sys::Win32::Security::{LookupAccountNameW, LookupAccountSidW, SID_NAME_USE};

    use super::*;

    /// The result of looking up an account name from a SID (or vice versa).
    #[derive(Debug, Clone)]
    pub struct AccountLookup {
        /// The account name (e.g., "Administrators", "SYSTEM").
        pub name: String,
        /// The domain name (e.g., "BUILTIN", "NT AUTHORITY", or the actual domain).
        pub domain: String,
        /// The SID type indicating what kind of account this is (user, group, alias, etc.).
        pub sid_type: SID_NAME_USE,
    }

    /// Looks up a SID from an account name.
    ///
    /// # Safety
    ///
    /// This function performs Windows API calls that may modify internal state.
    /// The account name string must be valid UTF-8.
    ///
    /// # Arguments
    ///
    /// * `account` - The account name to look up (e.g., "BUILTIN\\Administrators").
    ///
    /// # Returns
    ///
    /// An `AccountLookup` containing the SID string representation, domain, and SID type.
    pub(crate) unsafe fn lookup_account_name<S>(account: S) -> Result<AccountLookup, WinError>
    where
        S: AsRef<str>,
    {
        let wide_account = WideCString::new(account.as_ref());

        let mut sid_size = 0u32;
        let mut domain_size = 0u32;
        let mut sid_type: SID_NAME_USE = 0;

        unsafe {
            LookupAccountNameW(
                null_mut(),
                wide_account.as_ptr(),
                null_mut(),
                &mut sid_size,
                null_mut(),
                &mut domain_size,
                &mut sid_type,
            );
        }

        let err = unsafe { GetLastError() };
        if err != windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER {
            return Err(err.into());
        }

        let sid = unsafe { LocalAlloc(LMEM_FIXED, sid_size as usize) as PSID };
        if sid.is_null() {
            return Err(ERROR_OUTOFMEMORY.into());
        }

        let mut domain_buf = vec![0u16; domain_size as usize];

        unsafe {
            winapi_bool_call!(
                LookupAccountNameW(
                    null_mut(),
                    wide_account.as_ptr(),
                    sid,
                    &mut sid_size,
                    domain_buf.as_mut_ptr(),
                    &mut domain_size,
                    &mut sid_type,
                ),
                {
                    assert_free!(sid, "account::lookup_account_name()");
                }
            )
        };

        let domain = String::from_utf16_lossy(&domain_buf[..domain_size as usize]);

        let sid_ref = unsafe { SidRef::from_ptr(sid as *const SID) };
        let name = sid_ref.to_string()?;

        unsafe {
            assert_free!(sid, "account::lookup_account_name()");
        };

        Ok(AccountLookup { name, domain, sid_type })
    }

    /// Looks up an account name from a SID.
    ///
    /// # Safety
    ///
    /// The SID pointer must be valid and point to a properly formatted SID structure.
    ///
    /// # Arguments
    ///
    /// * `sid` - A pointer to a valid SID structure.
    ///
    /// # Returns
    ///
    /// An `AccountLookup` containing the account name, domain, and SID type.
    pub(crate) unsafe fn lookup_account_sid(sid: PSID) -> Result<AccountLookup, WinError> {
        let mut name_size = 0u32;
        let mut domain_size = 0u32;
        let mut sid_type: SID_NAME_USE = 0;

        unsafe {
            LookupAccountSidW(
                null_mut(),
                sid,
                null_mut(),
                &mut name_size,
                null_mut(),
                &mut domain_size,
                &mut sid_type,
            );
        }

        let err = unsafe { GetLastError() };
        if err != windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER {
            return Err(err.into());
        }

        let mut name_buf = vec![0u16; name_size as usize];
        let mut domain_buf = vec![0u16; domain_size as usize];

        unsafe {
            winapi_bool_call!(LookupAccountSidW(
                null_mut(),
                sid,
                name_buf.as_mut_ptr(),
                &mut name_size,
                domain_buf.as_mut_ptr(),
                &mut domain_size,
                &mut sid_type,
            ))
        }

        Ok(AccountLookup {
            name: String::from_utf16_lossy(&name_buf[..name_size as usize]),
            domain: String::from_utf16_lossy(&domain_buf[..domain_size as usize]),
            sid_type,
        })
    }
}
