//! Access Control List (ACL) operations.
//!
//! An ACL is a list of Access Control Entries (ACEs) that define the access rights for various
//! security principals. This module provides a safe wrapper around Windows ACL APIs for creating,
//! validating, and manipulating ACLs.
//!
//! # Examples
//!
//! ```no_run
//! use win_acl_rs::{acl::Acl, mask::AccessMask, sid::Sid};
//! use win_acl_rs::wellknown::WinWorldSid;
//!
//! // Create a new ACL
//! let mut acl = Acl::new()?;
//!
//! // Add an access-allowed ACE using well-known SID
//! let sid = Sid::from_well_known_sid(WinWorldSid)?; // Everyone SID
//! acl.allow(AccessMask::full().as_u32(), &sid)?;
//!
//! // Or use a string-based SID
//! let admin_sid = Sid::from_string("S-1-5-32-544")?; // Administrators
//! acl.allow(AccessMask::read().as_u32(), &admin_sid)?;
//!
//! // Iterate over ACEs
//! for ace in &acl {
//!     println!("ACE type: {:?}, mask: 0x{:X}", ace.ace_type(), ace.mask());
//! }
//! # Ok::<(), win_acl_rs::error::WinError>(())
//! ```

use std::{
    ffi::c_void,
    fmt::{Debug, Formatter},
    marker::PhantomData,
};

use windows_sys::Win32::{
    Foundation::{ERROR_OUTOFMEMORY, FALSE},
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
        AddAccessAllowedAce, AddAccessDeniedAce, DeleteAce, GetAce, GetAclInformation, GetLengthSid, InitializeAcl,
        IsValidAcl, PSID,
    },
    System::{
        Memory::{LMEM_FIXED, LocalAlloc},
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE},
    },
};

use crate::{
    assert_free,
    error::WinError,
    sid::{AsSidRef, Sid},
    winapi_bool_call,
};

/// An Access Control List (ACL) containing zero or more Access Control Entries (ACEs).
///
/// ACLs define which security principals have which access rights. There are two types:
/// - **DACL** (Discretionary ACL): Controls access to objects
/// - **SACL** (System ACL): Controls auditing of access attempts
///
/// This type manages the lifetime of the underlying Windows ACL structure and automatically
/// frees it when dropped if it owns the ACL.
pub struct Acl {
    ptr: *mut ACL,
    owned: bool,
}

/// An Access Control Entry (ACE) within an ACL.
///
/// An ACE specifies access rights for a specific security principal (identified by a SID).
/// ACEs can be of type `AccessAllowed`, `AccessDenied`, or `SystemAudit`.
///
/// This is a borrowed reference to an ACE within an ACL and should not outlive the ACL.
pub struct Ace<'a> {
    ptr: *const c_void,
    _phantom: PhantomData<&'a ACL>,
}

/// An iterator over the ACEs in an ACL.
#[derive(Debug)]
pub struct AclIter<'a> {
    acl: &'a Acl,
    index: u32,
    count: u32,
}

/// The type of an Access Control Entry (ACE).
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd, Hash)]
pub enum AceType {
    /// An ACE that grants access rights to a security principal.
    AccessAllowed,
    /// An ACE that explicitly denies access rights to a security principal.
    AccessDenied,
    /// An ACE used for system auditing, generating audit logs when access is attempted.
    SystemAudit,
    /// An unknown ACE type with the raw byte value.
    Unknown(u8),
}

impl Drop for Acl {
    fn drop(&mut self) {
        if self.owned {
            unsafe { assert_free!(self.ptr, "Acl::drop") }
        }
    }
}

impl Debug for Acl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut fmt = f.debug_struct("Acl");
        for ace in self {
            fmt.field("ace", &ace);
        }
        fmt.finish()
    }
}

impl Acl {
    /// Creates a new empty ACL.
    ///
    /// This is a convenience alias for [`Acl::empty()`].
    ///
    /// # Errors
    ///
    /// Returns an error if memory allocation fails or if ACL initialization fails.
    pub fn new() -> Result<Self, WinError> {
        Acl::empty()
    }

    /// Creates a new empty ACL with default capacity.
    ///
    /// The default capacity is suitable for most use cases. For ACLs that will contain
    /// many ACEs or very long SIDs, consider using [`Acl::with_capacity()`] instead.
    ///
    /// # Errors
    ///
    /// Returns an error if memory allocation fails or if ACL initialization fails.
    pub fn empty() -> Result<Self, WinError> {
        // just an estimate, the size is dynamic, but if we want to add data, we need to allocate more
        const DEFAULT_ACE_CAPACITY: usize = 8;
        const DEFAULT_SID_MAX_LEN: usize = 128;

        Self::with_capacity(DEFAULT_ACE_CAPACITY, DEFAULT_SID_MAX_LEN)
    }

    /// Creates a new empty ACL with the specified capacity.
    ///
    /// Pre-allocating capacity can improve performance when adding many ACEs, as it reduces
    /// the number of reallocations needed.
    ///
    /// # Arguments
    ///
    /// * `ace_count` - The expected number of ACEs that will be added to the ACL.
    /// * `sid_max_len` - The expected maximum length of SIDs that will be used in ACEs.
    ///
    /// # Errors
    ///
    /// Returns an error if memory allocation fails or if ACL initialization fails.
    pub fn with_capacity(ace_count: usize, sid_max_len: usize) -> Result<Self, WinError> {
        let estimated_size = size_of::<ACL>() + ace_count * (size_of::<ACCESS_ALLOWED_ACE>() + sid_max_len);

        let ptr = unsafe { LocalAlloc(LMEM_FIXED, estimated_size) as *mut ACL };
        if ptr.is_null() {
            return Err(ERROR_OUTOFMEMORY.into());
        }
        unsafe {
            winapi_bool_call!(InitializeAcl(ptr, estimated_size as u32, ACL_REVISION), {
                assert_free!(ptr, "Acl::empty");
            })
        };
        Ok(Self { ptr, owned: true })
    }

    /// Creates an `Acl` from a raw Windows ACL pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `ptr` points to a valid, initialized ACL structure
    /// - The ACL remains valid for the lifetime of the returned `Acl`
    /// - The ACL is not freed while the `Acl` is in use
    /// - The pointer will not be freed by other code (since `owned` is set to `false`)
    ///
    /// # Arguments
    ///
    /// * `ptr` - A pointer to a valid Windows `ACL` structure.
    ///
    /// # Returns
    ///
    /// An `Acl` that borrows the ACL at `ptr` (does not take ownership).
    pub unsafe fn from_ptr(ptr: *mut ACL) -> Self {
        Self { ptr, owned: false }
    }

    /// Checks if the ACL structure is valid.
    ///
    /// Validates that the ACL structure is properly formatted according to Windows security APIs.
    ///
    /// # Returns
    ///
    /// `true` if the ACL is valid, `false` otherwise.
    pub fn is_valid(&self) -> bool {
        unsafe { IsValidAcl(self.ptr) != FALSE }
    }

    /// Returns the number of ACEs in this ACL.
    ///
    /// # Returns
    ///
    /// The number of Access Control Entries in the ACL.
    pub fn ace_count(&self) -> u32 {
        unsafe {
            let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
            GetAclInformation(
                self.ptr,
                &mut info as *mut _ as *mut _,
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            );
            info.AceCount
        }
    }

    /// Adds an access-allowed ACE to the ACL.
    ///
    /// An access-allowed ACE grants the specified access rights to the given security principal.
    ///
    /// # Arguments
    ///
    /// * `access_mask` - A bitmask specifying the access rights to grant. Common values include
    ///   `GENERIC_READ`, `GENERIC_WRITE`, `GENERIC_EXECUTE`, `GENERIC_ALL`, or object-specific
    ///   rights from the `mask` module.
    /// * `sid_ref` - The SID (Security Identifier) of the security principal to grant access to.
    ///   Can be a `Sid`, `SidRef`, or any type implementing `AsSidRef`.
    ///
    /// # Errors
    ///
    /// Returns an error if the ACE cannot be added (e.g., insufficient memory).
    pub fn allow<'a, S>(&mut self, access_mask: u32, sid_ref: &'a S) -> Result<(), WinError>
    where
        S: AsSidRef<'a>,
    {
        unsafe {
            winapi_bool_call!(AddAccessAllowedAce(
                self.ptr,
                ACL_REVISION,
                access_mask,
                sid_ref.as_sid_ref().as_ptr() as _,
            ))
        };
        Ok(())
    }

    /// Adds an access-denied ACE to the ACL.
    ///
    /// An access-denied ACE explicitly denies the specified access rights to the given security principal.
    /// Access-denied ACEs take precedence over access-allowed ACEs.
    ///
    /// # Arguments
    ///
    /// * `access_mask` - A bitmask specifying the access rights to deny. Common values include
    ///   `GENERIC_READ`, `GENERIC_WRITE`, `GENERIC_EXECUTE`, `GENERIC_ALL`, or object-specific
    ///   rights from the `mask` module.
    /// * `sid_ref` - The SID (Security Identifier) of the security principal to deny access to.
    ///   Can be a `Sid`, `SidRef`, or any type implementing `AsSidRef`.
    ///
    /// # Errors
    ///
    /// Returns an error if the ACE cannot be added (e.g., insufficient memory).
    pub fn deny<'a, S>(&mut self, access_mask: u32, sid_ref: &'a S) -> Result<(), WinError>
    where
        S: AsSidRef<'a>,
    {
        unsafe {
            winapi_bool_call!(AddAccessDeniedAce(
                self.ptr,
                ACL_REVISION,
                access_mask,
                sid_ref.as_sid_ref().as_ptr() as _
            ))
        };
        Ok(())
    }

    /// Removes the ACE at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The zero-based index of the ACE to remove. Must be less than `ace_count()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is out of bounds or if the ACE cannot be removed.
    ///
    /// # Panics
    ///
    /// This function does not panic, but passing an invalid index will result in an error.
    pub fn remove_ace(&mut self, index: u32) -> Result<(), WinError> {
        unsafe {
            winapi_bool_call!(DeleteAce(self.ptr, index));
        }
        Ok(())
    }
}

impl<'a> Iterator for AclIter<'a> {
    type Item = Ace<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }

        let mut ace_ptr: *mut c_void = std::ptr::null_mut();
        let err = unsafe { GetAce(self.acl.ptr, self.index, &mut ace_ptr) };
        if err == FALSE {
            return None;
        }

        self.index += 1;

        Some(Ace {
            ptr: ace_ptr.cast(),
            _phantom: PhantomData,
        })
    }
}

impl<'a> IntoIterator for &'a Acl {
    type Item = Ace<'a>;
    type IntoIter = AclIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        let mut info = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };

        let err = unsafe {
            GetAclInformation(
                self.ptr,
                &mut info as *mut _ as *mut _,
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        };

        if err == FALSE {
            // TODO: this could perhaps be handled better... :/
            return AclIter {
                acl: self,
                index: 0,
                count: 0,
            };
        }

        AclIter {
            acl: self,
            index: 0,
            count: info.AceCount,
        }
    }
}

impl<'a> Ace<'a> {
    /// Returns the type of this ACE (allowed, denied, audit, etc.).
    ///
    /// # Returns
    ///
    /// The `AceType` enum variant indicating what type of ACE this is.
    pub fn ace_type(&self) -> AceType {
        unsafe {
            let header = &*(self.ptr as *const ACE_HEADER);
            match header.AceType as u32 {
                ACCESS_ALLOWED_ACE_TYPE => AceType::AccessAllowed,
                ACCESS_DENIED_ACE_TYPE => AceType::AccessDenied,
                SYSTEM_AUDIT_ACE_TYPE => AceType::SystemAudit,
                unknown => AceType::Unknown(unknown as u8),
            }
        }
    }

    /// Extracts the SID (Security Identifier) from this ACE.
    ///
    /// The SID identifies the security principal to which this ACE applies.
    ///
    /// # Returns
    ///
    /// An owned `Sid` containing the security identifier, or an error if the SID cannot be extracted.
    pub fn sid(&self) -> Result<Sid, WinError> {
        unsafe {
            // Calculate offset to SidStart: after ACE_HEADER + Mask (u32)
            let mask_offset = size_of::<ACE_HEADER>();
            let sid_offset = mask_offset + size_of::<u32>();
            let sid_ptr = (self.ptr as *const u8).add(sid_offset) as PSID;

            let len = GetLengthSid(sid_ptr) as usize;
            let data = std::slice::from_raw_parts(sid_ptr as *const u8, len).to_vec();
            Sid::from_bytes(&data)
        }
    }

    /// Returns the access mask from this ACE.
    ///
    /// The access mask is a bitmask that specifies the access rights granted or denied by this ACE.
    ///
    /// # Returns
    ///
    /// A `u32` bitmask representing the access rights. Common values include `GENERIC_READ`,
    /// `GENERIC_WRITE`, `GENERIC_EXECUTE`, `GENERIC_ALL`, or object-specific rights.
    pub fn mask(&self) -> u32 {
        unsafe {
            let mask_offset = size_of::<ACE_HEADER>();
            let mask_ptr = (self.ptr as *const u8).add(mask_offset) as *const u32;
            *mask_ptr
        }
    }
}

impl<'a> Debug for Ace<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let account_lookup = match self.sid().map(|sid| sid.lookup_name()) {
            Ok(Ok(lookup)) => format!("{}/{}", lookup.domain, lookup.name),
            _ => "<INVALID SID>".to_owned(),
        };

        f.debug_struct("Ace")
            .field("account_lookup", &account_lookup)
            .field("mask", &format_args!("{:b}b, 0x{:X}", &self.mask(), &self.mask()))
            .field("ace_type", &self.ace_type())
            .finish()
    }
}
