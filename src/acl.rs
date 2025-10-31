//! TODO

use crate::error::WinError;
use crate::sid::{Sid, SidRef};
use crate::{assert_free, winapi_bool_call};
use std::ffi::c_void;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use windows_sys::Win32::Foundation::{ERROR_OUTOFMEMORY, FALSE};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation, AddAccessAllowedAce,
    AddAccessDeniedAce, DeleteAce, GetAce, GetAclInformation, GetLengthSid, InitializeAcl, IsValidAcl, PSID,
};
use windows_sys::Win32::System::Memory::{LMEM_FIXED, LocalAlloc};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE,
};

/// TODO
pub struct Acl {
    ptr: *mut ACL,
    owned: bool,
}

pub struct Ace<'a> {
    ptr: *const c_void,
    _phantom: PhantomData<&'a ACL>,
}

#[derive(Debug)]
pub struct AclIter<'a> {
    acl: &'a Acl,
    index: u32,
    count: u32,
}

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd, Hash)]
pub enum AceType {
    AccessAllowed,
    AccessDenied,
    SystemAudit,
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
    pub fn new() -> Result<Self, WinError> {
        Acl::empty()
    }

    pub fn empty() -> Result<Self, WinError> {
        // just an estimate, the size is dynamic, but if we want to add data, we need to allocate more
        const DEFAULT_ACE_CAPACITY: usize = 8;
        const DEFAULT_SID_MAX_LEN: usize = 128;

        Self::with_capacity(DEFAULT_ACE_CAPACITY, DEFAULT_SID_MAX_LEN)
    }

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

    /// # Safety
    ///
    /// TODO!
    pub unsafe fn from_ptr(ptr: *mut ACL) -> Self {
        Self { ptr, owned: false }
    }

    pub fn is_valid(&self) -> bool {
        unsafe { IsValidAcl(self.ptr) != FALSE }
    }

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

    pub fn add_allowed_ace(&mut self, access_mask: u32, sid: SidRef<'_>) -> Result<(), WinError> {
        unsafe {
            winapi_bool_call!(AddAccessAllowedAce(
                self.ptr,
                ACL_REVISION,
                access_mask,
                sid.as_ptr() as _,
            ))
        };
        Ok(())
    }

    pub fn add_denied_ace(&mut self, access_mask: u32, sid: SidRef<'_>) -> Result<(), WinError> {
        unsafe {
            winapi_bool_call!(AddAccessDeniedAce(
                self.ptr,
                ACL_REVISION,
                access_mask,
                sid.as_ptr() as _
            ))
        };
        Ok(())
    }

    /// Removes the ACE at the given index.
    ///
    /// # Safety
    /// The index must be valid (0 <= index < ace_count()).
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

    pub fn sid(&self) -> Result<Sid, WinError> {
        unsafe {
            let header = &*(self.ptr as *const ACCESS_ALLOWED_ACE);
            let sid_ptr = &header.SidStart as *const _ as PSID;
            let len = GetLengthSid(sid_ptr) as usize;
            let data = std::slice::from_raw_parts(sid_ptr as *const u8, len).to_vec();
            Sid::from_bytes(&data)
        }
    }

    pub fn mask(&self) -> u32 {
        unsafe { (*(self.ptr as *const ACCESS_ALLOWED_ACE)).Mask }
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
