//! Access mask utilities and reexports.
//!
//! This module provides types and constants for working with Windows access rights.
//! Access masks are bit flags that specify what operations a security principal can perform
//! on a securable object.
//!
//! The module includes:
//! - **Generic access masks** (`AccessMask`) - Work across different object types
//! - **File access masks** (`FileAccess`) - Specific to files and directories
//! - **Registry access masks** (`RegistryAccess`) - Specific to registry keys
//! - **Service access masks** (`ServiceAccess`) - Specific to Windows services
//! - **Printer access masks** (`PrinterAccess`) - Specific to printer objects
//!
//! # Examples
//!
//! ```no_run
//! use win_acl_rs::mask::AccessMask;
//!
//! // Use predefined combinations
//! let read_mask = AccessMask::read();
//! let write_mask = AccessMask::write();
//! let full_mask = AccessMask::full();
//!
//! // Or combine constants manually using bitwise operators
//! let custom_mask = AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE;
//!
//! // Convert to u32 for use with Windows APIs
//! let mask_value = custom_mask.as_u32();
//! ```

/// Re-export commonly used Windows access rights.
pub use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE};
/// Re-export commonly used Windows access rights.
pub use windows_sys::Win32::Storage::FileSystem::{
    DELETE, READ_CONTROL, STANDARD_RIGHTS_ALL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::{
    Graphics::Printing::{
        PRINTER_ACCESS_ADMINISTER, PRINTER_ACCESS_MANAGE_LIMITED, PRINTER_ACCESS_USE, PRINTER_ALL_ACCESS, PRINTER_READ,
        PRINTER_WRITE,
    },
    Storage::FileSystem::{FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE},
    System::{
        Registry::{
            KEY_ALL_ACCESS, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, KEY_QUERY_VALUE, KEY_READ,
            KEY_SET_VALUE, KEY_WRITE,
        },
        Services::{
            SERVICE_ALL_ACCESS, SERVICE_CHANGE_CONFIG, SERVICE_ENUMERATE_DEPENDENTS, SERVICE_INTERROGATE,
            SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STOP, SERVICE_USER_DEFINED_CONTROL,
        },
    },
};

macro_rules! bit_ops {
    ($t:ty) => {
        impl std::ops::BitOr for $t {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self::Output {
                Self(self.0 | rhs.0)
            }
        }
        impl std::ops::BitAnd for $t {
            type Output = Self;
            fn bitand(self, rhs: Self) -> Self::Output {
                Self(self.0 & rhs.0)
            }
        }
        impl std::ops::BitOrAssign for $t {
            fn bitor_assign(&mut self, rhs: Self) {
                self.0 |= rhs.0;
            }
        }
        impl std::ops::BitAndAssign for $t {
            fn bitand_assign(&mut self, rhs: Self) {
                self.0 &= rhs.0;
            }
        }
        impl std::ops::Not for $t {
            type Output = Self;
            fn not(self) -> Self::Output {
                Self(!self.0)
            }
        }
    };
}

/// A bitmask of generic access rights for ACL entries.
///
/// This type provides convenient access to standard Windows access rights that
/// can be used across different object types. For object-specific rights, see
/// `FileAccess`, `RegistryAccess`, `ServiceAccess`, or `PrinterAccess`.
///
/// All bitwise operations (`|`, `&`, `|=`, `&=`, `!`) are supported for combining
/// access rights.
///
/// # Examples
///
/// ```no_run
/// use win_acl_rs::mask::AccessMask;
///
/// // Use predefined combinations
/// let read_mask = AccessMask::read();
/// let write_mask = AccessMask::write();
/// let full_mask = AccessMask::full();
///
/// // Or combine flags manually using bitwise operators
/// let custom_mask = AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE;
///
/// // Convert to u32 for use with Windows APIs
/// let mask_value = custom_mask.as_u32();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct AccessMask(pub u32);

impl AccessMask {
    /// Delete access right.
    pub const DELETE: Self = Self(DELETE);
    /// Read access control information right.
    pub const READ_CONTROL: Self = Self(READ_CONTROL);
    /// Write discretionary access control list (DACL) right.
    pub const WRITE_DAC: Self = Self(WRITE_DAC);
    /// Write owner information right.
    pub const WRITE_OWNER: Self = Self(WRITE_OWNER);
    /// Synchronize access right.
    pub const SYNCHRONIZE: Self = Self(SYNCHRONIZE);
    /// All standard access rights.
    pub const STANDARD_RIGHTS_ALL: Self = Self(STANDARD_RIGHTS_ALL);
    /// Generic read access right.
    pub const GENERIC_READ: Self = Self(GENERIC_READ);
    /// Generic write access right.
    pub const GENERIC_WRITE: Self = Self(GENERIC_WRITE);
    /// Generic execute access right.
    pub const GENERIC_EXECUTE: Self = Self(GENERIC_EXECUTE);
    /// Generic all access rights.
    pub const GENERIC_ALL: Self = Self(GENERIC_ALL);

    /// Creates an access mask for read operations.
    ///
    /// Includes `GENERIC_READ` and `READ_CONTROL` rights.
    pub fn read() -> Self {
        Self::GENERIC_READ | Self::READ_CONTROL
    }

    /// Creates an access mask for write operations.
    ///
    /// Includes `GENERIC_WRITE` and `WRITE_DAC` rights.
    pub fn write() -> Self {
        Self::GENERIC_WRITE | Self::WRITE_DAC
    }

    /// Creates an access mask for execute operations.
    ///
    /// Includes `GENERIC_EXECUTE` rights.
    pub fn execute() -> Self {
        Self::GENERIC_EXECUTE
    }

    /// Creates an access mask for full control.
    ///
    /// Includes `GENERIC_ALL` rights.
    pub fn full() -> Self {
        Self::GENERIC_ALL
    }

    /// Converts the access mask to a raw `u32` value.
    ///
    /// Useful when passing the mask to low-level Windows APIs that expect a `u32`.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<AccessMask> for u32 {
    fn from(mask: AccessMask) -> Self {
        mask.0
    }
}

impl From<u32> for AccessMask {
    fn from(value: u32) -> Self {
        AccessMask(value)
    }
}

impl From<i32> for AccessMask {
    fn from(value: i32) -> Self {
        AccessMask(value as u32)
    }
}

bit_ops!(AccessMask);

/// File object-specific access rights.
///
/// These are the access rights specific to file and directory objects.
/// Use these when working with file ACLs for more granular control than generic rights.
///
/// All bitwise operations (`|`, `&`, `|=`, `&=`, `!`) are supported for combining
/// access rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct FileAccess(pub u32);

impl FileAccess {
    /// File read access (includes read, execute, and read attributes).
    pub const READ: Self = Self(FILE_GENERIC_READ);
    /// File write access (includes write, append, and write attributes).
    pub const WRITE: Self = Self(FILE_GENERIC_WRITE);
    /// File execute access.
    pub const EXECUTE: Self = Self(FILE_GENERIC_EXECUTE);
    /// All file access rights.
    pub const FULL: Self = Self(FILE_ALL_ACCESS);

    /// Converts the file access mask to a raw `u32` value.
    ///
    /// Useful when passing the mask to low-level Windows APIs that expect a `u32`.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<FileAccess> for u32 {
    fn from(mask: FileAccess) -> Self {
        mask.0
    }
}

impl From<u32> for FileAccess {
    fn from(value: u32) -> Self {
        FileAccess(value)
    }
}

impl From<i32> for FileAccess {
    fn from(value: i32) -> Self {
        FileAccess(value as u32)
    }
}

bit_ops!(FileAccess);

/// Registry key access rights.
///
/// These are the access rights specific to Windows registry keys.
/// Use these when working with registry key ACLs.
///
/// All bitwise operations (`|`, `&`, `|=`, `&=`, `!`) are supported for combining
/// access rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct RegistryAccess(pub u32);

impl RegistryAccess {
    /// Query registry key value access right.
    pub const QUERY: Self = Self(KEY_QUERY_VALUE);
    /// Set registry key value access right.
    pub const SET: Self = Self(KEY_SET_VALUE);
    /// Create subkey access right.
    pub const CREATE: Self = Self(KEY_CREATE_SUB_KEY);
    /// Enumerate subkeys access right.
    pub const ENUMERATE: Self = Self(KEY_ENUMERATE_SUB_KEYS);
    /// Notify of registry key changes access right.
    pub const NOTIFY: Self = Self(KEY_NOTIFY);
    /// Read access (combines QUERY, ENUMERATE, NOTIFY, and READ_CONTROL).
    pub const READ: Self = Self(KEY_READ);
    /// Write access (combines SET and CREATE).
    pub const WRITE: Self = Self(KEY_WRITE);
    /// All registry key access rights.
    pub const FULL: Self = Self(KEY_ALL_ACCESS);

    /// Converts the registry access mask to a raw `u32` value.
    ///
    /// Useful when passing the mask to low-level Windows APIs that expect a `u32`.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<RegistryAccess> for u32 {
    fn from(mask: RegistryAccess) -> Self {
        mask.0
    }
}

impl From<u32> for RegistryAccess {
    fn from(value: u32) -> Self {
        RegistryAccess(value)
    }
}

impl From<i32> for RegistryAccess {
    fn from(value: i32) -> Self {
        RegistryAccess(value as u32)
    }
}

bit_ops!(RegistryAccess);

/// Windows service access rights.
///
/// These are the access rights specific to Windows services.
/// Use these when working with service ACLs.
///
/// All bitwise operations (`|`, `&`, `|=`, `&=`, `!`) are supported for combining
/// access rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ServiceAccess(pub u32);

impl ServiceAccess {
    /// Query service configuration access right.
    pub const QUERY_CONFIG: Self = Self(SERVICE_QUERY_CONFIG);
    /// Change service configuration access right.
    pub const CHANGE_CONFIG: Self = Self(SERVICE_CHANGE_CONFIG);
    /// Query service status access right.
    pub const QUERY_STATUS: Self = Self(SERVICE_QUERY_STATUS);
    /// Enumerate service dependents access right.
    pub const ENUM_DEPENDENTS: Self = Self(SERVICE_ENUMERATE_DEPENDENTS);
    /// Start service access right.
    pub const START: Self = Self(SERVICE_START);
    /// Stop service access right.
    pub const STOP: Self = Self(SERVICE_STOP);
    /// Interrogate service access right.
    pub const INTERROGATE: Self = Self(SERVICE_INTERROGATE);
    /// User-defined control access right.
    pub const USER_CONTROL: Self = Self(SERVICE_USER_DEFINED_CONTROL);
    /// All service access rights.
    pub const FULL: Self = Self(SERVICE_ALL_ACCESS);

    /// Converts the service access mask to a raw `u32` value.
    ///
    /// Useful when passing the mask to low-level Windows APIs that expect a `u32`.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<ServiceAccess> for u32 {
    fn from(mask: ServiceAccess) -> Self {
        mask.0
    }
}

impl From<u32> for ServiceAccess {
    fn from(value: u32) -> Self {
        ServiceAccess(value)
    }
}

impl From<i32> for ServiceAccess {
    fn from(value: i32) -> Self {
        ServiceAccess(value as u32)
    }
}

bit_ops!(ServiceAccess);

/// Printer object access rights.
///
/// These are the access rights specific to printer objects.
/// Use these when working with printer ACLs.
///
/// All bitwise operations (`|`, `&`, `|=`, `&=`, `!`) are supported for combining
/// access rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct PrinterAccess(pub u32);

impl PrinterAccess {
    /// Basic printer use access right.
    pub const USE: Self = Self(PRINTER_ACCESS_USE);
    /// Printer administration access right.
    pub const ADMIN: Self = Self(PRINTER_ACCESS_ADMINISTER);
    /// Limited printer management access right.
    pub const MANAGE: Self = Self(PRINTER_ACCESS_MANAGE_LIMITED);
    /// Printer read access right.
    pub const READ: Self = Self(PRINTER_READ);
    /// Printer write access right.
    pub const WRITE: Self = Self(PRINTER_WRITE);
    /// All printer access rights.
    pub const FULL: Self = Self(PRINTER_ALL_ACCESS);

    /// Converts the printer access mask to a raw `u32` value.
    ///
    /// Useful when passing the mask to low-level Windows APIs that expect a `u32`.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<PrinterAccess> for u32 {
    fn from(mask: PrinterAccess) -> Self {
        mask.0
    }
}

impl From<u32> for PrinterAccess {
    fn from(value: u32) -> Self {
        PrinterAccess(value)
    }
}

impl From<i32> for PrinterAccess {
    fn from(value: i32) -> Self {
        PrinterAccess(value as u32)
    }
}

bit_ops!(PrinterAccess);
