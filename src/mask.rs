//! Access mask utilities and reexports
//!
//! Provides reexports of common Windows access rights (`GENERIC_ALL`, etc.),
//! a safe `AccessMask` builder, and object-specific rights (files, registry, services).

use bitflags::bitflags;
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

bitflags! {
    /// A bitmask of generic access rights for ACL entries.
    ///
    /// This type provides convenient access to standard Windows access rights that
    /// can be used across different object types. For object-specific rights, see
    /// `FileAccess`, `RegistryAccess`, `ServiceAccess`, or `PrinterAccess`.
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
    /// // Or combine flags manually
    /// let custom_mask = AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE;
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AccessMask: u32 {
        const DELETE        = DELETE;
        const READ_CONTROL  = READ_CONTROL;
        const WRITE_DAC     = WRITE_DAC;
        const WRITE_OWNER   = WRITE_OWNER;
        const SYNCHRONIZE   = SYNCHRONIZE;

        const STANDARD_RIGHTS_ALL = STANDARD_RIGHTS_ALL;
        const GENERIC_READ        = GENERIC_READ;
        const GENERIC_WRITE       = GENERIC_WRITE;
        const GENERIC_EXECUTE     = GENERIC_EXECUTE;
        const GENERIC_ALL         = GENERIC_ALL;
    }
}

impl AccessMask {
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
    pub fn as_u32(&self) -> u32 {
        self.bits()
    }
}

bitflags! {
    /// File object-specific access rights.
    ///
    /// These are the access rights specific to file and directory objects.
    /// Use these when working with file ACLs for more granular control than generic rights.
    pub struct FileAccess: u32 {
        const READ    = FILE_GENERIC_READ;
        const WRITE   = FILE_GENERIC_WRITE;
        const EXECUTE = FILE_GENERIC_EXECUTE;
        const FULL    = FILE_ALL_ACCESS;
    }
}

bitflags! {
    /// Registry key access rights.
    ///
    /// These are the access rights specific to Windows registry keys.
    /// Use these when working with registry key ACLs.
    pub struct RegistryAccess: u32 {
        const QUERY       = KEY_QUERY_VALUE;
        const SET         = KEY_SET_VALUE;
        const CREATE      = KEY_CREATE_SUB_KEY;
        const ENUMERATE   = KEY_ENUMERATE_SUB_KEYS;
        const NOTIFY      = KEY_NOTIFY;
        const READ        = KEY_READ;
        const WRITE       = KEY_WRITE;
        const FULL        = KEY_ALL_ACCESS;
    }
}

bitflags! {
    /// Windows service access rights.
    ///
    /// These are the access rights specific to Windows services.
    /// Use these when working with service ACLs.
    pub struct ServiceAccess: u32 {
        const QUERY_CONFIG      = SERVICE_QUERY_CONFIG;
        const CHANGE_CONFIG     = SERVICE_CHANGE_CONFIG;
        const QUERY_STATUS      = SERVICE_QUERY_STATUS;
        const ENUM_DEPENDENTS   = SERVICE_ENUMERATE_DEPENDENTS;
        const START             = SERVICE_START;
        const STOP              = SERVICE_STOP;
        const INTERROGATE       = SERVICE_INTERROGATE;
        const USER_CONTROL      = SERVICE_USER_DEFINED_CONTROL;
        const FULL              = SERVICE_ALL_ACCESS;
    }
}

bitflags! {
    /// Printer object access rights.
    ///
    /// These are the access rights specific to printer objects.
    /// Use these when working with printer ACLs.
    pub struct PrinterAccess: u32 {
        const USE       = PRINTER_ACCESS_USE;
        const ADMIN     = PRINTER_ACCESS_ADMINISTER;
        const MANAGE    = PRINTER_ACCESS_MANAGE_LIMITED;
        const READ      = PRINTER_READ;
        const WRITE     = PRINTER_WRITE;
        const FULL      = PRINTER_ALL_ACCESS;
    }
}
