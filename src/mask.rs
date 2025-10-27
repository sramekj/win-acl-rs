//! Access mask utilities and reexports
//!
//! Provides reexports of common Windows access rights (`GENERIC_ALL`, etc.),
//! a safe `AccessMask` builder, and object-specific rights (files, registry, services).

use bitflags::bitflags;

use windows_sys::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows_sys::Win32::System::Registry::{
    KEY_ALL_ACCESS, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, KEY_QUERY_VALUE,
    KEY_READ, KEY_SET_VALUE, KEY_WRITE,
};
use windows_sys::Win32::System::Services::{
    SERVICE_ALL_ACCESS, SERVICE_CHANGE_CONFIG, SERVICE_ENUMERATE_DEPENDENTS, SERVICE_INTERROGATE,
    SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STOP,
    SERVICE_USER_DEFINED_CONTROL,
};

use windows_sys::Win32::Graphics::Printing::{
    PRINTER_ACCESS_ADMINISTER, PRINTER_ACCESS_MANAGE_LIMITED, PRINTER_ACCESS_USE,
    PRINTER_ALL_ACCESS, PRINTER_READ, PRINTER_WRITE,
};

/// Re-export commonly used Windows access rights.
pub use windows_sys::Win32::Foundation::{
    GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE,
};

/// Re-export commonly used Windows access rights.
pub use windows_sys::Win32::Storage::FileSystem::{
    DELETE, READ_CONTROL, STANDARD_RIGHTS_ALL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
};

bitflags! {
    /// Generic access mask builder for ACL entries.
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
    pub fn read() -> Self {
        Self::GENERIC_READ | Self::READ_CONTROL
    }
    pub fn write() -> Self {
        Self::GENERIC_WRITE | Self::WRITE_DAC
    }
    pub fn execute() -> Self {
        Self::GENERIC_EXECUTE
    }
    pub fn full() -> Self {
        Self::GENERIC_ALL
    }
    pub fn as_u32(&self) -> u32 {
        self.bits()
    }
}

bitflags! {
    /// File object access rights
    pub struct FileAccess: u32 {
        const READ    = FILE_GENERIC_READ;
        const WRITE   = FILE_GENERIC_WRITE;
        const EXECUTE = FILE_GENERIC_EXECUTE;
        const FULL    = FILE_ALL_ACCESS;
    }
}

bitflags! {
    /// Registry key access rights
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
    /// Service access rights
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
    /// Printer-specific access rights
    pub struct PrinterAccess: u32 {
        const USE       = PRINTER_ACCESS_USE;
        const ADMIN     = PRINTER_ACCESS_ADMINISTER;
        const MANAGE    = PRINTER_ACCESS_MANAGE_LIMITED;
        const READ      = PRINTER_READ;
        const WRITE     = PRINTER_WRITE;
        const FULL      = PRINTER_ALL_ACCESS;
    }
}
