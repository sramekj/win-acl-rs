#![cfg(windows)]

use std::str::FromStr;

use tempfile::NamedTempFile;
use win_acl_rs::{
    SE_PRINTER, acl::AceType::AccessAllowed, elevated::is_admin, error::Result, mask::FileAccess,
    sd::SecurityDescriptor, sid::Sid,
};
use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;

fn create_test_descriptor() -> Result<SecurityDescriptor> {
    let path = NamedTempFile::new().unwrap().into_temp_path();
    assert!(path.exists());
    SecurityDescriptor::from_path(path)
}

#[test]
fn test_is_admin() {
    assert!(is_admin().is_ok());
}

#[test]
fn test_sd_strings() {
    const TEST_SD_STRING: &str = "O:S-1-5-21-1402048822-409899687-2319524958-1001G:S-1-5-21-1402048822-409899687-2319524958-1001D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;S-1-5-21-1402048822-409899687-2319524958-1001)";

    let sd = SecurityDescriptor::from_str(TEST_SD_STRING).unwrap();

    assert!(sd.is_valid());

    let str = sd.as_sd_string().unwrap();

    assert_eq!(str, TEST_SD_STRING);
}

#[test]
fn test_sd_from_path() {
    let sd = create_test_descriptor().unwrap();

    assert!(sd.is_valid());
}

#[test]
#[ignore] // would fail on CI
fn test_sd_from_handle() {
    let handle = "Microsoft XPS Document Writer";
    let sd = SecurityDescriptor::from_handle(handle, SE_PRINTER).unwrap();

    assert!(sd.is_valid());
}

#[test]
fn test_sd_group_defaulted() {
    let sd = create_test_descriptor().unwrap();

    assert!(sd.is_valid());

    let group_defaulted = sd.group_defaulted().unwrap();
    assert!(!group_defaulted);
}

#[test]
fn test_sd_owner_defaulted() {
    let sd = create_test_descriptor().unwrap();

    assert!(sd.is_valid());

    let owner_defaulted = sd.group_defaulted().unwrap();
    assert!(!owner_defaulted);
}

#[test]
fn test_sd_dacl_defaulted() {
    let sd = create_test_descriptor().unwrap();

    assert!(sd.is_valid());

    let dacl_defaulted = sd.dacl_defaulted().unwrap();
    assert!(!dacl_defaulted);
}

#[test]
fn test_sd_dacl_present() {
    let sd = create_test_descriptor().unwrap();

    assert!(sd.is_valid());

    let dacl_present = sd.dacl_present().unwrap();
    assert!(dacl_present);
}

#[test]
fn test_sd_sacl_defaulted() {
    let sd = create_test_descriptor().unwrap();

    assert!(sd.is_valid());

    let sacl_defaulted = sd.sacl_defaulted().unwrap();
    assert!(!sacl_defaulted);
}

#[test]
fn test_sd_sacl_present() {
    let sd = create_test_descriptor().unwrap();

    assert!(sd.is_valid());

    let sacl_present = sd.sacl_present().unwrap();
    assert!(!sacl_present);
}

#[test]
fn test_persistence() {
    let path = NamedTempFile::new().unwrap().into_temp_path();
    assert!(path.exists());
    let sd = SecurityDescriptor::from_path(&path).unwrap();

    let user_sid = Sid::from_logged_in_user().unwrap();

    assert!(sd.is_valid());
    assert!(user_sid.is_valid());
    assert!(sd.dacl().is_some());

    let mut dacl = sd.dacl().unwrap();
    let has_full_access = dacl.has_permissions(&user_sid, FileAccess::FULL, AccessAllowed);
    assert!(has_full_access);

    dacl.remove_permission(&user_sid, FileAccess::FULL, AccessAllowed)
        .unwrap();
    let has_full_access = dacl.has_permissions(&user_sid, FileAccess::FULL, AccessAllowed);
    assert!(!has_full_access);

    dacl.ensure_permissions(&user_sid, FileAccess::WRITE, AccessAllowed)
        .unwrap();

    sd.persist(path.as_os_str().to_string_lossy(), SE_FILE_OBJECT).unwrap();

    let new_sd = SecurityDescriptor::from_path(&path).unwrap();
    assert!(new_sd.is_valid());
    assert!(new_sd.dacl().is_some());

    let dacl = new_sd.dacl().unwrap();
    let has_write_access = dacl.has_permissions(&user_sid, FileAccess::WRITE, AccessAllowed);

    println!("has_write_access: {}", has_write_access);
    assert!(has_write_access);
}
