#![cfg(windows)]

use std::str::FromStr;
use win_acl_rs::acl::{Acl, AclBuilder};
use win_acl_rs::sd::SecurityDescriptor;
use win_acl_rs::sid::Sid;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};

fn create_sd() -> SecurityDescriptor {
    const TEST_SD_STRING: &str = "O:S-1-5-21-1402048822-409899687-2319524958-1001G:S-1-5-21-1402048822-409899687-2319524958-1001D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;S-1-5-21-1402048822-409899687-2319524958-1001)";
    SecurityDescriptor::from_str(TEST_SD_STRING).unwrap()
}

#[test]
fn test_acl_from_sd() {
    let sd = create_sd();
    assert!(sd.is_valid());

    let acl = sd.dacl().unwrap();
    assert!(acl.is_valid());
}

#[test]
fn test_acl_count() {
    let sd = create_sd();
    assert!(sd.is_valid());

    let acl = sd.dacl().unwrap();
    assert!(acl.ace_count() > 0);

    let empty = Acl::empty().unwrap();
    assert_eq!(empty.ace_count(), 0);
}

#[test]
fn test_iter() {
    let sd = create_sd();
    assert!(sd.is_valid());

    let acl = sd.dacl().unwrap();
    assert!(acl.ace_count() > 0);

    for ace in &acl {
        println!("{:?}", ace);
    }
}

#[test]
fn test_add_remove_ace() {
    let mut acl = Acl::empty().unwrap();
    let sid = Sid::from_account_name("System").unwrap();
    assert!(sid.is_valid());

    acl.add_allowed_ace(FILE_GENERIC_READ, &sid).unwrap();

    assert!(acl.is_valid());
    assert_eq!(acl.ace_count(), 1);

    acl.add_denied_ace(FILE_GENERIC_WRITE, &sid).unwrap();

    assert!(acl.is_valid());
    assert_eq!(acl.ace_count(), 2);

    acl.remove_ace(1).unwrap();

    assert!(acl.is_valid());
    assert_eq!(acl.ace_count(), 1);
}

#[test]
fn acl_builder_test() {
    let sid = Sid::from_account_name("System").unwrap();
    let builder = AclBuilder::default();
    let acl = builder
        .allow(FILE_GENERIC_READ, &sid)
        .allow(FILE_GENERIC_WRITE, &sid)
        .deny(FILE_GENERIC_EXECUTE, &sid)
        .build();

    assert!(acl.is_valid());
    assert_eq!(acl.ace_count(), 3);

    for ace in &acl {
        println!("{:?}", ace);
    }
}
