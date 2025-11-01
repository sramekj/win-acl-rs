#![cfg(windows)]

use std::str::FromStr;

use win_acl_rs::{
    acl::{AceType::AccessAllowed, Acl},
    mask::FileAccess,
    sd::SecurityDescriptor,
    sid::{AsSidRef, Sid},
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
#[ignore] // would fail on CI
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
#[ignore] // would fail on CI
fn test_mask_and_type() {
    let mut acl = Acl::empty().unwrap();
    let mask = FileAccess::READ | FileAccess::WRITE;
    let sid = Sid::from_string("S-1-1-0").unwrap();
    acl.allow(mask.as_u32(), &sid).unwrap();

    assert!(acl.is_valid());
    assert_eq!(acl.ace_count(), 1);

    let ace = acl.into_iter().next().unwrap();

    assert_eq!(ace.ace_type(), AccessAllowed);
    assert_eq!(ace.mask(), mask.as_u32());
}

#[test]
#[ignore] // would fail on CI
fn test_add_remove_ace() {
    let mut acl = Acl::empty().unwrap();
    let sid = Sid::from_account_name("System").unwrap();
    assert!(sid.is_valid());

    let mask = FileAccess::READ | FileAccess::WRITE;

    // Try direct sid reference
    acl.allow(mask.as_u32(), &sid).unwrap();

    assert!(acl.is_valid());
    assert_eq!(acl.ace_count(), 1);

    let mask = FileAccess::EXECUTE;
    let sid_ref = sid.as_sid_ref();
    // Try sid_ref
    acl.deny(mask.as_u32(), &sid_ref).unwrap();

    assert!(acl.is_valid());
    assert_eq!(acl.ace_count(), 2);

    println!("{:?}", acl);

    acl.remove_ace(1).unwrap();

    assert!(acl.is_valid());
    assert_eq!(acl.ace_count(), 1);
}
