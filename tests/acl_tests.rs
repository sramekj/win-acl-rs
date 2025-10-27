#![cfg(windows)]

use std::str::FromStr;
use win_acl_rs::acl::Acl;
use win_acl_rs::sd::SecurityDescriptor;

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
