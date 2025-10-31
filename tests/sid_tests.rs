#![cfg(windows)]

use std::str::FromStr;
use win_acl_rs::sd::SecurityDescriptor;
use win_acl_rs::sid::Sid;
use windows_sys::Win32::Security::WinAnonymousSid;

#[test]
fn test_owner_sid_obtained_from_sd() {
    const TEST_SD_STRING: &str = "O:S-1-5-21-1402048822-409899687-2319524958-1001G:S-1-5-21-1402048822-409899687-2319524958-1001D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;S-1-5-21-1402048822-409899687-2319524958-1001)";

    let sd = SecurityDescriptor::from_str(TEST_SD_STRING).unwrap();

    assert!(sd.is_valid());

    let owner_sid = sd.owner_sid().unwrap();

    unsafe { assert!(owner_sid.is_valid()) };

    println!("{}", owner_sid);

    assert!(owner_sid.to_string().is_ok_and(|s| !s.is_empty()));
}

#[test]
fn test_group_sid_obtained_from_sd() {
    const TEST_SD_STRING: &str = "O:S-1-5-21-1402048822-409899687-2319524958-1001G:S-1-5-21-1402048822-409899687-2319524958-1001D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;S-1-5-21-1402048822-409899687-2319524958-1001)";

    let sd = SecurityDescriptor::from_str(TEST_SD_STRING).unwrap();

    assert!(sd.is_valid());

    let group_sid = sd.group_sid().unwrap();

    unsafe { assert!(group_sid.is_valid()) };

    assert!(group_sid.to_string().is_ok_and(|s| !s.is_empty()));
}

#[test]
fn test_sid_from_string() {
    const TEST_SID: &str = "S-1-5-21-1402048822-409899687-2319524958-1001";
    let sid = TEST_SID.parse::<Sid>().unwrap();
    assert!(sid.is_valid());
    assert!(sid.to_string().is_ok_and(|s| s == TEST_SID));
}

#[test]
fn test_sid_clone() {
    const TEST_SID: &str = "S-1-5-21-1402048822-409899687-2319524958-1001";
    let sid1 = TEST_SID.parse::<Sid>().unwrap();
    assert!(sid1.is_valid());
    let sid2 = sid1.clone();
    assert!(sid2.is_valid());
    assert_eq!(sid1, sid2);
    assert_eq!(sid1.to_string(), sid2.to_string());
    assert_eq!(sid1.to_vec(), sid2.to_vec());
}

#[test]
fn test_well_known() {
    let sid = Sid::from_well_known_sid(WinAnonymousSid).unwrap();
    assert!(sid.is_valid());
}

#[test]
fn test_lookup() {
    let sid = Sid::from_account_name("SYSTEM").unwrap();
    assert!(sid.is_valid());
    let lookup = sid.lookup_name().unwrap();
    assert_eq!(lookup.name, "SYSTEM");
}
