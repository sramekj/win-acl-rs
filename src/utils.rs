use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

pub fn to_wide(s: &OsStr) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_wide().collect();
    v.push(0);
    v
}

pub fn to_wide_ptr(s: &OsStr) -> *const u16 {
    Vec::as_ptr(&to_wide(s))
}

pub fn path_to_wide_ptr<P>(p: P) -> *const u16
where
    P: AsRef<Path>,
{
    to_wide_ptr(OsStr::new(p.as_ref()))
}
