use std::path::PathBuf;
use win_acl_rs::error::Result;
use win_acl_rs::sd::SecurityDescriptor;

pub fn main() {
    let path = PathBuf::from("c:\\devel\\rust\\win-acl-rs\\README.md");
    debug_assert!(path.exists());

    let sd: Result<SecurityDescriptor> = SecurityDescriptor::from_path(path);
    println!("{:?}", sd);
}
