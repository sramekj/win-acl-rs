use tempfile::NamedTempFile;
use win_acl_rs::elevated::{enable_se_security_privilege, is_admin};
use win_acl_rs::sd::SecurityDescriptor;

pub fn main() {
    let path = NamedTempFile::new().unwrap().into_temp_path();
    debug_assert!(path.exists());

    if !is_admin() {
        println!("Not running as an admin");
        let sd = SecurityDescriptor::from_path(&path);
        println!("{:?}", sd);
    } else {
        println!("Running as an admin");
        let res = enable_se_security_privilege();
        println!("enabled: {:?}", res);

        let sd = SecurityDescriptor::from_path_elevated(&path);
        println!("{:?}", sd);
    }
}
