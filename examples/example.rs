use std::str::FromStr;
use tempfile::NamedTempFile;
use win_acl_rs::elevated::sd::ElevatedSecurityDescriptor;
use win_acl_rs::elevated::{enable_se_security_privilege, is_admin};
use win_acl_rs::sd::SecurityDescriptor;

pub fn main() -> win_acl_rs::error::Result<()> {
    let path = NamedTempFile::new().unwrap().into_temp_path();
    debug_assert!(path.exists());

    if !is_admin()? {
        println!("Not running as an admin");
        let sd = SecurityDescriptor::from_path(&path)?;
        println!("SD: {:?}", sd);

        let sd_string = sd.as_sd_string()?;
        println!("SD string: {:?}", sd_string);

        const TEST_SD_STRING: &str = "O:S-1-5-21-1402048822-409899687-2319524958-1001G:S-1-5-21-1402048822-409899687-2319524958-1001D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;S-1-5-21-1402048822-409899687-2319524958-1001)";

        let sd = SecurityDescriptor::from_str(TEST_SD_STRING)?;

        println!("SD: {:?}", sd);
    } else {
        println!("Running as an admin");
        enable_se_security_privilege()?;
        println!("SeSecurityPrivilege enabled");

        let sd = ElevatedSecurityDescriptor::from_path(&path)?;
        println!("SD: {:?}", sd);
    }
    Ok(())
}
