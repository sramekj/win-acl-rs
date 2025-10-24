use std::str::FromStr;
use tempfile::NamedTempFile;
use win_acl_rs::SE_PRINTER;
use win_acl_rs::elevated::{PrivilegeToken, SecurityDescriptorElevated, is_admin};
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

        let printer_name = "Microsoft XPS Document Writer";
        let sd = SecurityDescriptor::from_handle(printer_name, SE_PRINTER)?;
        println!("SD: {:?}", sd);
        println!("Is valid: {}", sd.is_valid());
    } else {
        println!("Running as an admin");

        // create a privilege token and try to elevate it => this will try to obtain SeSecurityPrivilege
        let token = PrivilegeToken::new();
        let elevated_token = token.try_elevate()?;
        println!("SeSecurityPrivilege enabled");

        // we can either optionally upgrade regular security descriptor with elevated token
        let sd = SecurityDescriptor::from_path(&path)?;
        let _upgraded = sd.upgrade(&elevated_token);
        //...

        // or create a new one directly

        let sd = SecurityDescriptorElevated::from_path(&elevated_token, &path)?;
        println!("SD: {:?}", sd);
        println!("Is valid: {}", sd.is_valid());
    }
    Ok(())
}
