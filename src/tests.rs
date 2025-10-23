#![cfg(windows)]

mod sd_tests {
    use crate::SE_PRINTER;
    use crate::elevated::is_admin;
    use crate::error::Result;
    use crate::sd::SecurityDescriptor;
    use std::ffi::OsStr;
    use std::str::FromStr;
    use tempfile::NamedTempFile;

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
        let handle = OsStr::new("Microsoft XPS Document Writer");
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
}
