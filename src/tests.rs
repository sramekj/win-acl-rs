#![cfg(windows)]

mod tests {
    use crate::SE_PRINTER;
    use crate::elevated::is_admin;
    use crate::sd::SecurityDescriptor;
    use crate::utils::WideCString;
    use std::str::FromStr;
    use tempfile::NamedTempFile;

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
        let path = NamedTempFile::new().unwrap().into_temp_path();
        assert!(path.exists());

        let sd = SecurityDescriptor::from_path(path).unwrap();

        assert!(sd.is_valid());
    }

    #[test]
    fn test_sd_from_handle() {
        let handle = WideCString::new("Microsoft XPS Document Writer");
        let sd = SecurityDescriptor::from_handle(handle, SE_PRINTER).unwrap();

        assert!(sd.is_valid());
    }
}
