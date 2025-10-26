#![cfg(windows)]

mod sd_tests {
    use crate::error::Result;
    use crate::sd::SecurityDescriptor;
    use tempfile::NamedTempFile;

    fn create_test_descriptor() -> Result<SecurityDescriptor> {
        let path = NamedTempFile::new().unwrap().into_temp_path();
        assert!(path.exists());
        SecurityDescriptor::from_path(path)
    }

    mod sd {
        use crate::SE_PRINTER;
        use crate::elevated::is_admin;
        use crate::sd::SecurityDescriptor;
        use crate::tests::sd_tests::create_test_descriptor;
        use std::str::FromStr;

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
            let handle = "Microsoft XPS Document Writer";
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

    mod sid {
        use crate::tests::sd_tests::create_test_descriptor;

        #[test]
        fn test_owner_sid_obtained_from_sd() {
            let sd = create_test_descriptor().unwrap();

            assert!(sd.is_valid());

            let owner_sid = sd.owner_sid().unwrap();

            assert!(owner_sid.is_valid());

            assert!(owner_sid.to_string().is_ok_and(|s| !s.is_empty()));
        }

        #[test]
        fn test_group_sid_obtained_from_sd() {
            let sd = create_test_descriptor().unwrap();

            assert!(sd.is_valid());

            let group_sid = sd.group_sid().unwrap();

            assert!(group_sid.is_valid());

            assert!(group_sid.to_string().is_ok_and(|s| !s.is_empty()));
        }
    }
}
