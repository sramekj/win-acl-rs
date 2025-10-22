#![cfg(windows)]

mod tests {
    use crate::elevated::is_admin;

    #[test]
    fn test_is_admin() {
        assert!(is_admin().is_ok());
    }
}
