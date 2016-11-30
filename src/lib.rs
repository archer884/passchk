#[macro_use] extern crate lazy_static;

extern crate regex;

use regex::bytes::Regex;
use std::ffi::CString;

lazy_static! {
    static ref PATTERNS: Vec<Regex> = create_password_regex();
}

#[no_mangle]
pub unsafe extern fn is_valid_by_regex(password: *mut i8) -> bool {
    let password = CString::from_raw(password);
    patterns_match(password.as_bytes())
}

fn patterns_match(b: &[u8]) -> bool {
    PATTERNS.iter().all(|pattern| pattern.is_match(b))
}

#[no_mangle]
pub unsafe extern fn is_valid(password: *mut i8) -> bool {
    let password = CString::from_raw(password);

    let mut lowercase = false;
    let mut uppercase = false;
    let mut numeric = false;
    let mut symbol = false;

    for byte in password.as_bytes() {
        match *byte {
            b'A'...b'Z' => uppercase = true,
            b'a'...b'z' => lowercase = true,
            b'0'...b'9' => numeric = true,
            _ => symbol = true,
        }
    }

    lowercase && uppercase && numeric && symbol
}

fn create_password_regex() -> Vec<Regex> {
    vec![
        Regex::new(".*[A-Z].*").expect("invalid regex"),
        Regex::new(".*[a-z].*").expect("invalid regex"),
        Regex::new(".*[0-9].*").expect("invalid regex"),
        Regex::new(r#".*[-~!@#$%^&*_+=`|\\(){}\[\]:;'<>",.?/].*"#).expect("invalid regex"),
        Regex::new(".{12,}").expect("invalid regex"),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn pattern_is_valid() {
        super::create_password_regex();
    }

    #[test]
    fn valid_passwords_are_allowed() {
        assert!(super::patterns_match("paSsword$123".as_ref()));
    }

    #[test]
    fn must_have_caps() {
        assert!(!super::patterns_match("password$123".as_ref()))
    }

    #[test]
    fn must_have_lowercase() {
        assert!(!super::patterns_match("PASSWORD$123".as_ref()));
    }

    #[test]
    fn must_have_symbols() {
        assert!(!super::patterns_match("paSsword$%@#".as_ref()));
    }

    #[test]
    fn must_be_12_chars_long() {
        assert!(!super::patterns_match("pSwrd$12".as_ref()));
    }
}
