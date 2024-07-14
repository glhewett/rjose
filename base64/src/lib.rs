use std::io::{Error, ErrorKind};

// const ALPHABET_B64: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
// const ALPHABET_B64U: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn encode(_text: &str) -> Result<String, Error> {
    Err(Error::new(ErrorKind::Other, "Not implemented"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        assert_eq!(encode("hello there").unwrap(), "aGVsbG8gdGhlcmU=");
    }
}
