use std::io::{Error, ErrorKind};

const ALPHABET_B64: &[u8] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_bytes();
const ALPHABET_B64U: &[u8] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".as_bytes();

const TEBAHPLA_B64: [u8; 256] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0x3e, 0xff, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0x3f,
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

#[derive(Debug, PartialEq)]
pub enum Base64Variant {
    Standard,
    UrlSafe,
}

fn _get_alphabet(variant: &Base64Variant) -> &'static [u8] {
    match variant {
        Base64Variant::Standard => ALPHABET_B64,
        Base64Variant::UrlSafe => ALPHABET_B64U,
    }
}

fn _decode(input_text: &str, variant: Base64Variant) -> Result<Vec<u8>, Error> {
    if input_text.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "Input is empty"));
    }
    let input_length: usize = input_text.len();

    // extra validation -- inlen is a multiple of 4
    if input_length % 4 != 0 && variant == Base64Variant::Standard {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Input length is not a multiple of 4",
        ));
    }
    let input_text = input_text.as_bytes(); // convert input text to bytes
    let input_length: usize = input_text.len();
    let output_length: usize = ((input_length * 3) >> 2) + 3;
    let mut output_buffer: Vec<u8> = vec![0; output_length];
    let mut index: usize = 0;
    let mut position: usize = 0;
    let mut shift: usize = 0;
    let mut packed: u32 = 0;

    while input_length > index {
        let byte_value: u8 = match input_text[index] {
            b'=' => {
                break;
            }
            b'+' => match variant {
                Base64Variant::UrlSafe => {
                    return Err(Error::new(ErrorKind::InvalidInput, "Invalid character (+)"));
                }
                Base64Variant::Standard => TEBAHPLA_B64[b'+' as usize],
            },
            b'/' => match variant {
                Base64Variant::UrlSafe => {
                    return Err(Error::new(ErrorKind::InvalidInput, "Invalid character (/)"));
                }
                Base64Variant::Standard => TEBAHPLA_B64[b'/' as usize],
            },
            b'-' => match variant {
                Base64Variant::UrlSafe => TEBAHPLA_B64[b'-' as usize],
                Base64Variant::Standard => {
                    return Err(Error::new(ErrorKind::InvalidInput, "Invalid character (-)"));
                }
            },
            b'_' => match variant {
                Base64Variant::UrlSafe => TEBAHPLA_B64[b'_' as usize],
                Base64Variant::Standard => {
                    return Err(Error::new(ErrorKind::InvalidInput, "Invalid character (_)"));
                }
            },
            byte_value => TEBAHPLA_B64[byte_value as usize],
        };

        if byte_value == 0xff {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid character ({})", byte_value),
            ));
        }
        index += 1;

        // extend byte_value to u32
        let u32_value: u32 = byte_value as u32;
        packed = packed | (u32_value.wrapping_shl((18 - (6 * shift)) as u32) as u32);
        shift += 1;

        if shift == 4 {
            output_buffer[position] = (packed.wrapping_shr(16) & 0xff) as u8;
            position += 1;
            output_buffer[position] = (packed.wrapping_shr(8) & 0xff) as u8;
            position += 1;
            output_buffer[position] = (packed & 0xff) as u8;
            position += 1;
            shift = 0;
            packed = 0;
        }
    }

    match shift {
        1 => {
            return Err(Error::new(ErrorKind::InvalidInput, "Invalid shift value"));
        }
        2 => {
            output_buffer[position] = (packed.wrapping_shr(16) & 0xff) as u8;
            position += 1;
        }
        3 => {
            output_buffer[position] = (packed.wrapping_shr(16) & 0xff) as u8;
            position += 1;
            output_buffer[position] = (packed.wrapping_shr(8) & 0xff) as u8;
            position += 1;
        }
        4 => {
            return Err(Error::new(ErrorKind::InvalidInput, "Invalid shift value"));
        }
        _ => {}
    }
    output_buffer.resize(position, 0);
    Ok(output_buffer)
}

pub fn decode(input_text: &str, variant: Base64Variant) -> Result<Vec<u8>, Error> {
    match _decode(input_text, variant) {
        Ok(result) => Ok(result),
        Err(e) => Err(e),
    }
}

fn _encode(input_text: Vec<u8>, variant: Base64Variant) -> Result<String, Error> {
    if input_text.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "Input is empty"));
    }
    let alphabet = _get_alphabet(&variant);

    // length of resulting string
    let input_length: usize = input_text.len();
    let output_length: usize = ((input_length + 2) / 3) << 2;

    let mut output_text: Vec<u8> = vec![0; output_length];
    let mut position: usize = 0;
    let mut main_index: usize = 0;

    while (main_index + 2) < input_text.len() {
        let index: u8 = 0x3f & (input_text[main_index] >> 2);
        output_text[position] = alphabet[index as usize];
        position += 1;

        let index: u8 =
            (0x3f & (input_text[main_index] << 4)) | (0x3f & (input_text[main_index + 1] >> 4));
        output_text[position] = alphabet[index as usize];
        position += 1;

        let index: u8 =
            (0x3f & (input_text[main_index + 1] << 2)) | (0x3f & (input_text[main_index + 2] >> 6));
        output_text[position] = alphabet[index as usize];
        position += 1;

        let index: u8 = 0x3f & input_text[main_index + 2];
        output_text[position] = alphabet[index as usize];
        position += 1;

        main_index += 3;
    }

    if main_index < input_length {
        if (input_length - 1) == main_index {
            let index: u8 = 0x3f & (input_text[main_index] >> 2);
            output_text[position] = alphabet[index as usize];
            position += 1;

            let index: u8 = 0x3f & (input_text[main_index] << 4);
            output_text[position] = alphabet[index as usize];
            position += 1;

            match variant {
                Base64Variant::Standard => {
                    output_text[position] = b'=';
                    position += 1;
                    output_text[position] = b'=';
                }
                Base64Variant::UrlSafe => {
                    output_text.resize(position, 0);
                }
            }
        } else {
            let index: u8 = 0x3f & (input_text[main_index] >> 2);
            output_text[position] = alphabet[index as usize];
            position += 1;

            let index: u8 =
                (0x3f & (input_text[main_index] << 4)) | (0x3f & (input_text[main_index + 1] >> 4));
            output_text[position] = alphabet[index as usize];
            position += 1;

            let index: u8 = 0x3f & (input_text[main_index + 1] << 2);
            output_text[position] = alphabet[index as usize];
            position += 1;

            match variant {
                Base64Variant::Standard => {
                    output_text[position] = b'=';
                }
                Base64Variant::UrlSafe => {
                    output_text.resize(position, 0);
                }
            }
        }
    }

    let result = String::from_utf8(output_text).unwrap();

    Ok(result)
}

pub fn encode(input_text: &[u8], variant: Base64Variant) -> Result<String, Error> {
    match _encode(input_text.into(), variant) {
        Ok(result) => Ok(result),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        assert_eq!(
            encode(b"", Base64Variant::Standard).map_err(|e| e.kind()),
            Err(ErrorKind::InvalidInput)
        );
        assert_eq!(
            encode("hello there".as_bytes(), Base64Variant::Standard).unwrap(),
            "aGVsbG8gdGhlcmU="
        );
        assert_eq!(
            encode("A B C D E F ".as_bytes(), Base64Variant::Standard).unwrap(),
            "QSBCIEMgRCBFIEYg"
        );
        assert_eq!(encode(b"\xfe", Base64Variant::Standard).unwrap(), "/g==");
        assert_eq!(
            encode(b"hello\xfethere", Base64Variant::Standard).unwrap(),
            "aGVsbG/+dGhlcmU="
        );
        assert_eq!(
            encode(b"\x01\x02", Base64Variant::Standard).unwrap(),
            "AQI="
        );
        assert_eq!(encode(b"\x01", Base64Variant::Standard).unwrap(), "AQ==");
    }

    #[test]
    fn test_encode_url() {
        assert_eq!(
            encode(b"", Base64Variant::UrlSafe).map_err(|e| e.kind()),
            Err(ErrorKind::InvalidInput)
        );
        assert_eq!(
            encode(b"hello there", Base64Variant::UrlSafe).unwrap(),
            "aGVsbG8gdGhlcmU"
        );
        assert_eq!(
            encode(b"A B C D E F ", Base64Variant::UrlSafe).unwrap(),
            "QSBCIEMgRCBFIEYg"
        );
        assert_eq!(
            encode(b"hello\xfethere", Base64Variant::UrlSafe).unwrap(),
            "aGVsbG_-dGhlcmU"
        );
        assert_eq!(encode(b"\x01\x02", Base64Variant::UrlSafe).unwrap(), "AQI");
        assert_eq!(encode(b"\x01", Base64Variant::UrlSafe).unwrap(), "AQ");
    }

    #[test]
    fn test_decode() {
        assert_eq!(
            decode("", Base64Variant::Standard).map_err(|e| e.kind()),
            Err(ErrorKind::InvalidInput)
        );
        assert_eq!(
            decode("aGVsbG8gdGhlcmU=", Base64Variant::Standard).unwrap(),
            "hello there".as_bytes()
        );
        assert_eq!(
            decode("QSBCIEMgRCBFIEYg", Base64Variant::Standard).unwrap(),
            "A B C D E F ".as_bytes(),
        );
        assert_eq!(decode("/g==", Base64Variant::Standard).unwrap(), b"\xfe",);
        assert_eq!(
            decode("aGVsbG/+dGhlcmU=", Base64Variant::Standard).unwrap(),
            b"hello\xfethere",
        );
        assert_eq!(
            decode("AQI=", Base64Variant::Standard).unwrap(),
            "\x01\x02".as_bytes()
        );
        assert_eq!(
            decode("AQ==", Base64Variant::Standard).unwrap(),
            "\x01".as_bytes()
        );
    }

    #[test]
    fn test_decode_url() {
        assert_eq!(
            decode("", Base64Variant::UrlSafe).map_err(|e| e.kind()),
            Err(ErrorKind::InvalidInput)
        );
        assert_eq!(
            decode("aGVsbG8gdGhlcmU=", Base64Variant::UrlSafe).unwrap(),
            "hello there".as_bytes()
        );
        assert_eq!(
            decode("QSBCIEMgRCBFIEYg", Base64Variant::UrlSafe).unwrap(),
            "A B C D E F ".as_bytes(),
        );
        assert_eq!(decode("_g", Base64Variant::UrlSafe).unwrap(), b"\xfe",);
        assert_eq!(
            decode("aGVsbG_-dGhlcmU", Base64Variant::UrlSafe).unwrap(),
            b"hello\xfethere",
        );
        assert_eq!(
            decode("AQI", Base64Variant::UrlSafe).unwrap(),
            "\x01\x02".as_bytes()
        );
        assert_eq!(
            decode("AQ", Base64Variant::UrlSafe).unwrap(),
            "\x01".as_bytes()
        );
    }
}
