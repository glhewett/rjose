use serde::{Deserialize, Serialize};

pub enum Attribute {
    Alg,
    Enc,
    Cty,
    Kid,
    Epk,
    Apu,
    Apv,
}

pub enum Algorithm {
    None,
    EcdhEs,
    RsaOaep,
    Rsa15,
    A128kw,
    A192kw,
    A256kw,
    Ps256,
    Ps384,
    Ps512,
    Rs256,
    Rs384,
    Rs512,
    Hs256,
    Hs384,
    Hs512,
    Es256,
    Es384,
    Es512,
}

impl Algorithm {
    pub fn to_string(&self) -> String {
        match self {
            Algorithm::None => "none",
            Algorithm::EcdhEs => "ECDH-ES",
            Algorithm::RsaOaep => "RSA-OAEP",
            Algorithm::Rsa15 => "RSA1_5",
            Algorithm::A128kw => "A128KW",
            Algorithm::A192kw => "A192KW",
            Algorithm::A256kw => "A256KW",
            Algorithm::Ps256 => "PS256",
            Algorithm::Ps384 => "PS384",
            Algorithm::Ps512 => "PS512",
            Algorithm::Rs256 => "RS256",
            Algorithm::Rs384 => "RS384",
            Algorithm::Rs512 => "RS512",
            Algorithm::Hs256 => "HS256",
            Algorithm::Hs384 => "HS384",
            Algorithm::Hs512 => "HS512",
            Algorithm::Es256 => "ES256",
            Algorithm::Es384 => "ES384",
            Algorithm::Es512 => "ES512",
        }
        .to_string()
    }
}

pub enum Encryption {
    A256gcm,
    A128cbcHs256,
    A192cbcHs384,
    A256cbcHs512,
}

impl Encryption {
    pub fn to_string(&self) -> String {
        match self {
            Encryption::A256gcm => "A256GCM",
            Encryption::A128cbcHs256 => "A128CBC-HS256",
            Encryption::A192cbcHs384 => "A192CBC-HS384",
            Encryption::A256cbcHs512 => "A256CBC-HS512",
        }
        .to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    alg: String,
    enc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    apu: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    apv: Option<String>,
}

impl Default for Header {
    fn default() -> Header {
        Header {
            alg: String::from(""),
            enc: String::from(""),
            dir: None,
            cty: None,
            kid: None,
            epk: None,
            apu: None,
            apv: None,
        }
    }
}

impl Header {
    pub fn new(alg: &Algorithm, enc: &Encryption) -> Header {
        Header {
            alg: alg.to_string(),
            enc: enc.to_string(),
            ..Default::default()
        }
    }

    pub fn set(&mut self, attr: &Attribute, value: &str) {
        match attr {
            Attribute::Cty => self.cty = Some(value.to_string()),
            Attribute::Kid => self.kid = Some(value.to_string()),
            Attribute::Epk => self.epk = Some(value.to_string()),
            Attribute::Apu => self.apu = Some(value.to_string()),
            Attribute::Apv => self.apv = Some(value.to_string()),
            _ => (),
        }
    }

    pub fn unset(&mut self, attr: Attribute) {
        match attr {
            Attribute::Cty => self.cty = None,
            Attribute::Kid => self.kid = None,
            Attribute::Epk => self.epk = None,
            Attribute::Apu => self.apu = None,
            Attribute::Apv => self.apv = None,
            _ => (),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_header() {
        let mut header = Header::new(&Algorithm::RsaOaep, &Encryption::A256gcm);

        let header_str = serde_json::to_string(&header).unwrap();
        assert_eq!(r#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#, header_str);

        header.set(&Attribute::Kid, "foobar");
        let header_str = serde_json::to_string(&header).unwrap();
        assert_eq!(
            r#"{"alg":"RSA-OAEP","enc":"A256GCM","kid":"foobar"}"#,
            header_str
        );
    }
}
