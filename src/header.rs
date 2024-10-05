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
    None = 0,
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
pub enum Encryption {
    A256gcm,
    A128cbcHs256,
    A192cbcHs384,
    A256cbcHs512,
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
    pub fn new(alg: &str, enc: &str) -> Header {
        Header {
            alg: alg.to_string(),
            enc: enc.to_string(),
            ..Default::default()
        }
    }

    // fn set(&mut self, attr: &Attribute, value: &str) {
    //     match attr {
    //         Attribute::Alg => self.alg = Some(value.to_string()),
    //     }
    // }

    // fn unset(&mut self, attr: Attribute) {
    //     match attr {
    //         Attribute::Alg => self.alg = None,
    //     }
    // }
}

//////////////////////////////////////////////////////////////////////////////////
//cjose_header_t *cjose_header_new(cjose_err *err)
//{
//    cjose_header_t *retval = (cjose_header_t *)json_object();
//    if (NULL == retval)
//    {
//        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//    }
//    return retval;
//}
//
//////////////////////////////////////////////////////////////////////////////////
//cjose_header_t *cjose_header_retain(cjose_header_t *header)
//{
//    if (NULL != header)
//    {
//        header = (cjose_header_t *)json_incref((json_t *)header);
//    }
//    return header;
//}
//
//////////////////////////////////////////////////////////////////////////////////
//void cjose_header_release(cjose_header_t *header)
//{
//    if (NULL != header)
//    {
//        json_decref((json_t *)header);
//    }
//}
//
//////////////////////////////////////////////////////////////////////////////////
//bool cjose_header_set(cjose_header_t *header, const char *attr, const char *value, cjose_err *err)
//{
//    if (NULL == header || NULL == attr || NULL == value)
//    {
//        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//        return false;
//    }
//
//    json_t *value_obj = json_string(value);
//    if (NULL == value_obj)
//    {
//        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//        return false;
//    }
//
//    json_object_set_new((json_t *)header, attr, value_obj);
//
//    return true;
//}
//
//////////////////////////////////////////////////////////////////////////////////
//const char *cjose_header_get(cjose_header_t *header, const char *attr, cjose_err *err)
//{
//    if (NULL == header || NULL == attr)
//    {
//        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//        return NULL;
//    }
//
//    json_t *value_obj = json_object_get((json_t *)header, attr);
//    if (NULL == value_obj)
//    {
//        return NULL;
//    }
//
//    return json_string_value(value_obj);
//}
//
//////////////////////////////////////////////////////////////////////////////////
//bool cjose_header_set_raw(cjose_header_t *header, const char *attr, const char *value, cjose_err *err)
//{
//    if (NULL == header || NULL == attr || NULL == value)
//    {
//        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//        return false;
//    }
//
//    json_error_t j_err;
//    json_t *value_obj = json_loads(value, 0, &j_err);
//    if (NULL == value_obj)
//    {
//        // unfortunately, it's not possible to tell whether the error is due
//        // to syntax, or memory shortage. See https://github.com/akheron/jansson/issues/352
//        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//        return false;
//    }
//
//    json_object_set_new((json_t *)header, attr, value_obj);
//
//    return true;
//}
//
//////////////////////////////////////////////////////////////////////////////////
//char *cjose_header_get_raw(cjose_header_t *header, const char *attr, cjose_err *err)
//{
//    if (NULL == header || NULL == attr)
//    {
//        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//        return NULL;
//    }
//
//    json_t *value_obj = json_object_get((json_t *)header, attr);
//    if (NULL == value_obj)
//    {
//        return NULL;
//    }
//
//    return json_dumps(value_obj, JSON_COMPACT);
//}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_header() {
        let header = Header::new("RSA-OAEP", "A256GCM");
        let header_str = serde_json::to_string(&header).unwrap();
        assert_eq!(r#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#, header_str);
    }
}
