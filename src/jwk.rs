use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};

// const CJOSE_JWK_EC_P_256_STR: &str = "P-256";
// const CJOSE_JWK_EC_P_384_STR: &str = "P-384";
// const CJOSE_JWK_EC_P_521_STR: &str = "P-521";
// const CJOSE_JWK_KTY_STR: &str = "kty";
// const CJOSE_JWK_KID_STR: &str = "kid";
// const CJOSE_JWK_CRV_STR: &str = "crv";
// const CJOSE_JWK_X_STR: &str = "x";
// const CJOSE_JWK_Y_STR: &str = "y";
// const CJOSE_JWK_D_STR: &str = "d";
// const CJOSE_JWK_N_STR: &str = "n";
// const CJOSE_JWK_E_STR: &str = "e";
// const CJOSE_JWK_P_STR: &str = "p";
// const CJOSE_JWK_Q_STR: &str = "q";
// const CJOSE_JWK_DP_STR: &str = "dp";
// const CJOSE_JWK_DQ_STR: &str = "dq";
// const CJOSE_JWK_QI_STR: &str = "qi";
// const CJOSE_JWK_K_STR: &str = "k";

#[derive(Debug)]
pub enum JwkError {
    InvalidKeySpec,
    InvalidKeyData,
    NoPrivateKey,
}

#[derive(Debug, PartialEq)]
pub enum KeyType {
    Rsa,
    Ec,
    Oct,
}

impl KeyType {
    pub fn from_str(s: &str) -> Self {
        match s {
            "EC" => Self::Ec,
            "RSA" => Self::Rsa,
            "oct" => Self::Oct,
            _ => panic!("Invalid key type"),
        }
    }

    pub fn to_str(&self) -> &str {
        match self {
            KeyType::Ec => "EC",
            KeyType::Rsa => "RSA",
            KeyType::Oct => "oct",
        }
    }
}

pub struct RsaKeySpec {
    pub e: Vec<u8>,
    pub n: Vec<u8>,
    pub d: Vec<u8>,
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub dp: Vec<u8>,
    pub dq: Vec<u8>,
    pub qi: Vec<u8>,
}

pub struct Jwk {
    pub key_type: KeyType,
    pub kid: Option<String>,
    // pub retained: u32,
    pub key_size: usize,
    pub private_key: Option<RsaPrivateKey>,
    pub public_key: Option<RsaPublicKey>,
    // fns: *const key_fntable,
}

impl Jwk {
    pub fn create_rsa_spec(key: &RsaKeySpec) -> Result<Self, JwkError> {
        // Private Key
        if key.n.len() > 0 && key.e.len() > 0 {
            let key_n = BigUint::from_bytes_be(&key.n);
            let key_e = BigUint::from_bytes_be(&key.e);
            let key_d = BigUint::from_bytes_be(&key.d);
            let key_p = BigUint::from_bytes_be(&key.p);
            let key_q = BigUint::from_bytes_be(&key.q);

            let key = match RsaPrivateKey::from_components(key_n, key_e, key_d, vec![key_p, key_q])
            {
                Ok(k) => k,
                Err(_) => return Err(JwkError::InvalidKeySpec),
            };

            return Ok(Self {
                key_type: KeyType::Rsa,
                key_size: key.n().bits(),
                kid: None,
                private_key: Some(key.clone()),
                public_key: Some(key.to_public_key()),
            });

        // Public Key
        } else if key.n.len() > 0 && key.e.len() > 0 {
            let key_n = BigUint::from_bytes_be(&key.n);
            let key_e = BigUint::from_bytes_be(&key.e);
            let key = match RsaPublicKey::new(key_n, key_e) {
                Ok(k) => k,
                Err(_) => return Err(JwkError::InvalidKeySpec),
            };
            return Ok(Self {
                key_type: KeyType::Rsa,
                key_size: 0,
                kid: None,
                private_key: None,
                public_key: Some(key),
            });
        }
        Err(JwkError::InvalidKeySpec)
    }

    //pub fn get_factors(&self) -> Result<(BigUint, BigUint), JwkError> {
    //    if let Some(key) = &self.private_key {
    //        let primes: &[BigUint] = key.primes();
    //        return Ok((primes.0.clone(), primes.1.clone()));
    //    }
    //    return Err(JwkError::NoPrivateKey);
    //}
}

// void _cjose_jwk_rsa_set_factors(RSA *rsa, uint8_t *p, size_t p_len, uint8_t *q, size_t q_len)
// {
//     BIGNUM *rsa_p = NULL, *rsa_q = NULL;

//     if (p && p_len > 0)
//         rsa_p = BN_bin2bn(p, p_len, NULL);
//     if (q && q_len > 0)
//         rsa_q = BN_bin2bn(q, q_len, NULL);

// #if defined(CJOSE_OPENSSL_11X)
//     RSA_set0_factors(rsa, rsa_p, rsa_q);
// #else
//     rsa->p = rsa_p;
//     rsa->q = rsa_q;
// #endif
// }

// void _cjose_jwk_rsa_get_crt(RSA *rsa, BIGNUM **dmp1, BIGNUM **dmq1, BIGNUM **iqmp)
// {
// #if defined(CJOSE_OPENSSL_11X)
//     RSA_get0_crt_params(rsa, (const BIGNUM **)dmp1, (const BIGNUM **)dmq1, (const BIGNUM **)iqmp);
// #else
//     *dmp1 = rsa->dmp1;
//     *dmq1 = rsa->dmq1;
//     *iqmp = rsa->iqmp;
// #endif
// }

// void _cjose_jwk_rsa_set_crt(
//     RSA *rsa, uint8_t *dmp1, size_t dmp1_len, uint8_t *dmq1, size_t dmq1_len, uint8_t *iqmp, size_t iqmp_len)
// {
//     BIGNUM *rsa_dmp1 = NULL, *rsa_dmq1 = NULL, *rsa_iqmp = NULL;

//     if (dmp1 && dmp1_len > 0)
//         rsa_dmp1 = BN_bin2bn(dmp1, dmp1_len, NULL);
//     if (dmq1 && dmq1_len > 0)
//         rsa_dmq1 = BN_bin2bn(dmq1, dmq1_len, NULL);
//     if (iqmp && iqmp_len > 0)
//         rsa_iqmp = BN_bin2bn(iqmp, iqmp_len, NULL);

// #if defined(CJOSE_OPENSSL_11X)
//     RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp);
// #else
//     rsa->dmp1 = rsa_dmp1;
//     rsa->dmq1 = rsa_dmq1;
//     rsa->iqmp = rsa_iqmp;
// #endif
// }

// // interface functions -- Generic

// const char *cjose_jwk_name_for_kty(cjose_jwk_kty_t kty, cjose_err *err)
// {
//     if (0 == kty || CJOSE_JWK_KTY_OCT < kty)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return NULL;
//     }

//     return JWK_KTY_NAMES[kty - CJOSE_JWK_KTY_RSA];
// }

// cjose_jwk_t *cjose_jwk_retain(cjose_jwk_t *jwk, cjose_err *err)
// {
//     if (!jwk)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return NULL;
//     }

//     ++(jwk->retained);
//     // TODO: check for overflow

//     return jwk;
// }

// bool cjose_jwk_release(cjose_jwk_t *jwk)
// {
//     if (!jwk)
//     {
//         return false;
//     }

//     --(jwk->retained);
//     if (0 == jwk->retained)
//     {
//         cjose_get_dealloc()(jwk->kid);
//         jwk->kid = NULL;

//         // assumes freefunc is set
//         assert(NULL != jwk->fns->free);
//         jwk->fns->free(jwk);
//         jwk = NULL;
//     }

//     return (NULL != jwk);
// }

// cjose_jwk_kty_t cjose_jwk_get_kty(const cjose_jwk_t *jwk, cjose_err *err)
// {
//     if (!jwk)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return -1;
//     }

//     return jwk->kty;
// }
// size_t cjose_jwk_get_keysize(const cjose_jwk_t *jwk, cjose_err *err)
// {
//     if (!jwk)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return 0;
//     }
//     return jwk->keysize;
// }

// void *cjose_jwk_get_keydata(const cjose_jwk_t *jwk, cjose_err *err)
// {
//     if (!jwk)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return NULL;
//     }
//     return jwk->keydata;
// }

// const char *cjose_jwk_get_kid(const cjose_jwk_t *jwk, cjose_err *err)
// {
//     if (!jwk)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return NULL;
//     }

//     return jwk->kid;
// }

// bool cjose_jwk_set_kid(cjose_jwk_t *jwk, const char *kid, size_t len, cjose_err *err)
// {
//     if (!jwk || !kid)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return false;
//     }
//     if (jwk->kid)
//     {
//         cjose_get_dealloc()(jwk->kid);
//     }
//     jwk->kid = (char *)cjose_get_alloc()(len + 1);
//     if (!jwk->kid)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         return false;
//     }
//     strncpy(jwk->kid, kid, len + 1);
//     return true;
// }

// char *cjose_jwk_to_json(const cjose_jwk_t *jwk, bool priv, cjose_err *err)
// {
//     char *result = NULL;

//     if (!jwk)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return NULL;
//     }

//     json_t *json = json_object(), *field = NULL;
//     if (!json)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto to_json_cleanup;
//     }

//     // set kty
//     const char *kty = cjose_jwk_name_for_kty(jwk->kty, err);
//     field = json_string(kty);
//     if (!field)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto to_json_cleanup;
//     }
//     json_object_set(json, "kty", field);
//     json_decref(field);
//     field = NULL;

//     // set kid
//     if (NULL != jwk->kid)
//     {
//         field = json_string(jwk->kid);
//         if (!field)
//         {
//             CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//             goto to_json_cleanup;
//         }
//         json_object_set(json, CJOSE_JWK_KID_STR, field);
//         json_decref(field);
//         field = NULL;
//     }

//     // set public fields
//     if (jwk->fns->public_json && !jwk->fns->public_json(jwk, json, err))
//     {
//         goto to_json_cleanup;
//     }

//     // set private fields
//     if (priv && jwk->fns->private_json && !jwk->fns->private_json(jwk, json, err))
//     {
//         goto to_json_cleanup;
//     }

//     // generate the string ...
//     char *str_jwk = json_dumps(json, JSON_ENCODE_ANY | JSON_COMPACT | JSON_PRESERVE_ORDER);
//     if (!str_jwk)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto to_json_cleanup;
//     }
//     result = _cjose_strndup(str_jwk, -1, err);
//     if (!result)
//     {
//         cjose_get_dealloc()(str_jwk);
//         goto to_json_cleanup;
//     }
//     cjose_get_dealloc()(str_jwk);

// to_json_cleanup:
//     if (json)
//     {
//         json_decref(json);
//         json = NULL;
//     }
//     if (field)
//     {
//         json_decref(field);
//         field = NULL;
//     }

//     return result;
// }

// //////////////// Octet String ////////////////
// // internal data & functions -- Octet String

// static void _oct_free(cjose_jwk_t *jwk);
// static bool _oct_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
// static bool _oct_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

// static const key_fntable OCT_FNTABLE = { _oct_free, _oct_public_fields, _oct_private_fields };

// static cjose_jwk_t *_oct_new(uint8_t *buffer, size_t keysize, cjose_err *err)
// {
//     cjose_jwk_t *jwk = (cjose_jwk_t *)cjose_get_alloc()(sizeof(cjose_jwk_t));
//     if (NULL == jwk)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//     }
//     else
//     {
//         memset(jwk, 0, sizeof(cjose_jwk_t));
//         jwk->retained = 1;
//         jwk->kty = CJOSE_JWK_KTY_OCT;
//         jwk->keysize = keysize;
//         jwk->keydata = buffer;
//         jwk->fns = &OCT_FNTABLE;
//     }

//     return jwk;
// }

// static void _oct_free(cjose_jwk_t *jwk)
// {
//     uint8_t *buffer = (uint8_t *)jwk->keydata;
//     jwk->keydata = NULL;
//     if (buffer)
//     {
//         cjose_get_dealloc()(buffer);
//     }
//     cjose_get_dealloc()(jwk);
// }

// static bool _oct_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err) { return true; }

// static bool _oct_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
// {
//     json_t *field = NULL;
//     char *k = NULL;
//     size_t klen = 0;
//     uint8_t *keydata = (uint8_t *)jwk->keydata;
//     size_t keysize = jwk->keysize / 8;

//     if (!cjose_base64url_encode(keydata, keysize, &k, &klen, err))
//     {
//         return false;
//     }

//     field = _cjose_json_stringn(k, klen, err);
//     cjose_get_dealloc()(k);
//     k = NULL;
//     if (!field)
//     {
//         return false;
//     }
//     json_object_set(json, "k", field);
//     json_decref(field);

//     return true;
// }

// // interface functions -- Octet String

// cjose_jwk_t *cjose_jwk_create_oct_random(size_t keysize, cjose_err *err)
// {
//     cjose_jwk_t *jwk = NULL;
//     uint8_t *buffer = NULL;

//     if (0 == keysize)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto create_oct_failed;
//     }

//     // resize to bytes
//     size_t buffersize = sizeof(uint8_t) * (keysize / 8);

//     buffer = (uint8_t *)cjose_get_alloc()(buffersize);
//     if (NULL == buffer)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto create_oct_failed;
//     }
//     if (1 != RAND_bytes(buffer, buffersize))
//     {
//         goto create_oct_failed;
//     }

//     jwk = _oct_new(buffer, keysize, err);
//     if (NULL == jwk)
//     {
//         goto create_oct_failed;
//     }
//     return jwk;

// create_oct_failed:
//     if (buffer)
//     {
//         cjose_get_dealloc()(buffer);
//         buffer = NULL;
//     }

//     return NULL;
// }

// cjose_jwk_t *cjose_jwk_create_oct_spec(const uint8_t *data, size_t len, cjose_err *err)
// {
//     cjose_jwk_t *jwk = NULL;
//     uint8_t *buffer = NULL;

//     if (NULL == data || 0 == len)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto create_oct_failed;
//     }

//     buffer = (uint8_t *)cjose_get_alloc()(len);
//     if (!buffer)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto create_oct_failed;
//     }
//     memcpy(buffer, data, len);

//     jwk = _oct_new(buffer, len * 8, err);
//     if (NULL == jwk)
//     {
//         goto create_oct_failed;
//     }

//     return jwk;

// create_oct_failed:
//     if (buffer)
//     {
//         cjose_get_dealloc()(buffer);
//         buffer = NULL;
//     }

//     return NULL;
// }

// //////////////// Elliptic Curve ////////////////
// // internal data & functions -- Elliptic Curve

// static void _EC_free(cjose_jwk_t *jwk);
// static bool _EC_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
// static bool _EC_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

// static const key_fntable EC_FNTABLE = { _EC_free, _EC_public_fields, _EC_private_fields };

// static inline uint8_t _ec_size_for_curve(cjose_jwk_ec_curve crv, cjose_err *err)
// {
//     switch (crv)
//     {
//     case CJOSE_JWK_EC_P_256:
//         return 32;
//     case CJOSE_JWK_EC_P_384:
//         return 48;
//     case CJOSE_JWK_EC_P_521:
//         return 66;
//     case CJOSE_JWK_EC_INVALID:
//         return 0;
//     }

//     return 0;
// }

// static inline const char *_ec_name_for_curve(cjose_jwk_ec_curve crv, cjose_err *err)
// {
//     switch (crv)
//     {
//     case CJOSE_JWK_EC_P_256:
//         return CJOSE_JWK_EC_P_256_STR;
//     case CJOSE_JWK_EC_P_384:
//         return CJOSE_JWK_EC_P_384_STR;
//     case CJOSE_JWK_EC_P_521:
//         return CJOSE_JWK_EC_P_521_STR;
//     case CJOSE_JWK_EC_INVALID:
//         return NULL;
//     }

//     return NULL;
// }

// static inline bool _ec_curve_from_name(const char *name, cjose_jwk_ec_curve *crv, cjose_err *err)
// {
//     bool retval = true;
//     if (strncmp(name, CJOSE_JWK_EC_P_256_STR, sizeof(CJOSE_JWK_EC_P_256_STR)) == 0)
//     {
//         *crv = CJOSE_JWK_EC_P_256;
//     }
//     else if (strncmp(name, CJOSE_JWK_EC_P_384_STR, sizeof(CJOSE_JWK_EC_P_384_STR)) == 0)
//     {
//         *crv = CJOSE_JWK_EC_P_384;
//     }
//     else if (strncmp(name, CJOSE_JWK_EC_P_521_STR, sizeof(CJOSE_JWK_EC_P_521_STR)) == 0)
//     {
//         *crv = CJOSE_JWK_EC_P_521;
//     }
//     else
//     {
//         retval = false;
//     }
//     return retval;
// }

// static inline bool _kty_from_name(const char *name, cjose_jwk_kty_t *kty, cjose_err *err)
// {
//     bool retval = true;
//     if (strncmp(name, CJOSE_JWK_KTY_EC_STR, sizeof(CJOSE_JWK_KTY_EC_STR)) == 0)
//     {
//         *kty = CJOSE_JWK_KTY_EC;
//     }
//     else if (strncmp(name, CJOSE_JWK_KTY_RSA_STR, sizeof(CJOSE_JWK_KTY_RSA_STR)) == 0)
//     {
//         *kty = CJOSE_JWK_KTY_RSA;
//     }
//     else if (strncmp(name, CJOSE_JWK_KTY_OCT_STR, sizeof(CJOSE_JWK_KTY_OCT_STR)) == 0)
//     {
//         *kty = CJOSE_JWK_KTY_OCT;
//     }
//     else
//     {
//         retval = false;
//     }
//     return retval;
// }

// static cjose_jwk_t *_EC_new(cjose_jwk_ec_curve crv, EC_KEY *ec, cjose_err *err)
// {
//     ec_keydata *keydata = cjose_get_alloc()(sizeof(ec_keydata));
//     if (!keydata)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         return NULL;
//     }
//     keydata->crv = crv;
//     keydata->key = ec;

//     cjose_jwk_t *jwk = cjose_get_alloc()(sizeof(cjose_jwk_t));
//     if (!jwk)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         cjose_get_dealloc()(keydata);
//         return NULL;
//     }
//     memset(jwk, 0, sizeof(cjose_jwk_t));
//     jwk->retained = 1;
//     jwk->kty = CJOSE_JWK_KTY_EC;
//     switch (crv)
//     {
//     case CJOSE_JWK_EC_P_256:
//         jwk->keysize = 256;
//         break;
//     case CJOSE_JWK_EC_P_384:
//         jwk->keysize = 384;
//         break;
//     case CJOSE_JWK_EC_P_521:
//         jwk->keysize = 521;
//         break;
//     case CJOSE_JWK_EC_INVALID:
//         // should never happen
//         jwk->keysize = 0;
//         break;
//     }
//     jwk->keydata = keydata;
//     jwk->fns = &EC_FNTABLE;

//     return jwk;
// }

// static void _EC_free(cjose_jwk_t *jwk)
// {
//     ec_keydata *keydata = (ec_keydata *)jwk->keydata;
//     jwk->keydata = NULL;

//     if (keydata)
//     {
//         EC_KEY *ec = keydata->key;
//         keydata->key = NULL;
//         if (ec)
//         {
//             EC_KEY_free(ec);
//         }
//         cjose_get_dealloc()(keydata);
//     }
//     cjose_get_dealloc()(jwk);
// }

// static bool _EC_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
// {
//     ec_keydata *keydata = (ec_keydata *)jwk->keydata;
//     const EC_GROUP *params = NULL;
//     const EC_POINT *pub = NULL;
//     BIGNUM *bnX = NULL, *bnY = NULL;
//     uint8_t *buffer = NULL;
//     char *b64u = NULL;
//     size_t len = 0, offset = 0;
//     json_t *field = NULL;
//     bool result = false;

//     // track expected binary data size
//     uint8_t numsize = _ec_size_for_curve(keydata->crv, err);

//     // output the curve
//     field = json_string(_ec_name_for_curve(keydata->crv, err));
//     if (!field)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto _ec_to_string_cleanup;
//     }
//     json_object_set(json, "crv", field);
//     json_decref(field);
//     field = NULL;

//     // obtain the public key
//     pub = EC_KEY_get0_public_key(keydata->key);
//     params = EC_KEY_get0_group(keydata->key);
//     if (!pub || !params)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto _ec_to_string_cleanup;
//     }

//     buffer = cjose_get_alloc()(numsize);
//     bnX = BN_new();
//     bnY = BN_new();
//     if (!buffer || !bnX || !bnY)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto _ec_to_string_cleanup;
//     }
//     if (1 != EC_POINT_get_affine_coordinates_GFp(params, pub, bnX, bnY, NULL))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto _ec_to_string_cleanup;
//     }

//     // output the x coordinate
//     offset = numsize - BN_num_bytes(bnX);
//     memset(buffer, 0, numsize);
//     BN_bn2bin(bnX, (buffer + offset));
//     if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
//     {
//         goto _ec_to_string_cleanup;
//     }
//     field = _cjose_json_stringn(b64u, len, err);
//     if (!field)
//     {
//         goto _ec_to_string_cleanup;
//     }
//     json_object_set(json, "x", field);
//     json_decref(field);
//     field = NULL;
//     cjose_get_dealloc()(b64u);
//     b64u = NULL;

//     // output the y coordinate
//     offset = numsize - BN_num_bytes(bnY);
//     memset(buffer, 0, numsize);
//     BN_bn2bin(bnY, (buffer + offset));
//     if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
//     {
//         goto _ec_to_string_cleanup;
//     }
//     field = _cjose_json_stringn(b64u, len, err);
//     if (!field)
//     {
//         goto _ec_to_string_cleanup;
//     }
//     json_object_set(json, "y", field);
//     json_decref(field);
//     field = NULL;
//     cjose_get_dealloc()(b64u);
//     b64u = NULL;

//     result = true;

// _ec_to_string_cleanup:
//     if (field)
//     {
//         json_decref(field);
//     }
//     if (bnX)
//     {
//         BN_free(bnX);
//     }
//     if (bnY)
//     {
//         BN_free(bnY);
//     }
//     if (buffer)
//     {
//         cjose_get_dealloc()(buffer);
//     }
//     if (b64u)
//     {
//         cjose_get_dealloc()(b64u);
//     }

//     return result;
// }

// static bool _EC_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
// {
//     ec_keydata *keydata = (ec_keydata *)jwk->keydata;
//     const BIGNUM *bnD = EC_KEY_get0_private_key(keydata->key);
//     uint8_t *buffer = NULL;
//     char *b64u = NULL;
//     size_t len = 0, offset = 0;
//     json_t *field = NULL;
//     bool result = false;

//     // track expected binary data size
//     uint8_t numsize = _ec_size_for_curve(keydata->crv, err);

//     // short circuit if 'd' is NULL or 0
//     if (!bnD || BN_is_zero(bnD))
//     {
//         return true;
//     }

//     buffer = cjose_get_alloc()(numsize);
//     if (!buffer)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto _ec_to_string_cleanup;
//     }

//     offset = numsize - BN_num_bytes(bnD);
//     memset(buffer, 0, numsize);
//     BN_bn2bin(bnD, (buffer + offset));
//     if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
//     {
//         goto _ec_to_string_cleanup;
//     }
//     field = _cjose_json_stringn(b64u, len, err);
//     if (!field)
//     {
//         goto _ec_to_string_cleanup;
//     }
//     json_object_set(json, "d", field);
//     json_decref(field);
//     field = NULL;
//     cjose_get_dealloc()(b64u);
//     b64u = NULL;

//     result = true;

// _ec_to_string_cleanup:
//     if (buffer)
//     {
//         cjose_get_dealloc()(buffer);
//     }

//     return result;
// }

// // interface functions -- Elliptic Curve

// cjose_jwk_t *cjose_jwk_create_EC_random(cjose_jwk_ec_curve crv, cjose_err *err)
// {
//     cjose_jwk_t *jwk = NULL;
//     EC_KEY *ec = NULL;

//     ec = EC_KEY_new_by_curve_name(crv);
//     if (!ec)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto create_EC_failed;
//     }

//     if (1 != EC_KEY_generate_key(ec))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto create_EC_failed;
//     }

//     jwk = _EC_new(crv, ec, err);
//     if (!jwk)
//     {
//         goto create_EC_failed;
//     }

//     return jwk;

// create_EC_failed:
//     if (jwk)
//     {
//         cjose_get_dealloc()(jwk);
//         jwk = NULL;
//     }
//     if (ec)
//     {
//         EC_KEY_free(ec);
//         ec = NULL;
//     }

//     return NULL;
// }

// cjose_jwk_t *cjose_jwk_create_EC_spec(const cjose_jwk_ec_keyspec *spec, cjose_err *err)
// {
//     cjose_jwk_t *jwk = NULL;
//     EC_KEY *ec = NULL;
//     EC_GROUP *params = NULL;
//     EC_POINT *Q = NULL;
//     BIGNUM *bnD = NULL;
//     BIGNUM *bnX = NULL;
//     BIGNUM *bnY = NULL;

//     if (!spec)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return NULL;
//     }

//     bool hasPriv = (NULL != spec->d && 0 < spec->dlen);
//     bool hasPub = ((NULL != spec->x && 0 < spec->xlen) && (NULL != spec->y && 0 < spec->ylen));
//     if (!hasPriv && !hasPub)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return NULL;
//     }

//     ec = EC_KEY_new_by_curve_name(spec->crv);
//     if (NULL == ec)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto create_EC_failed;
//     }

//     params = (EC_GROUP *)EC_KEY_get0_group(ec);
//     if (NULL == params)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto create_EC_failed;
//     }

//     // convert d from octet string to BIGNUM
//     if (hasPriv)
//     {
//         bnD = BN_bin2bn(spec->d, spec->dlen, NULL);
//         if (NULL == bnD)
//         {
//             CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//             goto create_EC_failed;
//         }
//         if (1 != EC_KEY_set_private_key(ec, bnD))
//         {
//             CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//             goto create_EC_failed;
//         }

//         // calculate public key from private
//         Q = EC_POINT_new(params);
//         if (NULL == Q)
//         {
//             CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//             goto create_EC_failed;
//         }
//         if (1 != EC_POINT_mul(params, Q, bnD, NULL, NULL, NULL))
//         {
//             CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//             goto create_EC_failed;
//         }

//         // public key is set below
//         // ignore provided public key!
//         hasPub = false;
//     }
//     if (hasPub)
//     {
//         Q = EC_POINT_new(params);
//         if (NULL == Q)
//         {
//             CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//             goto create_EC_failed;
//         }

//         bnX = BN_bin2bn(spec->x, spec->xlen, NULL);
//         bnY = BN_bin2bn(spec->y, spec->ylen, NULL);
//         if (!bnX || !bnY)
//         {
//             CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//             goto create_EC_failed;
//         }

//         if (1 != EC_POINT_set_affine_coordinates_GFp(params, Q, bnX, bnY, NULL))
//         {
//             CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//             goto create_EC_failed;
//         }
//     }

//     // always set the public key
//     if (1 != EC_KEY_set_public_key(ec, Q))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto create_EC_failed;
//     }

//     jwk = _EC_new(spec->crv, ec, err);
//     if (!jwk)
//     {
//         goto create_EC_failed;
//     }

//     // jump to cleanup
//     goto create_EC_cleanup;

// create_EC_failed:
//     if (jwk)
//     {
//         cjose_get_dealloc()(jwk);
//         jwk = NULL;
//     }
//     if (ec)
//     {
//         EC_KEY_free(ec);
//         ec = NULL;
//     }

// create_EC_cleanup:
//     if (Q)
//     {
//         EC_POINT_free(Q);
//         Q = NULL;
//     }
//     if (bnD)
//     {
//         BN_free(bnD);
//         bnD = NULL;
//     }
//     if (bnX)
//     {
//         BN_free(bnX);
//         bnX = NULL;
//     }
//     if (bnY)
//     {
//         BN_free(bnY);
//         bnY = NULL;
//     }

//     return jwk;
// }

// const cjose_jwk_ec_curve cjose_jwk_EC_get_curve(const cjose_jwk_t *jwk, cjose_err *err)
// {
//     if (NULL == jwk || CJOSE_JWK_KTY_EC != cjose_jwk_get_kty(jwk, err))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return CJOSE_JWK_EC_INVALID;
//     }

//     ec_keydata *keydata = jwk->keydata;
//     return keydata->crv;
// }

// //////////////// RSA ////////////////
// // internal data & functions -- RSA

// static void _RSA_free(cjose_jwk_t *jwk);
// static bool _RSA_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
// static bool _RSA_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

// static const key_fntable RSA_FNTABLE = { _RSA_free, _RSA_public_fields, _RSA_private_fields };

// static inline cjose_jwk_t *_RSA_new(RSA *rsa, cjose_err *err)
// {
//     cjose_jwk_t *jwk = cjose_get_alloc()(sizeof(cjose_jwk_t));
//     if (!jwk)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         return NULL;
//     }
//     memset(jwk, 0, sizeof(cjose_jwk_t));
//     jwk->retained = 1;
//     jwk->kty = CJOSE_JWK_KTY_RSA;
//     jwk->keysize = RSA_size(rsa) * 8;
//     jwk->keydata = rsa;
//     jwk->fns = &RSA_FNTABLE;

//     return jwk;
// }

// static void _RSA_free(cjose_jwk_t *jwk)
// {
//     RSA *rsa = (RSA *)jwk->keydata;
//     jwk->keydata = NULL;
//     if (rsa)
//     {
//         RSA_free(rsa);
//     }
//     cjose_get_dealloc()(jwk);
// }

// static inline bool _RSA_json_field(BIGNUM *param, const char *name, json_t *json, cjose_err *err)
// {
//     json_t *field = NULL;
//     uint8_t *data = NULL;
//     char *b64u = NULL;
//     size_t datalen = 0, b64ulen = 0;
//     bool result = false;

//     if (!param)
//     {
//         return true;
//     }

//     datalen = BN_num_bytes(param);
//     data = cjose_get_alloc()(sizeof(uint8_t) * datalen);
//     if (!data)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto RSA_json_field_cleanup;
//     }
//     BN_bn2bin(param, data);
//     if (!cjose_base64url_encode(data, datalen, &b64u, &b64ulen, err))
//     {
//         goto RSA_json_field_cleanup;
//     }
//     field = _cjose_json_stringn(b64u, b64ulen, err);
//     if (!field)
//     {
//         goto RSA_json_field_cleanup;
//     }
//     json_object_set(json, name, field);
//     json_decref(field);
//     field = NULL;
//     result = true;

// RSA_json_field_cleanup:
//     if (b64u)
//     {
//         cjose_get_dealloc()(b64u);
//         b64u = NULL;
//     }
//     if (data)
//     {
//         cjose_get_dealloc()(data);
//         data = NULL;
//     }

//     return result;
// }

// static bool _RSA_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
// {
//     RSA *rsa = (RSA *)jwk->keydata;

//     BIGNUM *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL;
//     _cjose_jwk_rsa_get(rsa, &rsa_n, &rsa_e, &rsa_d);

//     if (!_RSA_json_field(rsa_e, "e", json, err))
//     {
//         return false;
//     }
//     if (!_RSA_json_field(rsa_n, "n", json, err))
//     {
//         return false;
//     }

//     return true;
// }

// static bool _RSA_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
// {
//     RSA *rsa = (RSA *)jwk->keydata;

//     BIGNUM *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL;
//     _cjose_jwk_rsa_get(rsa, &rsa_n, &rsa_e, &rsa_d);

//     BIGNUM *rsa_p = NULL, *rsa_q;
//     _cjose_jwk_rsa_get_factors(rsa, &rsa_p, &rsa_q);

//     BIGNUM *rsa_dmp1 = NULL, *rsa_dmq1 = NULL, *rsa_iqmp = NULL;
//     _cjose_jwk_rsa_get_crt(rsa, &rsa_dmp1, &rsa_dmq1, &rsa_iqmp);

//     if (!_RSA_json_field(rsa_d, "d", json, err))
//     {
//         return false;
//     }
//     if (!_RSA_json_field(rsa_p, "p", json, err))
//     {
//         return false;
//     }
//     if (!_RSA_json_field(rsa_q, "q", json, err))
//     {
//         return false;
//     }
//     if (!_RSA_json_field(rsa_dmp1, "dp", json, err))
//     {
//         return false;
//     }
//     if (!_RSA_json_field(rsa_dmq1, "dq", json, err))
//     {
//         return false;
//     }
//     if (!_RSA_json_field(rsa_iqmp, "qi", json, err))
//     {
//         return false;
//     }

//     return true;
// }

// // interface functions -- RSA
// static const uint8_t *DEFAULT_E_DAT = (const uint8_t *)"\x01\x00\x01";
// static const size_t DEFAULT_E_LEN = 3;

// cjose_jwk_t *cjose_jwk_create_RSA_random(size_t keysize, const uint8_t *e, size_t elen, cjose_err *err)
// {
//     if (0 == keysize)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return NULL;
//     }
//     if (NULL == e || 0 >= elen)
//     {
//         e = DEFAULT_E_DAT;
//         elen = DEFAULT_E_LEN;
//     }

//     RSA *rsa = NULL;
//     BIGNUM *bn = NULL;

//     rsa = RSA_new();
//     if (!rsa)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto create_RSA_random_failed;
//     }

//     bn = BN_bin2bn(e, elen, NULL);
//     if (!bn)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto create_RSA_random_failed;
//     }

//     if (0 == RSA_generate_key_ex(rsa, keysize, bn, NULL))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto create_RSA_random_failed;
//     }

//     BN_free(bn);
//     return _RSA_new(rsa, err);

// create_RSA_random_failed:
//     if (bn)
//     {
//         BN_free(bn);
//     }
//     if (rsa)
//     {
//         RSA_free(rsa);
//     }
//     return NULL;
// }

// //////////////// Import ////////////////
// // internal data & functions -- JWK key import

// static const char *_get_json_object_string_attribute(json_t *json, const char *key, cjose_err *err)
// {
//     const char *attr_str = NULL;
//     json_t *attr_json = json_object_get(json, key);
//     if (NULL != attr_json)
//     {
//         attr_str = json_string_value(attr_json);
//     }
//     return attr_str;
// }

// /**
//  * Internal helper function for extracing an octet string from a base64url
//  * encoded field.  Caller provides the json object, the attribute key,
//  * and an expected length for the octet string.  On successful decoding,
//  * this will return a newly allocated buffer with the decoded octet string
//  * of the expected length.
//  *
//  * Note: caller is responsible for freeing the buffer returned by this function.
//  *
//  * \param[in]     json the JSON object from which to read the attribute.
//  * \param[in]     key the name of the attribute to be decoded.
//  * \param[out]    pointer to buffer of octet string (if decoding succeeds).
//  * \param[in/out] in as the expected length of the attribute, out as the
//  *                actual decoded length.  Note, this method succeeds only
//  *                if the actual decoded length matches the expected length.
//  *                If the in-value is 0 this indicates there is no particular
//  *                expected length (i.e. any length is ok).
//  * \returns true  if attribute is either not present or successfully decoded.
//  *                false otherwise.
//  */
// static bool
// _decode_json_object_base64url_attribute(json_t *jwk_json, const char *key, uint8_t **buffer, size_t *buflen, cjose_err *err)
// {
//     // get the base64url encoded string value of the attribute (if any)
//     const char *str = _get_json_object_string_attribute(jwk_json, key, err);
//     if (str == NULL || strlen(str) == 0)
//     {
//         *buflen = 0;
//         *buffer = NULL;
//         return true;
//     }

//     // if a particular decoded length is expected, check for that
//     if (*buflen != 0)
//     {
//         const char *end = NULL;
//         for (end = str + strlen(str) - 1; *end == '=' && end > str; --end)
//             ;
//         size_t unpadded_len = end + 1 - str - ((*end == '=') ? 1 : 0);
//         size_t expected_len = ceil(4 * ((float)*buflen / 3));

//         if (expected_len != unpadded_len)
//         {
//             CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//             *buflen = 0;
//             *buffer = NULL;
//             return false;
//         }
//     }

//     // decode the base64url encoded string to the allocated buffer
//     if (!cjose_base64url_decode(str, strlen(str), buffer, buflen, err))
//     {
//         *buflen = 0;
//         *buffer = NULL;
//         return false;
//     }

//     return true;
// }

// static cjose_jwk_t *_cjose_jwk_import_EC(json_t *jwk_json, cjose_err *err)
// {
//     cjose_jwk_t *jwk = NULL;
//     uint8_t *x_buffer = NULL;
//     uint8_t *y_buffer = NULL;
//     uint8_t *d_buffer = NULL;

//     // get the value of the crv attribute
//     const char *crv_str = _get_json_object_string_attribute(jwk_json, CJOSE_JWK_CRV_STR, err);
//     if (crv_str == NULL)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto import_EC_cleanup;
//     }

//     // get the curve identifer for the curve named by crv
//     cjose_jwk_ec_curve crv;
//     if (!_ec_curve_from_name(crv_str, &crv, err))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto import_EC_cleanup;
//     }

//     // get the decoded value of the x coordinate
//     size_t x_buflen = (size_t)_ec_size_for_curve(crv, err);
//     if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_X_STR, &x_buffer, &x_buflen, err))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto import_EC_cleanup;
//     }

//     // get the decoded value of the y coordinate
//     size_t y_buflen = (size_t)_ec_size_for_curve(crv, err);
//     if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_Y_STR, &y_buffer, &y_buflen, err))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto import_EC_cleanup;
//     }

//     // get the decoded value of the private key d
//     size_t d_buflen = (size_t)_ec_size_for_curve(crv, err);
//     if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_D_STR, &d_buffer, &d_buflen, err))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto import_EC_cleanup;
//     }

//     // create an ec keyspec
//     cjose_jwk_ec_keyspec ec_keyspec;
//     memset(&ec_keyspec, 0, sizeof(cjose_jwk_ec_keyspec));
//     ec_keyspec.crv = crv;
//     ec_keyspec.x = x_buffer;
//     ec_keyspec.xlen = x_buflen;
//     ec_keyspec.y = y_buffer;
//     ec_keyspec.ylen = y_buflen;
//     ec_keyspec.d = d_buffer;
//     ec_keyspec.dlen = d_buflen;

//     // create the jwk
//     jwk = cjose_jwk_create_EC_spec(&ec_keyspec, err);

// import_EC_cleanup:
//     if (NULL != x_buffer)
//     {
//         cjose_get_dealloc()(x_buffer);
//     }
//     if (NULL != y_buffer)
//     {
//         cjose_get_dealloc()(y_buffer);
//     }
//     if (NULL != d_buffer)
//     {
//         cjose_get_dealloc()(d_buffer);
//     }

//     return jwk;
// }

// static cjose_jwk_t *_cjose_jwk_import_RSA(json_t *jwk_json, cjose_err *err)
// {
//     cjose_jwk_t *jwk = NULL;
//     uint8_t *n_buffer = NULL;
//     uint8_t *e_buffer = NULL;
//     uint8_t *d_buffer = NULL;
//     uint8_t *p_buffer = NULL;
//     uint8_t *q_buffer = NULL;
//     uint8_t *dp_buffer = NULL;
//     uint8_t *dq_buffer = NULL;
//     uint8_t *qi_buffer = NULL;

//     // get the decoded value of n (buflen = 0 means no particular expected len)
//     size_t n_buflen = 0;
//     if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_N_STR, &n_buffer, &n_buflen, err))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto import_RSA_cleanup;
//     }

//     // get the decoded value of e
//     size_t e_buflen = 0;
//     if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_E_STR, &e_buffer, &e_buflen, err))
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto import_RSA_cleanup;
//     }

//     // get the decoded value of d
//     size_t d_buflen = 0;
//     if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_D_STR, &d_buffer, &d_buflen, err))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto import_RSA_cleanup;
//     }

//     // get the decoded value of p
//     size_t p_buflen = 0;
//     if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_P_STR, &p_buffer, &p_buflen, err))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto import_RSA_cleanup;
//     }

//     // get the decoded value of q
//     size_t q_buflen = 0;
//     if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_Q_STR, &q_buffer, &q_buflen, err))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto import_RSA_cleanup;
//     }

//     // get the decoded value of dp
//     size_t dp_buflen = 0;
//     if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_DP_STR, &dp_buffer, &dp_buflen, err))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto import_RSA_cleanup;
//     }

//     // get the decoded value of dq
//     size_t dq_buflen = 0;
//     if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_DQ_STR, &dq_buffer, &dq_buflen, err))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto import_RSA_cleanup;
//     }

//     // get the decoded value of qi
//     size_t qi_buflen = 0;
//     if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_QI_STR, &qi_buffer, &qi_buflen, err))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//     }

//     // create an rsa keyspec
//     cjose_jwk_rsa_keyspec rsa_keyspec;
//     memset(&rsa_keyspec, 0, sizeof(cjose_jwk_rsa_keyspec));
//     rsa_keyspec.n = n_buffer;
//     rsa_keyspec.nlen = n_buflen;
//     rsa_keyspec.e = e_buffer;
//     rsa_keyspec.elen = e_buflen;
//     rsa_keyspec.d = d_buffer;
//     rsa_keyspec.dlen = d_buflen;
//     rsa_keyspec.p = p_buffer;
//     rsa_keyspec.plen = p_buflen;
//     rsa_keyspec.q = q_buffer;
//     rsa_keyspec.qlen = q_buflen;
//     rsa_keyspec.dp = dp_buffer;
//     rsa_keyspec.dplen = dp_buflen;
//     rsa_keyspec.dq = dq_buffer;
//     rsa_keyspec.dqlen = dq_buflen;
//     rsa_keyspec.qi = qi_buffer;
//     rsa_keyspec.qilen = qi_buflen;

//     // create the jwk
//     jwk = cjose_jwk_create_RSA_spec(&rsa_keyspec, err);

// import_RSA_cleanup:
//     cjose_get_dealloc()(n_buffer);
//     cjose_get_dealloc()(e_buffer);
//     cjose_get_dealloc()(d_buffer);
//     cjose_get_dealloc()(p_buffer);
//     cjose_get_dealloc()(q_buffer);
//     cjose_get_dealloc()(dp_buffer);
//     cjose_get_dealloc()(dq_buffer);
//     cjose_get_dealloc()(qi_buffer);

//     return jwk;
// }

// static cjose_jwk_t *_cjose_jwk_import_oct(json_t *jwk_json, cjose_err *err)
// {
//     cjose_jwk_t *jwk = NULL;
//     uint8_t *k_buffer = NULL;

//     // get the decoded value of k (buflen = 0 means no particular expected len)
//     size_t k_buflen = 0;
//     if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_K_STR, &k_buffer, &k_buflen, err))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto import_oct_cleanup;
//     }

//     // create the jwk
//     jwk = cjose_jwk_create_oct_spec(k_buffer, k_buflen, err);

// import_oct_cleanup:
//     if (NULL != k_buffer)
//     {
//         cjose_get_dealloc()(k_buffer);
//     }

//     return jwk;
// }

// cjose_jwk_t *cjose_jwk_import(const char *jwk_str, size_t len, cjose_err *err)
// {
//     cjose_jwk_t *jwk = NULL;

//     // check params
//     if ((NULL == jwk_str) || (0 == len))
//     {
//         return NULL;
//     }

//     // parse json content from the given string
//     json_t *jwk_json = json_loadb(jwk_str, len, 0, NULL);
//     if (NULL == jwk_json)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto import_cleanup;
//     }

//     jwk = cjose_jwk_import_json((cjose_header_t *)jwk_json, err);

// // poor man's "finally"
// import_cleanup:
//     if (NULL != jwk_json)
//     {
//         json_decref(jwk_json);
//     }

//     return jwk;
// }

// cjose_jwk_t *cjose_jwk_import_json(cjose_header_t *json, cjose_err *err)
// {
//     cjose_jwk_t *jwk = NULL;

//     json_t *jwk_json = (json_t *)json;

//     if (NULL == jwk_json || JSON_OBJECT != json_typeof(jwk_json))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return NULL;
//     }

//     // get the string value of the kty attribute of the jwk
//     const char *kty_str = _get_json_object_string_attribute(jwk_json, CJOSE_JWK_KTY_STR, err);
//     if (NULL == kty_str)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return NULL;
//     }

//     // get kty corresponding to kty_str (kty is required)
//     cjose_jwk_kty_t kty;
//     if (!_kty_from_name(kty_str, &kty, err))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return NULL;
//     }

//     // create a cjose_jwt_t based on the kty
//     switch (kty)
//     {
//     case CJOSE_JWK_KTY_EC:
//         jwk = _cjose_jwk_import_EC(jwk_json, err);
//         break;

//     case CJOSE_JWK_KTY_RSA:
//         jwk = _cjose_jwk_import_RSA(jwk_json, err);
//         break;

//     case CJOSE_JWK_KTY_OCT:
//         jwk = _cjose_jwk_import_oct(jwk_json, err);
//         break;

//     default:
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return NULL;
//     }
//     if (NULL == jwk)
//     {
//         // helper function will have already set err
//         return NULL;
//     }

//     // get the value of the kid attribute (kid is optional)
//     const char *kid_str = _get_json_object_string_attribute(jwk_json, CJOSE_JWK_KID_STR, err);
//     if (kid_str != NULL)
//     {
//         jwk->kid = _cjose_strndup(kid_str, -1, err);
//         if (!jwk->kid)
//         {
//             cjose_jwk_release(jwk);
//             return NULL;
//         }
//     }

//     return jwk;
// }

// //////////////// ECDH ////////////////
// // internal data & functions -- ECDH derivation

// static bool _cjose_jwk_evp_key_from_ec_key(const cjose_jwk_t *jwk, EVP_PKEY **key, cjose_err *err)
// {
//     // validate that the jwk is of type EC and we have a valid out-param
//     if (NULL == jwk || CJOSE_JWK_KTY_EC != jwk->kty || NULL == jwk->keydata || NULL == key || NULL != *key)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         goto _cjose_jwk_evp_key_from_ec_key_fail;
//     }

//     // create a blank EVP_PKEY
//     *key = EVP_PKEY_new();
//     if (NULL == key)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
//         goto _cjose_jwk_evp_key_from_ec_key_fail;
//     }

//     // assign the EVP_PKEY to reference the jwk's internal EC_KEY structure
//     if (1 != EVP_PKEY_set1_EC_KEY(*key, ((struct _ec_keydata_int *)(jwk->keydata))->key))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
//         goto _cjose_jwk_evp_key_from_ec_key_fail;
//     }

//     // happy path
//     return true;

// // fail path
// _cjose_jwk_evp_key_from_ec_key_fail:

//     EVP_PKEY_free(*key);
//     *key = NULL;

//     return false;
// }

// cjose_jwk_t *cjose_jwk_derive_ecdh_secret(
//     const cjose_jwk_t *jwk_self, const cjose_jwk_t *jwk_peer, const uint8_t *salt, size_t salt_len, cjose_err *err)
// {
//     return cjose_jwk_derive_ecdh_ephemeral_key(jwk_self, jwk_peer, salt, salt_len, err);
// }

// cjose_jwk_t *cjose_jwk_derive_ecdh_ephemeral_key(
//     const cjose_jwk_t *jwk_self, const cjose_jwk_t *jwk_peer, const uint8_t *salt, size_t salt_len, cjose_err *err)
// {
//     uint8_t *secret = NULL;
//     size_t secret_len = 0;
//     uint8_t *ephemeral_key = NULL;
//     size_t ephemeral_key_len = 0;
//     cjose_jwk_t *jwk_ephemeral_key = NULL;

//     if (!cjose_jwk_derive_ecdh_bits(jwk_self, jwk_peer, &secret, &secret_len, err))
//     {
//         goto _cjose_jwk_derive_shared_secret_fail;
//     }

//     // HKDF of the DH shared secret (SHA256, no info, 256 bit expand)
//     ephemeral_key_len = 32;
//     ephemeral_key = (uint8_t *)cjose_get_alloc()(ephemeral_key_len);
//     if (!cjose_jwk_hkdf(EVP_sha256(), salt, salt_len, (uint8_t *)"", 0, secret, secret_len, ephemeral_key, ephemeral_key_len, err))
//     {
//         goto _cjose_jwk_derive_shared_secret_fail;
//     }

//     // create a JWK of the shared secret
//     jwk_ephemeral_key = cjose_jwk_create_oct_spec(ephemeral_key, ephemeral_key_len, err);
//     if (NULL == jwk_ephemeral_key)
//     {
//         goto _cjose_jwk_derive_shared_secret_fail;
//     }

//     // happy path
//     cjose_get_dealloc()(secret);
//     cjose_get_dealloc()(ephemeral_key);

//     return jwk_ephemeral_key;

// // fail path
// _cjose_jwk_derive_shared_secret_fail:

//     if (NULL != jwk_ephemeral_key)
//     {
//         cjose_jwk_release(jwk_ephemeral_key);
//     }
//     cjose_get_dealloc()(secret);
//     cjose_get_dealloc()(ephemeral_key);
//     return NULL;
// }

// bool cjose_jwk_derive_ecdh_bits(
//     const cjose_jwk_t *jwk_self, const cjose_jwk_t *jwk_peer, uint8_t **output, size_t *output_len, cjose_err *err)
// {
//     EVP_PKEY_CTX *ctx = NULL;
//     EVP_PKEY *pkey_self = NULL;
//     EVP_PKEY *pkey_peer = NULL;
//     uint8_t *secret = NULL;
//     size_t secret_len = 0;

//     // get EVP_KEY from jwk_self
//     if (!_cjose_jwk_evp_key_from_ec_key(jwk_self, &pkey_self, err))
//     {
//         goto _cjose_jwk_derive_bits_fail;
//     }

//     // get EVP_KEY from jwk_peer
//     if (!_cjose_jwk_evp_key_from_ec_key(jwk_peer, &pkey_peer, err))
//     {
//         goto _cjose_jwk_derive_bits_fail;
//     }

//     // create derivation context based on local key pair
//     ctx = EVP_PKEY_CTX_new(pkey_self, NULL);
//     if (NULL == ctx)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
//         goto _cjose_jwk_derive_bits_fail;
//     }

//     // initialize derivation context
//     if (1 != EVP_PKEY_derive_init(ctx))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
//         goto _cjose_jwk_derive_bits_fail;
//     }

//     // provide the peer public key
//     if (1 != EVP_PKEY_derive_set_peer(ctx, pkey_peer))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
//         goto _cjose_jwk_derive_bits_fail;
//     }

//     // determine buffer length for shared secret
//     if (1 != EVP_PKEY_derive(ctx, NULL, &secret_len))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
//         goto _cjose_jwk_derive_bits_fail;
//     }

//     // allocate buffer for shared secret
//     secret = (uint8_t *)cjose_get_alloc()(secret_len);
//     if (NULL == output)
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto _cjose_jwk_derive_bits_fail;
//     }
//     memset(secret, 0, secret_len);

//     // derive the shared secret
//     if (1 != (EVP_PKEY_derive(ctx, secret, &secret_len)))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
//         goto _cjose_jwk_derive_bits_fail;
//     }

//     // happy path
//     EVP_PKEY_CTX_free(ctx);
//     EVP_PKEY_free(pkey_self);
//     EVP_PKEY_free(pkey_peer);

//     *output = secret;
//     *output_len = secret_len;
//     return true;

// _cjose_jwk_derive_bits_fail:

//     if (NULL != ctx)
//     {
//         EVP_PKEY_CTX_free(ctx);
//     }
//     if (NULL != pkey_self)
//     {
//         EVP_PKEY_free(pkey_self);
//     }
//     if (NULL != pkey_peer)
//     {
//         EVP_PKEY_free(pkey_peer);
//     }
//     cjose_get_dealloc()(secret);

//     return false;
// }

// bool cjose_jwk_hkdf(const EVP_MD *md,
//                     const uint8_t *salt,
//                     size_t salt_len,
//                     const uint8_t *info,
//                     size_t info_len,
//                     const uint8_t *ikm,
//                     size_t ikm_len,
//                     uint8_t *okm,
//                     unsigned int okm_len,
//                     cjose_err *err)
// {
//     // current impl. is very limited: SHA256, 256 bit output, and no info
//     if ((EVP_sha256() != md) || (0 != info_len) || (32 != okm_len))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
//         return false;
//     }

//     // HKDF-Extract, HMAC-SHA256(salt, IKM) -> PRK
//     unsigned int prk_len;
//     unsigned char prk[EVP_MAX_MD_SIZE];
//     if (NULL == HMAC(md, salt, salt_len, ikm, ikm_len, prk, &prk_len))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
//         return false;
//     }

//     // HKDF-Expand, HMAC-SHA256(PRK,0x01) -> OKM
//     const unsigned char t[] = { 0x01 };
//     if (NULL == HMAC(md, prk, prk_len, t, sizeof(t), okm, NULL))
//     {
//         CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
//         return false;
//     }

//     return true;
// }

#[cfg(test)]
mod test {
    use super::*;
    use crate::base64::{decode, Base64Variant};

    #[test]
    fn test_key_type() {
        assert_eq!(KeyType::Ec.to_str(), "EC");
        assert_eq!(KeyType::Rsa.to_str(), "RSA");
        assert_eq!(KeyType::Oct.to_str(), "oct");

        assert_eq!(KeyType::Ec, KeyType::from_str("EC"));
        assert_eq!(KeyType::Rsa, KeyType::from_str("RSA"));
        assert_eq!(KeyType::Oct, KeyType::from_str("oct"));
    }

    #[test]
    fn test_rsa_keys() {
        const RSA_E: &str = "AQAB";
        const RSA_N: &str = "2Rgbvu_cGMpvVl8DE6aGGX7IE2lKn5c9ZtexriFrCLqBbKt2TBOZko\
Cn_AbcDjUVk23CxsIj9Z1VfsL_0UeVA_AeOLUWw0F5-JhoK6NBeLpYZOz7HYieTOSJjSxYhoCYtVbLK\
I27e3NEvckxTs-90CdKl71P7YwrdSrY59hR-u2etyNCRGAPcoDH5xYJxrG2p5FH_Dh_MQ0ugDnJY2_b\
_-w9NS2Y2atIkzXZDjtcSpjImKpL0eIFF69ptiF8vd4q2j-ougipFBGP9U5bSVzeZ7FyGkJ5Qa2DYc0\
osYi1QFs3YZKzkKfcblx14u-yZYhUkZHlb_jbfulnUHxDdO_r8Q";
        const RSA_D: &str = "P9N6tNRIXXGG8lnUyb43xt8ja7GVIv6QKuBXeN6SXWqYCp8OlKdei1\
gQC2To5bRtt36ZuV3yvI-ZRz-Ffr4Q7at29y0mmBl0BsaoOcwxv5Dp1CJoYfJ8uBao6jyTelfsjcQKz\
s18xXrKRxIT0Rv6rmwe3iXmjeycCkKiqudKkv8m9RtbvdWH8AFd2ZsCLNblVRrOZ9ZPQQCMVJLf65pF\
_cBfux-Zz_CJCfq93gFcN3h1tPFLX8UPBMqvqkBZzDx8PGoYgrydz-T8tcqtkDriyEL3mGYe9b2uH_8\
JnzMMNMFheVPDdNBhyQQVOmQqPj7idv7677eSle4LJZANUYZdwQ";
        const RSA_P: &str = "8Yhaq4UMiFptSuUMcLUqOJdZ9Jr0z2KG_ZrPaaHIX8gfbtp5DGjhXE\
E--SwoX9ukEzR6vCewSFcEl20wnT0uTwrVs-Bf2J1L-5tKKeiiwLQxXtk1cG5-PI-ECkqX0AP2K2Xa0\
wpIjldBE5SBR0S7whANpKxhVFMtNgKog4xNvxU";
        const RSA_Q: &str = "5hkENNaWQSJ5qWXVJYh0LAHddr1NXwkKIfKNjK8vCYfOHXDgKxW4Ub\
AIu7wIU9iZcVjTdN2UcaJMe5fBQR9ZEP8bcuY9ZpeUCkv-g9IGw69HUXE7ERBz1es_lZOuJzENwL85A\
l7jOtVJ2y26g4r30q4jqaL7CcgUZjBKAytjUG0";
        const RSA_DP: &str = "pAn1epQsRNcVb05Muqdv-2tfnu824TqLb-YahCVqjxK9tm4O1EzO8\
fcmK9i_uwrTTm_QA8X4xcjDx4xS_he1Qd2b8kSrE9UQ69s17WygTLyU41QmJSwF9F-MT-kFXjOylxrg\
GYDccj_0ZLXxb1PRKSX5_iNNHxY2mH4JsP4zN1k";
        const RSA_DQ: &str = "gTTxAL6y9vZl_PKa4w2htoiBlMiuJryLvQ5X3_ULY72nxy54Ipl6v\
Bwue0UWJAcP-u8XJpu6XKj3a7uGoIv61ql5_2Y8elyJm9Kao-kPNVk6oggEVAu6EBiext57v7Qy9dYr\
LCKeVI4qf_JIts8VZG-2xO4pK4_3rH5XQTpe9W0";
        const RSA_QI: &str = "xTJ_ON_6kc9g3ZbunSSt_oqJBguxH2x8HVl2KQXafW-F0_DOv09P1\
e0fbSdOLhR-V9lLjq8DxOcvCMxkpQr2G8lTaBRVTF_-szu9adi9bgb_-egvc_NAvRkuGE9fUmB2_nAy\
U-j4VUh1MMSP5qqQhMYvFdAF5y36MpI-pV1SLFQ";

        let rsa_spec_private = RsaKeySpec {
            e: decode(RSA_E, Base64Variant::UrlSafe).expect("Failed to decode RSA e"),
            n: decode(RSA_N, Base64Variant::UrlSafe).expect("Failed to decode RSA e"),
            d: decode(RSA_D, Base64Variant::UrlSafe).expect("Failed to decode RSA e"),
            p: decode(RSA_P, Base64Variant::UrlSafe).expect("Failed to decode RSA e"),
            q: decode(RSA_Q, Base64Variant::UrlSafe).expect("Failed to decode RSA e"),
            dp: decode(RSA_DP, Base64Variant::UrlSafe).expect("Failed to decode RSA e"),
            dq: decode(RSA_DQ, Base64Variant::UrlSafe).expect("Failed to decode RSA e"),
            qi: decode(RSA_QI, Base64Variant::UrlSafe).expect("Failed to decode RSA e"),
        };

        let jwk = Jwk::create_rsa_spec(&rsa_spec_private).expect("Failed to create RSA JWK");

        assert_eq!(jwk.key_type, KeyType::Rsa);
        assert_eq!(jwk.key_size, 2048);
    }

    //     // everything
    //     cjose_jwk_t *jwk = NULL;
    //     jwk = cjose_jwk_create_RSA_spec(&specPriv, &err);
    //     ck_assert(NULL != jwk);
    //     ck_assert(1 == jwk->retained);
    //     ck_assert(CJOSE_JWK_KTY_RSA == jwk->kty);
    //     ck_assert(2048 == jwk->keysize);
    //     ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    //     ck_assert(NULL != jwk->keydata);
    //     ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    //     cjose_jwk_release(jwk);

    //     // only private is not possible after the OpenSSL 1.1.x changes because e & n always need to be set

    //     // minimal private
    //     cjose_get_dealloc()(specPriv.p);
    //     specPriv.p = NULL;
    //     cjose_get_dealloc()(specPriv.q);
    //     specPriv.q = NULL;
    //     cjose_get_dealloc()(specPriv.dp);
    //     specPriv.dp = NULL;
    //     cjose_get_dealloc()(specPriv.dq);
    //     specPriv.dq = NULL;
    //     cjose_get_dealloc()(specPriv.qi);
    //     specPriv.qi = NULL;
    //     jwk = cjose_jwk_create_RSA_spec(&specPriv, &err);
    //     ck_assert(NULL != jwk);
    //     ck_assert(1 == jwk->retained);
    //     ck_assert(CJOSE_JWK_KTY_RSA == jwk->kty);
    //     ck_assert(2048 == jwk->keysize);
    //     ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    //     ck_assert(NULL != jwk->keydata);
    //     ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    //     cjose_jwk_release(jwk);

    //     cjose_get_dealloc()(specPriv.n);
    //     specPriv.n = NULL;
    //     cjose_get_dealloc()(specPriv.d);
    //     specPriv.d = NULL;
    //     cjose_get_dealloc()(specPriv.e);
    //     specPriv.e = NULL;

    //     // public only
    //     memset(&specPub, 0, sizeof(cjose_jwk_rsa_keyspec));
    //     cjose_base64url_decode(RSA_e, strlen(RSA_e), &specPub.e, &specPub.elen, &err);
    //     cjose_base64url_decode(RSA_n, strlen(RSA_n), &specPub.n, &specPub.nlen, &err);

    //     jwk = cjose_jwk_create_RSA_spec(&specPub, &err);
    //     ck_assert(NULL != jwk);
    //     ck_assert(1 == jwk->retained);
    //     ck_assert(CJOSE_JWK_KTY_RSA == jwk->kty);
    //     ck_assert(2048 == jwk->keysize);
    //     ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    //     ck_assert(NULL != jwk->keydata);
    //     ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    //     cjose_jwk_release(jwk);

    //     cjose_get_dealloc()(specPub.n);
    //     specPub.n = NULL;
    //     cjose_get_dealloc()(specPub.e);
    //     specPub.e = NULL;
    // }
    // END_TEST

    // START_TEST(test_cjose_jwk_create_RSA_random)
    // {
    //     cjose_err err;
    //     cjose_jwk_t *jwk = NULL;
    //     uint8_t *e = NULL;
    //     size_t elen = 0;

    //     e = (uint8_t *)"\x01\x00\x01";
    //     elen = 3;
    //     jwk = cjose_jwk_create_RSA_random(2048, e, elen, &err);
    //     ck_assert(NULL != jwk);
    //     ck_assert(1 == jwk->retained);
    //     ck_assert(CJOSE_JWK_KTY_RSA == jwk->kty);
    //     ck_assert(2048 == jwk->keysize);
    //     ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    //     ck_assert(NULL != jwk->keydata);
    //     ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);

    //     cjose_jwk_release(jwk);

    //     e = NULL;
    //     elen = 0;
    //     jwk = cjose_jwk_create_RSA_random(2048, e, elen, &err);
    //     ck_assert(NULL != jwk);
    //     ck_assert(1 == jwk->retained);
    //     ck_assert(CJOSE_JWK_KTY_RSA == jwk->kty);
    //     ck_assert(2048 == jwk->keysize);
    //     ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    //     ck_assert(NULL != jwk->keydata);
    //     ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);

    //     cjose_jwk_release(jwk);
    // }
    // END_TEST

    // const char *EC_P256_d = "RSSjcBQW_EBxm1gzYhejCdWtj3Id_GuwldwEgSuKCEM";
    // const char *EC_P256_x = "ii8jCnvs4FLc0rteSWxanup22pNDhzizmlGN-bfTcFk";
    // const char *EC_P256_y = "KbkZ7r_DQ-t67pnxPnFDHObTLBqn44BSjcqn0STUkaM";
    // START_TEST(test_cjose_jwk_create_EC_P256_spec)
    // {
    //     cjose_err err;
    //     cjose_jwk_t *jwk = NULL;
    //     cjose_jwk_ec_keyspec spec;

    //     memset(&spec, 0, sizeof(cjose_jwk_ec_keyspec));
    //     spec.crv = CJOSE_JWK_EC_P_256;
    //     cjose_base64url_decode(EC_P256_d, strlen(EC_P256_d), &spec.d, &spec.dlen, &err);
    //     cjose_base64url_decode(EC_P256_x, strlen(EC_P256_x), &spec.x, &spec.xlen, &err);
    //     cjose_base64url_decode(EC_P256_y, strlen(EC_P256_y), &spec.y, &spec.ylen, &err);

    //     jwk = cjose_jwk_create_EC_spec(&spec, &err);
    //     ck_assert(NULL != jwk);
    //     ck_assert(1 == jwk->retained);
    //     ck_assert(CJOSE_JWK_KTY_EC == jwk->kty);
    //     ck_assert(256 == jwk->keysize);
    //     ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    //     ck_assert(NULL != jwk->keydata);
    //     ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    //     ck_assert(CJOSE_JWK_EC_P_256 == cjose_jwk_EC_get_curve(jwk, &err));
    //     cjose_get_dealloc()(spec.d);
    //     cjose_get_dealloc()(spec.x);
    //     cjose_get_dealloc()(spec.y);

    //     // cleanup
    //     cjose_jwk_release(jwk);
    // }
    // END_TEST
    // START_TEST(test_cjose_jwk_create_EC_P256_random)
    // {
    //     cjose_err err;
    //     cjose_jwk_t *jwk = NULL;

    //     jwk = cjose_jwk_create_EC_random(CJOSE_JWK_EC_P_256, &err);
    //     ck_assert(1 == jwk->retained);
    //     ck_assert(CJOSE_JWK_KTY_EC == jwk->kty);
    //     ck_assert(256 == jwk->keysize);
    //     ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    //     ck_assert(NULL != jwk->keydata);
    //     ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    //     ck_assert(CJOSE_JWK_EC_P_256 == cjose_jwk_EC_get_curve(jwk, &err));

    //     // cleanup
    //     cjose_jwk_release(jwk);
    // }
    // END_TEST

    // const char *EC_384_d = "vpwFfxYfV7Ftm3fuidQsK-l_tGxqqnUUG6R5QZStJAeZy7qQiHAo7rZumFslws38";
    // const char *EC_384_x = "ulIwcMpG6gbi9Bo_CeVFDIu7RT-AFxu5NRiH9Wm39lYQOAcZTlHJM8Tz4Fwbtu-0";
    // const char *EC_384_y = "WOZtl6a6x_ukWquJbd_sF18zivwVq26HhJbnmwEKuab7zvZ3sGzOX7LJCHl4zmXa";
    // START_TEST(test_cjose_jwk_create_EC_P384_spec)
    // {
    //     cjose_err err;
    //     cjose_jwk_t *jwk = NULL;
    //     cjose_jwk_ec_keyspec spec;

    //     memset(&spec, 0, sizeof(cjose_jwk_ec_keyspec));
    //     spec.crv = CJOSE_JWK_EC_P_384;
    //     cjose_base64url_decode(EC_384_d, strlen(EC_384_d), &spec.d, &spec.dlen, &err);
    //     cjose_base64url_decode(EC_384_x, strlen(EC_384_x), &spec.x, &spec.xlen, &err);
    //     cjose_base64url_decode(EC_384_y, strlen(EC_384_y), &spec.y, &spec.ylen, &err);

    //     jwk = cjose_jwk_create_EC_spec(&spec, &err);
    //     ck_assert(NULL != jwk);
    //     ck_assert(1 == jwk->retained);
    //     ck_assert(CJOSE_JWK_KTY_EC == jwk->kty);
    //     ck_assert(384 == jwk->keysize);
    //     ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    //     ck_assert(NULL != jwk->keydata);
    //     ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    //     ck_assert(CJOSE_JWK_EC_P_384 == cjose_jwk_EC_get_curve(jwk, &err));
    //     cjose_get_dealloc()(spec.d);
    //     cjose_get_dealloc()(spec.x);
    //     cjose_get_dealloc()(spec.y);

    //     // cleanup
    //     cjose_jwk_release(jwk);
    // }
    // END_TEST
    // START_TEST(test_cjose_jwk_create_EC_P384_random)
    // {
    //     cjose_err err;
    //     cjose_jwk_t *jwk = NULL;

    //     jwk = cjose_jwk_create_EC_random(CJOSE_JWK_EC_P_384, &err);
    //     ck_assert(1 == jwk->retained);
    //     ck_assert(CJOSE_JWK_KTY_EC == jwk->kty);
    //     ck_assert(384 == jwk->keysize);
    //     ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    //     ck_assert(NULL != jwk->keydata);
    //     ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    //     ck_assert(CJOSE_JWK_EC_P_384 == cjose_jwk_EC_get_curve(jwk, &err));

    //     // cleanup
    //     cjose_jwk_release(jwk);
    // }
    // END_TEST

    // const char *EC_521_d = "E-0dXEk-bh2Fb08ge8_kNCiSSLiWu7zAR-4SVxH_SfqX2vPimGlF8cU-RFxb64zjW599vsULwvE62MzFWtK63Y4";
    // const char *EC_521_x = "C3LEPuVWTeIQ7KGNibjAdUyHYyapCE6GAQ_oEs7P49yA8AWyJhxIVGWuc1punIsi5WjzHRoNhj0TqEBN4LsW0-g";
    // const char *EC_521_y = "AeMjLFBhdk-lBiaFc8QKYZYziRIS_8q-3ziwXm5zfREdzVv9GUm-l-APSv4gIq-0-G0oSyFf6j6oh7KTf4aYGTV6";
    // START_TEST(test_cjose_jwk_create_EC_P521_spec)
    // {
    //     cjose_err err;
    //     cjose_jwk_t *jwk = NULL;
    //     cjose_jwk_ec_keyspec spec;

    //     memset(&spec, 0, sizeof(cjose_jwk_ec_keyspec));
    //     spec.crv = CJOSE_JWK_EC_P_521;
    //     cjose_base64url_decode(EC_521_d, strlen(EC_521_d), &spec.d, &spec.dlen, &err);
    //     cjose_base64url_decode(EC_521_x, strlen(EC_521_x), &spec.x, &spec.xlen, &err);
    //     cjose_base64url_decode(EC_521_y, strlen(EC_521_y), &spec.y, &spec.ylen, &err);

    //     jwk = cjose_jwk_create_EC_spec(&spec, &err);
    //     ck_assert(NULL != jwk);
    //     ck_assert(1 == jwk->retained);
    //     ck_assert(CJOSE_JWK_KTY_EC == jwk->kty);
    //     ck_assert(521 == jwk->keysize);
    //     ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    //     ck_assert(NULL != jwk->keydata);
    //     ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    //     ck_assert(CJOSE_JWK_EC_P_521 == cjose_jwk_EC_get_curve(jwk, &err));
    //     free(spec.d);
    //     free(spec.x);
    //     free(spec.y);

    //     // cleanup
    //     cjose_jwk_release(jwk);
    // }
    // END_TEST
    // START_TEST(test_cjose_jwk_create_EC_P521_random)
    // {
    //     cjose_err err;
    //     cjose_jwk_t *jwk = NULL;

    //     jwk = cjose_jwk_create_EC_random(CJOSE_JWK_EC_P_521, &err);
    //     ck_assert(1 == jwk->retained);
    //     ck_assert(CJOSE_JWK_KTY_EC == jwk->kty);
    //     ck_assert(521 == jwk->keysize);
    //     ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    //     ck_assert(NULL != jwk->keydata);
    //     ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    //     ck_assert(CJOSE_JWK_EC_P_521 == cjose_jwk_EC_get_curve(jwk, &err));

    //     // cleanup
    //     cjose_jwk_release(jwk);
    // }
    // END_TEST

    // const uint8_t *OCT_KEY = "pKE-eSbyFqPdtA5WzazKFg";
    // START_TEST(test_cjose_jwk_create_oct_spec)
    // {
    //     cjose_err err;
    //     cjose_jwk_t *jwk = NULL;
    //     uint8_t *k = NULL;
    //     size_t klen = 0;

    //     cjose_base64url_decode(OCT_KEY, strlen(OCT_KEY), &k, &klen, &err);

    //     jwk = cjose_jwk_create_oct_spec(k, klen, &err);
    //     ck_assert(1 == jwk->retained);
    //     ck_assert(CJOSE_JWK_KTY_OCT == jwk->kty);
    //     ck_assert(klen * 8 == jwk->keysize);
    //     ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    //     ck_assert(NULL != jwk->keydata);
    //     ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);
    //     ck_assert_bin_eq(k, jwk->keydata, klen);
    //     cjose_get_dealloc()(k);

    //     // cleanup
    //     cjose_jwk_release(jwk);
    // }
    // END_TEST
    // START_TEST(test_cjose_jwk_create_oct_random)
    // {
    //     cjose_err err;
    //     cjose_jwk_t *jwk = NULL;

    //     jwk = cjose_jwk_create_oct_random(128, &err);
    //     ck_assert(1 == jwk->retained);
    //     ck_assert(CJOSE_JWK_KTY_OCT == jwk->kty);
    //     ck_assert(128 == jwk->keysize);
    //     ck_assert(cjose_jwk_get_keysize(jwk, &err) == jwk->keysize);
    //     ck_assert(NULL != jwk->keydata);
    //     ck_assert(cjose_jwk_get_keydata(jwk, &err) == jwk->keydata);

    //     // cleanup
    //     cjose_jwk_release(jwk);
    // }
    // END_TEST
    // START_TEST(test_cjose_jwk_create_oct_random_inval)
    // {
    //     cjose_err err;
    //     cjose_jwk_t *jwk = NULL;

    //     jwk = cjose_jwk_create_oct_random(0, &err);
    //     ck_assert(NULL == jwk);
    //     ck_assert(CJOSE_ERR_INVALID_ARG == err.code);
    // }
    // END_TEST

    // START_TEST(test_cjose_jwk_retain_release)
    // {
    //     cjose_err err;
    //     // create some type of key
    //     cjose_jwk_t *jwk = cjose_jwk_create_oct_random(128, &err);
    //     ck_assert(1 == jwk->retained);

    //     cjose_jwk_t *retained = NULL;
    //     retained = cjose_jwk_retain(jwk, &err);
    //     ck_assert(jwk == retained);
    //     ck_assert(2 == jwk->retained);

    //     bool result = false;
    //     result = cjose_jwk_release(jwk);
    //     ck_assert(result);
    //     ck_assert(1 == jwk->retained);

    //     retained = cjose_jwk_retain(jwk, &err);
    //     ck_assert(jwk == retained);
    //     ck_assert(2 == jwk->retained);

    //     result = cjose_jwk_release(jwk);
    //     ck_assert(result);
    //     ck_assert(1 == jwk->retained);

    //     result = cjose_jwk_release(jwk);
    //     ck_assert(!result);

    //     result = cjose_jwk_release(NULL);
    //     ck_assert(!result);

    //     retained = cjose_jwk_retain(NULL, &err);
    //     ck_assert(retained == NULL);
    // }
    // END_TEST

    // START_TEST(test_cjose_jwk_get_kty)
    // {
    //     cjose_err err;
    //     cjose_jwk_t *jwk = NULL;
    //     jwk = cjose_jwk_create_oct_random(128, &err);
    //     ck_assert(CJOSE_JWK_KTY_OCT == cjose_jwk_get_kty(jwk, &err));
    //     cjose_jwk_release(jwk);

    //     jwk = cjose_jwk_create_EC_random(CJOSE_JWK_EC_P_256, &err);
    //     ck_assert(CJOSE_JWK_KTY_EC == cjose_jwk_get_kty(jwk, &err));
    //     cjose_jwk_release(jwk);
    // }
    // END_TEST

    // START_TEST(test_cjose_jwk_to_json_oct)
    // {
    //     cjose_err err;
    //     cjose_jwk_t *jwk = NULL;
    //     uint8_t *k = NULL;
    //     size_t klen = 0;

    //     cjose_base64url_decode(OCT_KEY, strlen(OCT_KEY), &k, &klen, &err);
    //     jwk = cjose_jwk_create_oct_spec(k, klen, &err);
    //     cjose_get_dealloc()(k);

    //     char *json;
    //     json = cjose_jwk_to_json(jwk, false, &err);
    //     ck_assert(NULL != json);
    //     ck_assert_str_eq("{\"kty\":\"oct\"}", json);
    //     free(json);

    //     json = cjose_jwk_to_json(jwk, true, &err);
    //     ck_assert(NULL != json);
    //     ck_assert_str_eq("{\"kty\":\"oct\",\"k\":\"pKE-eSbyFqPdtA5WzazKFg\"}", json);
    //     free(json);

    //     cjose_jwk_release(jwk);
    // }
    // END_TEST
    // START_TEST(test_cjose_jwk_to_json_ec)
    // {
    //     cjose_err err;
    //     cjose_jwk_t *jwk = NULL;
    //     cjose_jwk_ec_keyspec spec;

    //     memset(&spec, 0, sizeof(cjose_jwk_ec_keyspec));
    //     spec.crv = CJOSE_JWK_EC_P_256;
    //     cjose_base64url_decode(EC_P256_d, strlen(EC_P256_d), &spec.d, &spec.dlen, &err);
    //     cjose_base64url_decode(EC_P256_x, strlen(EC_P256_x), &spec.x, &spec.xlen, &err);
    //     cjose_base64url_decode(EC_P256_y, strlen(EC_P256_y), &spec.y, &spec.ylen, &err);

    //     jwk = cjose_jwk_create_EC_spec(&spec, &err);
    //     cjose_get_dealloc()(spec.d);
    //     cjose_get_dealloc()(spec.x);
    //     cjose_get_dealloc()(spec.y);

    //     char *json;
    //     json = cjose_jwk_to_json(jwk, false, &err);
    //     ck_assert(NULL != json);
    //     ck_assert_str_eq("{\"kty\":\"EC\",\"crv\":\"P-256\""
    //                      ",\"x\":\"ii8jCnvs4FLc0rteSWxanup22pNDhzizmlGN-bfTcFk\""
    //                      ",\"y\":\"KbkZ7r_DQ-t67pnxPnFDHObTLBqn44BSjcqn0STUkaM\"}",
    //                      json);
    //     free(json);

    //     json = cjose_jwk_to_json(jwk, true, &err);
    //     ck_assert(NULL != json);
    //     ck_assert_str_eq("{\"kty\":\"EC\",\"crv\":\"P-256\""
    //                      ",\"x\":\"ii8jCnvs4FLc0rteSWxanup22pNDhzizmlGN-bfTcFk\""
    //                      ",\"y\":\"KbkZ7r_DQ-t67pnxPnFDHObTLBqn44BSjcqn0STUkaM\""
    //                      ",\"d\":\"RSSjcBQW_EBxm1gzYhejCdWtj3Id_GuwldwEgSuKCEM\"}",
    //                      json);
    //     free(json);

    //     cjose_jwk_release(jwk);
    // }
    // END_TEST

    // const char *RSA_PUBLIC_JSON = "{\"kty\":\"RSA\","
    //                               "\"e\":\"AQAB\""
    //                               ",\"n\":\"2Rgbvu_cGMpvVl8DE6aGGX7IE2lKn5c9ZtexriFrCLqBbKt2TBOZkoCn_AbcDjUVk23CxsIj9Z1VfsL_0UeVA_"
    //                               "AeOLUWw0F5-JhoK6NBeLpYZOz7HYieTOSJjSxYhoCYtVbLKI27e3NEvckxTs-90CdKl71P7YwrdSrY59hR-"
    //                               "u2etyNCRGAPcoDH5xYJxrG2p5FH_Dh_MQ0ugDnJY2_b_-w9NS2Y2atIkzXZDjtcSpjImKpL0eIFF69ptiF8vd4q2j-"
    //                               "ougipFBGP9U5bSVzeZ7FyGkJ5Qa2DYc0osYi1QFs3YZKzkKfcblx14u-yZYhUkZHlb_jbfulnUHxDdO_r8Q\""
    //                               "}";
    // START_TEST(test_cjose_jwk_to_json_rsa)
    // {
    //     cjose_err err;
    //     cjose_jwk_t *jwk = NULL;
    //     cjose_jwk_rsa_keyspec spec;

    //     memset(&spec, 0, sizeof(cjose_jwk_rsa_keyspec));
    //     cjose_base64url_decode(RSA_e, strlen(RSA_e), &spec.e, &spec.elen, &err);
    //     cjose_base64url_decode(RSA_n, strlen(RSA_n), &spec.n, &spec.nlen, &err);
    //     cjose_base64url_decode(RSA_d, strlen(RSA_d), &spec.d, &spec.dlen, &err);
    //     cjose_base64url_decode(RSA_p, strlen(RSA_p), &spec.p, &spec.plen, &err);
    //     cjose_base64url_decode(RSA_q, strlen(RSA_q), &spec.q, &spec.qlen, &err);
    //     cjose_base64url_decode(RSA_dp, strlen(RSA_dp), &spec.dp, &spec.dplen, &err);
    //     cjose_base64url_decode(RSA_dq, strlen(RSA_dq), &spec.dq, &spec.dqlen, &err);
    //     cjose_base64url_decode(RSA_qi, strlen(RSA_qi), &spec.qi, &spec.qilen, &err);

    //     jwk = cjose_jwk_create_RSA_spec(&spec, &err);
    //     cjose_get_dealloc()(spec.e);
    //     cjose_get_dealloc()(spec.n);
    //     cjose_get_dealloc()(spec.d);
    //     cjose_get_dealloc()(spec.p);
    //     cjose_get_dealloc()(spec.q);
    //     cjose_get_dealloc()(spec.dp);
    //     cjose_get_dealloc()(spec.dq);
    //     cjose_get_dealloc()(spec.qi);

    //     char *json;
    //     json = cjose_jwk_to_json(jwk, false, &err);
    //     ck_assert(NULL != json);
    //     ck_assert_str_eq(RSA_PUBLIC_JSON, json);
    //     free(json);

    //     json = cjose_jwk_to_json(jwk, true, &err);
    //     ck_assert(NULL != json);
    //     ck_assert_str_eq("{\"kty\":\"RSA\",\"e\":\"AQAB\""
    //                      ",\"n\":\"2Rgbvu_cGMpvVl8DE6aGGX7IE2lKn5c9ZtexriFrCLqBbKt2TBOZkoCn_AbcDjUVk23CxsIj9Z1VfsL_0UeVA_AeOLUWw0F5-"
    //                      "JhoK6NBeLpYZOz7HYieTOSJjSxYhoCYtVbLKI27e3NEvckxTs-90CdKl71P7YwrdSrY59hR-u2etyNCRGAPcoDH5xYJxrG2p5FH_Dh_"
    //                      "MQ0ugDnJY2_b_-w9NS2Y2atIkzXZDjtcSpjImKpL0eIFF69ptiF8vd4q2j-"
    //                      "ougipFBGP9U5bSVzeZ7FyGkJ5Qa2DYc0osYi1QFs3YZKzkKfcblx14u-yZYhUkZHlb_jbfulnUHxDdO_r8Q\""
    //                      ",\"d\":\"P9N6tNRIXXGG8lnUyb43xt8ja7GVIv6QKuBXeN6SXWqYCp8OlKdei1gQC2To5bRtt36ZuV3yvI-ZRz-"
    //                      "Ffr4Q7at29y0mmBl0BsaoOcwxv5Dp1CJoYfJ8uBao6jyTelfsjcQKzs18xXrKRxIT0Rv6rmwe3iXmjeycCkKiqudKkv8m9RtbvdWH8AFd2ZsC"
    //                      "LNblVRrOZ9ZPQQCMVJLf65pF_cBfux-Zz_CJCfq93gFcN3h1tPFLX8UPBMqvqkBZzDx8PGoYgrydz-T8tcqtkDriyEL3mGYe9b2uH_"
    //                      "8JnzMMNMFheVPDdNBhyQQVOmQqPj7idv7677eSle4LJZANUYZdwQ\""
    //                      ",\"p\":\"8Yhaq4UMiFptSuUMcLUqOJdZ9Jr0z2KG_ZrPaaHIX8gfbtp5DGjhXEE--SwoX9ukEzR6vCewSFcEl20wnT0uTwrVs-Bf2J1L-"
    //                      "5tKKeiiwLQxXtk1cG5-PI-ECkqX0AP2K2Xa0wpIjldBE5SBR0S7whANpKxhVFMtNgKog4xNvxU\""
    //                      ",\"q\":\"5hkENNaWQSJ5qWXVJYh0LAHddr1NXwkKIfKNjK8vCYfOHXDgKxW4UbAIu7wIU9iZcVjTdN2UcaJMe5fBQR9ZEP8bcuY9ZpeUCkv-"
    //                      "g9IGw69HUXE7ERBz1es_lZOuJzENwL85Al7jOtVJ2y26g4r30q4jqaL7CcgUZjBKAytjUG0\""
    //                      ",\"dp\":\"pAn1epQsRNcVb05Muqdv-2tfnu824TqLb-YahCVqjxK9tm4O1EzO8fcmK9i_uwrTTm_QA8X4xcjDx4xS_"
    //                      "he1Qd2b8kSrE9UQ69s17WygTLyU41QmJSwF9F-MT-kFXjOylxrgGYDccj_0ZLXxb1PRKSX5_iNNHxY2mH4JsP4zN1k\""
    //                      ",\"dq\":\"gTTxAL6y9vZl_PKa4w2htoiBlMiuJryLvQ5X3_ULY72nxy54Ipl6vBwue0UWJAcP-u8XJpu6XKj3a7uGoIv61ql5_"
    //                      "2Y8elyJm9Kao-kPNVk6oggEVAu6EBiext57v7Qy9dYrLCKeVI4qf_JIts8VZG-2xO4pK4_3rH5XQTpe9W0\""
    //                      ",\"qi\":\"xTJ_ON_6kc9g3ZbunSSt_oqJBguxH2x8HVl2KQXafW-F0_DOv09P1e0fbSdOLhR-V9lLjq8DxOcvCMxkpQr2G8lTaBRVTF_-"
    //                      "szu9adi9bgb_-egvc_NAvRkuGE9fUmB2_nAyU-j4VUh1MMSP5qqQhMYvFdAF5y36MpI-pV1SLFQ\""
    //                      "}",
    //                      json);
    //     free(json);

    //     cjose_jwk_release(jwk);
    // }
    // END_TEST

    // START_TEST(test_cjose_jwk_import_json_valid)
    // {
    //     cjose_err err;
    //     static const char *JWK[] = {
    //         // EC P-256
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"4E34BAFD-E5D9-479C-964D-009C419C38DB\" }",

    //         // EC P-256, attributes rearranged
    //         "{ \"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"05A9BE36-CBBD-43F4-ACC2-8C7823B2DE23\", "
    //         "\"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\"}",

    //         // EC P-256, no 'kid'
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\"}",

    //         // EC P-256, empty 'kid'
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"\" }",

    //         // EC P-256, empty 'kid'
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": null }",

    //         // EC P-256 with private key 'd'
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"ccXrxIe0aS32y9kBkZFfAh6f7UvdcowtGH5uxCIo7eY\", "
    //         "\"y\": \"GGQACnDgoiQvdQTsv1KxNUzOjZgnNoO4wQe_F75-bb0\", "
    //         "\"kid\": \"F2BF329A-151B-4066-AB92-1CCA0C0F9DB5\", "
    //         "\"d\": \"hWdoUQvCWta1UQhC0nkTG0fHLFjWpDLv5wucVyq4-HY\" }",

    //         // EC P-384
    //         "{ \"kty\": \"EC\", \"crv\": \"P-384\", "
    //         "\"x\": \"pO1SWmH7uOJfrtU1ibqVVK7VHffbpZtGfPYMPP_5KLQO9Dtsy41UEkMlL3BWHJDH\", "
    //         "\"y\": \"RdBNoaV42bRE55V8PJR3Toeo8omQAIHPboOa7LlbQSGPYp6H6zW0tKroPquJYr3w\", "
    //         "\"kid\": \"55680752-989A-4C5C-BC6E-48602489865C\" }",

    //         // EC P-521
    //         "{ \"kty\": \"EC\", \"crv\": \"P-521\", "
    //         "\"x\": \"AC8xogZa6uKAPU8086yAlG_inL3BaRyTB0pQUIJMENsPV_4S32DxIEEellMzQ_ts1Egp6OyS3ewjCUKHv5CTF7IV\", "
    //         "\"y\": \"AIR1I2rUew5WyetOHYC-arEDDk2R30Yto6TTot92l4aY0DL8pSYxPVwv9beFUJEl95o_1Vv5y1453nFZW1Ca0uUj\", "
    //         "\"kid\": \"A3EAB438-EBF8-4FEC-B605-A67C3A0D2313\" }",

    //         // RSA 2048 public params only
    //         "{ \"kty\": \"RSA\", "
    //         "\"e\": \"AQAB\", "
    //         "\"n\": "
    //         "\"zSNO12-ydrm-bheszVm2ZvycKrSV2CN0xqQHPxB4yT8MFlWfopMA2Imt4EkILfPfZPeUYV6lElCjoY_4GBtQOy_"
    //         "e4RvDSMC0pqt5X4e6mjQvLsaAClkBmhhCYd-Vn9XIC3rSeAmBpSJDuwq_RTweXSG0hb_bn5FHf1Bl_"
    //         "ekEBUsm0Xq4p6N5DjC0ImNP74G0qxBVJzu07qsCJzYpifYYoEYkwIY7S4jqyHv55wiuMt89VTl37y8VFR3ll6RPiPFa4Raiminw5wKNJEmrGEukabibspiC0Xv"
    //         "WEMXj_zk0YnVTGAGdZeDPwnjYY6JUOJ9KgcYkiQYb9SXetsjSbyheZw\", "
    //         "\"kid\": \"05F24DC3-59F4-4AC5-9849-F2F5EA8A6F3E\" }",

    //         // RSA 2048 public and private params with CRT params
    //         "{ \"kty\": \"RSA\", "
    //         "\"e\": \"AQAB\", "
    //         "\"n\": "
    //         "\"zSNO12-ydrm-bheszVm2ZvycKrSV2CN0xqQHPxB4yT8MFlWfopMA2Imt4EkILfPfZPeUYV6lElCjoY_4GBtQOy_"
    //         "e4RvDSMC0pqt5X4e6mjQvLsaAClkBmhhCYd-Vn9XIC3rSeAmBpSJDuwq_RTweXSG0hb_bn5FHf1Bl_"
    //         "ekEBUsm0Xq4p6N5DjC0ImNP74G0qxBVJzu07qsCJzYpifYYoEYkwIY7S4jqyHv55wiuMt89VTl37y8VFR3ll6RPiPFa4Raiminw5wKNJEmrGEukabibspiC0Xv"
    //         "WEMXj_zk0YnVTGAGdZeDPwnjYY6JUOJ9KgcYkiQYb9SXetsjSbyheZw\", "
    //         "\"kid\": \"F7D90C71-6671-4064-A0AA-379AD1862D19\", "
    //         "\"d\": "
    //         "\"bixuZapp0PYFXp98gXWTT1CQlycR61lvmFf0RFyWYo9n8H7gE7KcG7AmIHVY3UVDT7jgikMIqQOCPn1SI7BXsNIPBBujEGnfHDywHSyKfdNVG-"
    //         "wkTGptP9OTo3kvpP5uSCwY6btBU-1JLyWggJC_RgmaKNNYIyUlny0Q-gOx0x0I-6ipWyLQVdKZBkw6erSODM244sPU9qEmyzVW7Nbmo5PKC1U4w-"
    //         "Dt4nBe19TIUHG-ggN_UDRauljbegIIcnEWWeXdJZDdPUHgmIRa2ODN0mfSKl1CB4LJ2eyKlmddGLFiHys44OVwA8LVzrodUixIQP6wQ02AUwlaYU_"
    //         "BWLEVoQ\", "
    //         "\"p\": "
    //         "\"9GRrzfmxrL_WgSKXexO6uc2hWh-lV9bPfBU735uHUFBS2_OOUjtQSYSqm-HK2ND1EIlPZBEEu9ccdshaEVYx79eP5fRnpF8EKEo1W-eeinmn7pQsfR-"
    //         "6kFzkKmdBVhUyfpZvWtNuIwNZLu-HEvF2eIVVauQtJCPnjeYFbDyveqk\", "
    //         "\"q\": "
    //         "\"1uGXUwk052ayLvpYx3-L272X5srOyme3PCS2W1AZBXnXK06jqFp_KqUDpPnL3MNYZlfoYW5HIQBNpGCcZaTwfdLnSZroSbkQk-"
    //         "9w3zfsOiJplDbZb77mG6xbw7m7AqcNQA6szoGlCrxluE74apKg4dUOg5rEx8-LOeK90rz-So8\", "
    //         "\"dp\": "
    //         "\"D36KYy2weQ5UkC1cQz5V-U-zKh6VggMpdml2OVAH_SyKhE1luYrvJSoXEvj2vlZJIzpBYUu-7BXQRSugoja_xb_57I9ZPs-"
    //         "TWOaTiXce0xKxdevJAknPrzVkddfECawgXmw1NSHweqHMtrAS9T1_0FZLuxIqVn88P__UWi9ixLk\", "
    //         "\"dq\": "
    //         "\"J733d-MXBslGoUuqCdO8MTsCkivmTScbi6Mamw7YYdvkAN19hVCffmqgnu2YV89FVUBi-UolG6Rrt8AqjN4RoKPWJRXiamgw-"
    //         "btqO86jASmGL2RpmLJM6sdY_X0nalktKTDNoy_1L2QiyBDK_yL5YGtAUPTZ-j6XeHBIPWa4_V8\", "
    //         "\"qi\": "
    //         "\"DJcZFEvdjynkwHEOrTSXLezReXT8bj73eo7Yoadtbln27nD_8q5yAobHVOO9ZzrwSoDCeepW_fVotgMuqxdGIBXZB_"
    //         "DboRvjWW0QuBZ7Lg2SwwQqi9Ve8w31Z36gvOr1fR-Bd12B5STepC4SYBn1u5uMG5AIgfgzoa-FXEEBgB8\" }",

    //         // RSA 4096 public and private params, without CRT params
    //         "{ \"kty\": \"RSA\", "
    //         "\"e\": \"AQAB\", "
    //         "\"n\": "
    //         "\"vlbWUA9HUDHB5MDotmXObtE_Y4zKtGNtmPHUy_xkp_fSr0BxNdSOUzvzoAhK3sxTqpzVujKC245RHJ84Hhbl-KDj-"
    //         "n7Ee8EV3nKpnsqiBgHyc3rBpxpIi0J8kYmpiPGXu7k4xnCWCeiu_gfFGzvPdLHzlV7WOfYIHvymtbS7WOyTQLBgDjUKfHdJzH75vogy35h_mEcS-pde-"
    //         "EIi7u4OqD3bNW7iLbf2JVLtSNUYNCMMu23GsOEcBAsdf4QMq5gU-AEFK4Aib8mSPi_tXoohembr-"
    //         "JkzByRAkHbdzoGXssj0EHESt4reDfY8enVo5ACKmzbqlIJ1jmPVV6EKPBPzcQiN9dUA43xei2gmRAswdUKnexVPAPFPfKMpLqr24h1e7jHFBQL23-QqZX-"
    //         "gASbEDiYa9GusSY4kRn80hZRqCq4sgIRVEiu3ofjVdo4YzzESAkmfgFayUThhakqP82_wr9_Uc2vw3ZtlaTC_"
    //         "0LY70ne9yTy3SD3yEOa649nOTBfSh156YGtxvaHHidFojVHpPHBmjGAlak--mONHXHn00l_CVivUcuBqIGcZXRfiO6YwVDH_4ZTVzAkDov1C-"
    //         "4SNJK0XKeIwvGSspaSQrTmH_pT66L7tIhdZLTMVMh2ahnInVZP2G_-motugLq-x962JLQuLLeuh_r_Rk4VHZYhOgoc\", "
    //         "\"kid\": \"2940921e-3646-451c-8510-971552754e74\", "
    //         "\"d\": "
    //         "\"oMyvxXcC4icHDQBEGUOswEYabTmWTgrpnho_kg0p5BUjclbYzYdCreKqEPqwdcTcsfhJP0JI9r8mmy2PtSvXINKbhxXtXDdlCEaKMdIySyz97L06OLelrbB_"
    //         "mFxaU4z2iOsToeGff8OJgqaByF4hBw8HH5u9E75cYgFDvaJv29IRHMdkftwkfb4xJIfo6SQbBnbI5Ja22-"
    //         "lhnA4TgRKwY0XOmTeR8NnHIwUJ3UvZZMJvkTBOeUPT7T6OrxmZsqWKoXILMhLQBOyfldXbjNDZM5UbqSuTxmbD_"
    //         "MfO3xTwWWQXfIRqMZEpw1XRBguGj4g9kJ82Ujxcn-yLYbp08QhR0ijBY13HzFVMZ2jxqckrvp3uYgfJjcCN9QXZ6qlv40s_"
    //         "vJRRgv4wxdDc035eoymqGQby0UnDTmhijRV_-eAJQvdl3bv-R5dH9IzhxoJA8xAqZfVtlehPuGaXDAsa4pIWSg9hZkMdDEjW15g3zTQi3ba8_"
    //         "MfmnKuDe4GXYBjrH69z7epxbhnTmKQ-fZIxboA9sYuJHj6pEGT8D485QmrnmLjvqmQUzcxnpU6E3awksTp_"
    //         "HeBYLLbmrv4DPGNyVri2yPPTTRrNBtbWkuvEGVnMhvL2ed9uqLSnH8zOfgWqstqjxadxKADidYEZzmiYfEjYTDZGd9VDIUdKNGHWGFRB7UE\", "
    //         "\"p\": "
    //         "\"6VtjaNMD_VKTbs7sUQk-qjPTn6mCI8_3loqrOOy32b1G0HfIzCijuV-"
    //         "L7g7RxmMszEEfEILxRpJnOZRehN8etsIEuCdhU6VAdhBsBH5hIA9ZtX8GIs0sPrhc4kzPiwJ6JcLytUc6HCTICf2FIU7SI8I17-"
    //         "p53d35VItYiC1sGLZ2yN61VoKYNTncUSwboP2zXmGv4FPB5wQogryA_bEn-"
    //         "1U12FFSRd75Ku9GAEVxbTk3OaQqYgqfo9LnAWvunTDu31D4uyC6rze77NCo8UguqCpFjvF0ihOryQI6C3d0e8kxcM1vJbMvZNfrDN65btzqWi4m-"
    //         "CnqGYkl6BXQtS5UVw\", "
    //         "\"q\": "
    //         "\"0M7h_gtxoVoNPLRjYA5zBUD8qmyWiAzjloFOrDRLJwiD4OPHgImUx2WPTiSCjouvGqwfJh1jEEryJV_d0e4iVGyKYbFeXfzadwYXXR2jK4QwO1V_"
    //         "JDHI7HUYwNl6qzZqATi2zNKunPgIwY55gWBKjP2aUvPUBAcTeCsUPvrN_SajPVfc2wSlA2TvEnjmweNvgSTNqtBlMpmpwvEb9WXfv4pl3BfRvoTk3VR4icyvl-"
    //         "PLFedp2y0Fs0aQ4LRQ2ZMKWyGQEam_uAoa1tXrRJ_yQRvtWm1K8GpRZGKwN3TvtAg649PxQ7tJ8cvh3BwQROJyQBZDrlR04wqvDK4SNezlUQ\" }",

    //         // oct 256
    //         "{ \"kty\": \"oct\", "
    //         "\"kid\": \"b779034d-2e9b-44a8-8334-55d6b7a0ef59\", "
    //         "\"k\": \"wsL6R8uXG4RnsckLggj9Lg-kE5MMSJ8luzIBA8j7WXE\" }",

    //         // oct 512
    //         "{ \"kty\": \"oct\", "
    //         "\"kid\": \"0c17c6d8-307d-4e4a-a860-a14788ee1110\", "
    //         "\"k\": \"qKcFDl6VSS7CgMpdF9we9JFEenMQniO-8lQ0DvFI1jzfTb93H2Gc0YzO4iNEZ7VPN6p0l-PyA4vlOrn0hPS5qA\" }",

    //         // oct 1024
    //         "{ \"kty\": \"oct\", "
    //         "\"kid\": \"3dfc3c58-74fd-4b8a-88d6-5321b30b554c\", "
    //         "\"k\": "
    //         "\"dCDW6NH5DkKtH6dTsRm_yJchQtrVxD_ZjDob3UquMBoAwdtVIjKvMztbP4XQE7Gf_QjzEa58_UrI80QzBxG_UpFxzpjTOBfWz8Do1BHZak_"
    //         "W1KBWDyfnEqc8RtxZmc4yE1dko5B8GUyfplMrEFa2tO899hnGe7pqRVdiwFF5QkY\" }",

    //         NULL,
    //     };

    //     cjose_jwk_t *jwk = NULL;
    //     for (int i = 0; JWK[i] != NULL; ++i)
    //     {
    //         // get json representation of "before"
    //         json_t *left_json = json_loads(JWK[i], 0, NULL);
    //         ck_assert(NULL != left_json);

    //         // do import
    //         jwk = cjose_jwk_import_json((cjose_header_t *)left_json, &err);
    //         ck_assert_msg(NULL != jwk,
    //                       "expected a cjose_jwk_t, but got NULL (%s) : "
    //                       "%s, file: %s, function: %s, line: %ld",
    //                       JWK[i], err.message, err.file, err.function, err.line);

    //         // get json representation of "after"
    //         char *jwk_str = cjose_jwk_to_json(jwk, true, &err);
    //         json_t *right_json = json_loads(jwk_str, 0, NULL);
    //         ck_assert(NULL != right_json);

    //         // check that cooresponding attributes match up
    //         const char *attrs[] = { "kty", "crv", "x", "y", "d", "kid", "e", "n", "p", "q", "dp", "dq", "qi", NULL };
    //         if (!_match_string_attrs(left_json, right_json, attrs))
    //         {
    //             ck_assert_str_eq(JWK[i], jwk_str);
    //         }

    //         free(jwk_str);
    //         json_decref(left_json);
    //         json_decref(right_json);
    //         cjose_jwk_release(jwk);
    //     }
    // }
    // END_TEST

    // START_TEST(test_cjose_jwk_import_json_invalid)
    // {
    //     cjose_err err;
    //     static const char *JWK[] = {
    //         // EC P-256 invalid 'kty'
    //         "{ \"kty\": \"EMC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"0406E98B-CE84-4C78-965A-84C53BA73A1E\" }",

    //         // EC P-256 missing 'kty'
    //         "{ \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"EE05B07C-22ED-4059-A50B-4AD0A48E28D4\" }",

    //         // EC P-256 invalid 'crv'
    //         "{ \"kty\": \"EC\", \"crv\": \"P-257\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"BB70E4BD-9547-4566-9195-1C45777D368B\" }",

    //         // EC P-256 missing 'crv'
    //         "{ \"kty\": \"EC\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"928D103F-8DF2-41D5-A42B-7A72508FC70E\" }",

    //         // EC P-256 invalid 'x' (truncated)
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"685A7314-EBE1-4E1A-A81D-8AB4A1B56452\" }",

    //         // EC P-256 invalid 'x' (a number)
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": 42, "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"5B3F3AB3-E716-4D85-8E4A-4BAC0D7D64E8\" }",

    //         // EC P-256 missing 'x'
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"9354D170-5FA4-46B5-901D-38098716E28A\" }",

    //         // EC P-256 invalid 'y' (truncated)
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRg\", "
    //         "\"kid\": \"262DDF7E-1AB5-43D1-91EA-13B99779DF16\" }",

    //         // EC P-256 invalid 'y' (an object)
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": {}, "
    //         "\"kid\": \"1BEFD34C-A86E-4512-B206-7A2B94D82D27\" }",

    //         // EC P-256 missing 'y'
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"kid\": \"CBA61EED-3C61-45B3-9A35-9DE03F247720\" }",

    //         // EC P-384 invalid 'x' (truncated)
    //         "{ \"kty\": \"EC\", \"crv\": \"P-384\", "
    //         "\"x\": \"pO1SWmH7uOJfrtU1ibqVVK7VHffbpZtGfPYMPP_5KLQO9Dtsy41UEkMlL3BWHJD\", "
    //         "\"y\": \"RdBNoaV42bRE55V8PJR3Toeo8omQAIHPboOa7LlbQSGPYp6H6zW0tKroPquJYr3w\", "
    //         "\"kid\": \"FFC23684-88C8-4783-BBA3-ABF29971943B\" }",

    //         // EC P-521 invalid 'x' (truncated)
    //         "{ \"kty\": \"EC\", \"crv\": \"P-521\", "
    //         "\"x\": \"AVq9Y0jEvSINQJzcExSIUWYjo73cJcVTz_QHXCU7p9rbmC8chFdACiGLKDKlzdgW6lhZzA5qnp8mkpS2qJO_EVxU\", "
    //         "\"y\": \"AQHcQF8s_dhS_84CKLll0vkr0xCqWLp5XXdb79coYWI7Ev9SwZ4UZZVPxgu7ZGyp_2WdtaWw68uYeUVU4WiyKfP\", "
    //         "\"kid\": \"3930AC1C-C02F-46DA-9730-87785F405FE8\" }",

    //         // RSA 2048 missing 'n' (needed for both public and private)
    //         "{ \"kty\": \"RSA\", "
    //         "\"e\": \"AQAB\", "
    //         "\"kid\": \"05F24DC3-59F4-4AC5-9849-F2F5EA8A6F3E\" }",

    //         // empty object
    //         "{}",

    //         // empty string
    //         "\"\"",

    //         // a number
    //         "5",

    //         // null JWK
    //         "null",

    //         NULL,
    //     };

    //     cjose_jwk_t *jwk = NULL;
    //     for (int i = 0; JWK[i] != NULL; ++i)
    //     {
    //         json_t *left_json = json_loads(JWK[i], 0, NULL);
    //         jwk = cjose_jwk_import_json((cjose_header_t *)left_json, &err);
    //         ck_assert_msg(NULL == jwk, "expected NULL, received a cjose_jwk_t");
    //         ck_assert_int_eq(err.code, CJOSE_ERR_INVALID_ARG);
    //         cjose_jwk_release(jwk);
    //     }
    // }
    // END_TEST

    // START_TEST(test_cjose_jwk_import_valid)
    // {
    //     cjose_err err;
    //     static const char *JWK[] = {
    //         // EC P-256
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"4E34BAFD-E5D9-479C-964D-009C419C38DB\" }",

    //         // EC P-256, attributes rearranged
    //         "{ \"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"05A9BE36-CBBD-43F4-ACC2-8C7823B2DE23\", "
    //         "\"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\"}",

    //         // EC P-256, no 'kid'
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\"}",

    //         // EC P-256, empty 'kid'
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"\" }",

    //         // EC P-256, empty 'kid'
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": null }",

    //         // EC P-256 with private key 'd'
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"ccXrxIe0aS32y9kBkZFfAh6f7UvdcowtGH5uxCIo7eY\", "
    //         "\"y\": \"GGQACnDgoiQvdQTsv1KxNUzOjZgnNoO4wQe_F75-bb0\", "
    //         "\"kid\": \"F2BF329A-151B-4066-AB92-1CCA0C0F9DB5\", "
    //         "\"d\": \"hWdoUQvCWta1UQhC0nkTG0fHLFjWpDLv5wucVyq4-HY\" }",

    //         // EC P-384
    //         "{ \"kty\": \"EC\", \"crv\": \"P-384\", "
    //         "\"x\": \"pO1SWmH7uOJfrtU1ibqVVK7VHffbpZtGfPYMPP_5KLQO9Dtsy41UEkMlL3BWHJDH\", "
    //         "\"y\": \"RdBNoaV42bRE55V8PJR3Toeo8omQAIHPboOa7LlbQSGPYp6H6zW0tKroPquJYr3w\", "
    //         "\"kid\": \"55680752-989A-4C5C-BC6E-48602489865C\" }",

    //         // EC P-521
    //         "{ \"kty\": \"EC\", \"crv\": \"P-521\", "
    //         "\"x\": \"AC8xogZa6uKAPU8086yAlG_inL3BaRyTB0pQUIJMENsPV_4S32DxIEEellMzQ_ts1Egp6OyS3ewjCUKHv5CTF7IV\", "
    //         "\"y\": \"AIR1I2rUew5WyetOHYC-arEDDk2R30Yto6TTot92l4aY0DL8pSYxPVwv9beFUJEl95o_1Vv5y1453nFZW1Ca0uUj\", "
    //         "\"kid\": \"A3EAB438-EBF8-4FEC-B605-A67C3A0D2313\" }",

    //         // RSA 2048 public params only
    //         "{ \"kty\": \"RSA\", "
    //         "\"e\": \"AQAB\", "
    //         "\"n\": "
    //         "\"zSNO12-ydrm-bheszVm2ZvycKrSV2CN0xqQHPxB4yT8MFlWfopMA2Imt4EkILfPfZPeUYV6lElCjoY_4GBtQOy_"
    //         "e4RvDSMC0pqt5X4e6mjQvLsaAClkBmhhCYd-Vn9XIC3rSeAmBpSJDuwq_RTweXSG0hb_bn5FHf1Bl_"
    //         "ekEBUsm0Xq4p6N5DjC0ImNP74G0qxBVJzu07qsCJzYpifYYoEYkwIY7S4jqyHv55wiuMt89VTl37y8VFR3ll6RPiPFa4Raiminw5wKNJEmrGEukabibspiC0Xv"
    //         "WEMXj_zk0YnVTGAGdZeDPwnjYY6JUOJ9KgcYkiQYb9SXetsjSbyheZw\", "
    //         "\"kid\": \"05F24DC3-59F4-4AC5-9849-F2F5EA8A6F3E\" }",

    //         // RSA 2048 public and private params with CRT params
    //         "{ \"kty\": \"RSA\", "
    //         "\"e\": \"AQAB\", "
    //         "\"n\": "
    //         "\"zSNO12-ydrm-bheszVm2ZvycKrSV2CN0xqQHPxB4yT8MFlWfopMA2Imt4EkILfPfZPeUYV6lElCjoY_4GBtQOy_"
    //         "e4RvDSMC0pqt5X4e6mjQvLsaAClkBmhhCYd-Vn9XIC3rSeAmBpSJDuwq_RTweXSG0hb_bn5FHf1Bl_"
    //         "ekEBUsm0Xq4p6N5DjC0ImNP74G0qxBVJzu07qsCJzYpifYYoEYkwIY7S4jqyHv55wiuMt89VTl37y8VFR3ll6RPiPFa4Raiminw5wKNJEmrGEukabibspiC0Xv"
    //         "WEMXj_zk0YnVTGAGdZeDPwnjYY6JUOJ9KgcYkiQYb9SXetsjSbyheZw\", "
    //         "\"kid\": \"F7D90C71-6671-4064-A0AA-379AD1862D19\", "
    //         "\"d\": "
    //         "\"bixuZapp0PYFXp98gXWTT1CQlycR61lvmFf0RFyWYo9n8H7gE7KcG7AmIHVY3UVDT7jgikMIqQOCPn1SI7BXsNIPBBujEGnfHDywHSyKfdNVG-"
    //         "wkTGptP9OTo3kvpP5uSCwY6btBU-1JLyWggJC_RgmaKNNYIyUlny0Q-gOx0x0I-6ipWyLQVdKZBkw6erSODM244sPU9qEmyzVW7Nbmo5PKC1U4w-"
    //         "Dt4nBe19TIUHG-ggN_UDRauljbegIIcnEWWeXdJZDdPUHgmIRa2ODN0mfSKl1CB4LJ2eyKlmddGLFiHys44OVwA8LVzrodUixIQP6wQ02AUwlaYU_"
    //         "BWLEVoQ\", "
    //         "\"p\": "
    //         "\"9GRrzfmxrL_WgSKXexO6uc2hWh-lV9bPfBU735uHUFBS2_OOUjtQSYSqm-HK2ND1EIlPZBEEu9ccdshaEVYx79eP5fRnpF8EKEo1W-eeinmn7pQsfR-"
    //         "6kFzkKmdBVhUyfpZvWtNuIwNZLu-HEvF2eIVVauQtJCPnjeYFbDyveqk\", "
    //         "\"q\": "
    //         "\"1uGXUwk052ayLvpYx3-L272X5srOyme3PCS2W1AZBXnXK06jqFp_KqUDpPnL3MNYZlfoYW5HIQBNpGCcZaTwfdLnSZroSbkQk-"
    //         "9w3zfsOiJplDbZb77mG6xbw7m7AqcNQA6szoGlCrxluE74apKg4dUOg5rEx8-LOeK90rz-So8\", "
    //         "\"dp\": "
    //         "\"D36KYy2weQ5UkC1cQz5V-U-zKh6VggMpdml2OVAH_SyKhE1luYrvJSoXEvj2vlZJIzpBYUu-7BXQRSugoja_xb_57I9ZPs-"
    //         "TWOaTiXce0xKxdevJAknPrzVkddfECawgXmw1NSHweqHMtrAS9T1_0FZLuxIqVn88P__UWi9ixLk\", "
    //         "\"dq\": "
    //         "\"J733d-MXBslGoUuqCdO8MTsCkivmTScbi6Mamw7YYdvkAN19hVCffmqgnu2YV89FVUBi-UolG6Rrt8AqjN4RoKPWJRXiamgw-"
    //         "btqO86jASmGL2RpmLJM6sdY_X0nalktKTDNoy_1L2QiyBDK_yL5YGtAUPTZ-j6XeHBIPWa4_V8\", "
    //         "\"qi\": "
    //         "\"DJcZFEvdjynkwHEOrTSXLezReXT8bj73eo7Yoadtbln27nD_8q5yAobHVOO9ZzrwSoDCeepW_fVotgMuqxdGIBXZB_"
    //         "DboRvjWW0QuBZ7Lg2SwwQqi9Ve8w31Z36gvOr1fR-Bd12B5STepC4SYBn1u5uMG5AIgfgzoa-FXEEBgB8\" }",

    //         // RSA 4096 public and private params, without CRT params
    //         "{ \"kty\": \"RSA\", "
    //         "\"e\": \"AQAB\", "
    //         "\"n\": "
    //         "\"vlbWUA9HUDHB5MDotmXObtE_Y4zKtGNtmPHUy_xkp_fSr0BxNdSOUzvzoAhK3sxTqpzVujKC245RHJ84Hhbl-KDj-"
    //         "n7Ee8EV3nKpnsqiBgHyc3rBpxpIi0J8kYmpiPGXu7k4xnCWCeiu_gfFGzvPdLHzlV7WOfYIHvymtbS7WOyTQLBgDjUKfHdJzH75vogy35h_mEcS-pde-"
    //         "EIi7u4OqD3bNW7iLbf2JVLtSNUYNCMMu23GsOEcBAsdf4QMq5gU-AEFK4Aib8mSPi_tXoohembr-"
    //         "JkzByRAkHbdzoGXssj0EHESt4reDfY8enVo5ACKmzbqlIJ1jmPVV6EKPBPzcQiN9dUA43xei2gmRAswdUKnexVPAPFPfKMpLqr24h1e7jHFBQL23-QqZX-"
    //         "gASbEDiYa9GusSY4kRn80hZRqCq4sgIRVEiu3ofjVdo4YzzESAkmfgFayUThhakqP82_wr9_Uc2vw3ZtlaTC_"
    //         "0LY70ne9yTy3SD3yEOa649nOTBfSh156YGtxvaHHidFojVHpPHBmjGAlak--mONHXHn00l_CVivUcuBqIGcZXRfiO6YwVDH_4ZTVzAkDov1C-"
    //         "4SNJK0XKeIwvGSspaSQrTmH_pT66L7tIhdZLTMVMh2ahnInVZP2G_-motugLq-x962JLQuLLeuh_r_Rk4VHZYhOgoc\", "
    //         "\"kid\": \"2940921e-3646-451c-8510-971552754e74\", "
    //         "\"d\": "
    //         "\"oMyvxXcC4icHDQBEGUOswEYabTmWTgrpnho_kg0p5BUjclbYzYdCreKqEPqwdcTcsfhJP0JI9r8mmy2PtSvXINKbhxXtXDdlCEaKMdIySyz97L06OLelrbB_"
    //         "mFxaU4z2iOsToeGff8OJgqaByF4hBw8HH5u9E75cYgFDvaJv29IRHMdkftwkfb4xJIfo6SQbBnbI5Ja22-"
    //         "lhnA4TgRKwY0XOmTeR8NnHIwUJ3UvZZMJvkTBOeUPT7T6OrxmZsqWKoXILMhLQBOyfldXbjNDZM5UbqSuTxmbD_"
    //         "MfO3xTwWWQXfIRqMZEpw1XRBguGj4g9kJ82Ujxcn-yLYbp08QhR0ijBY13HzFVMZ2jxqckrvp3uYgfJjcCN9QXZ6qlv40s_"
    //         "vJRRgv4wxdDc035eoymqGQby0UnDTmhijRV_-eAJQvdl3bv-R5dH9IzhxoJA8xAqZfVtlehPuGaXDAsa4pIWSg9hZkMdDEjW15g3zTQi3ba8_"
    //         "MfmnKuDe4GXYBjrH69z7epxbhnTmKQ-fZIxboA9sYuJHj6pEGT8D485QmrnmLjvqmQUzcxnpU6E3awksTp_"
    //         "HeBYLLbmrv4DPGNyVri2yPPTTRrNBtbWkuvEGVnMhvL2ed9uqLSnH8zOfgWqstqjxadxKADidYEZzmiYfEjYTDZGd9VDIUdKNGHWGFRB7UE\", "
    //         "\"p\": "
    //         "\"6VtjaNMD_VKTbs7sUQk-qjPTn6mCI8_3loqrOOy32b1G0HfIzCijuV-"
    //         "L7g7RxmMszEEfEILxRpJnOZRehN8etsIEuCdhU6VAdhBsBH5hIA9ZtX8GIs0sPrhc4kzPiwJ6JcLytUc6HCTICf2FIU7SI8I17-"
    //         "p53d35VItYiC1sGLZ2yN61VoKYNTncUSwboP2zXmGv4FPB5wQogryA_bEn-"
    //         "1U12FFSRd75Ku9GAEVxbTk3OaQqYgqfo9LnAWvunTDu31D4uyC6rze77NCo8UguqCpFjvF0ihOryQI6C3d0e8kxcM1vJbMvZNfrDN65btzqWi4m-"
    //         "CnqGYkl6BXQtS5UVw\", "
    //         "\"q\": "
    //         "\"0M7h_gtxoVoNPLRjYA5zBUD8qmyWiAzjloFOrDRLJwiD4OPHgImUx2WPTiSCjouvGqwfJh1jEEryJV_d0e4iVGyKYbFeXfzadwYXXR2jK4QwO1V_"
    //         "JDHI7HUYwNl6qzZqATi2zNKunPgIwY55gWBKjP2aUvPUBAcTeCsUPvrN_SajPVfc2wSlA2TvEnjmweNvgSTNqtBlMpmpwvEb9WXfv4pl3BfRvoTk3VR4icyvl-"
    //         "PLFedp2y0Fs0aQ4LRQ2ZMKWyGQEam_uAoa1tXrRJ_yQRvtWm1K8GpRZGKwN3TvtAg649PxQ7tJ8cvh3BwQROJyQBZDrlR04wqvDK4SNezlUQ\" }",

    //         // oct 256
    //         "{ \"kty\": \"oct\", "
    //         "\"kid\": \"b779034d-2e9b-44a8-8334-55d6b7a0ef59\", "
    //         "\"k\": \"wsL6R8uXG4RnsckLggj9Lg-kE5MMSJ8luzIBA8j7WXE\" }",

    //         // oct 512
    //         "{ \"kty\": \"oct\", "
    //         "\"kid\": \"0c17c6d8-307d-4e4a-a860-a14788ee1110\", "
    //         "\"k\": \"qKcFDl6VSS7CgMpdF9we9JFEenMQniO-8lQ0DvFI1jzfTb93H2Gc0YzO4iNEZ7VPN6p0l-PyA4vlOrn0hPS5qA\" }",

    //         // oct 1024
    //         "{ \"kty\": \"oct\", "
    //         "\"kid\": \"3dfc3c58-74fd-4b8a-88d6-5321b30b554c\", "
    //         "\"k\": "
    //         "\"dCDW6NH5DkKtH6dTsRm_yJchQtrVxD_ZjDob3UquMBoAwdtVIjKvMztbP4XQE7Gf_QjzEa58_UrI80QzBxG_UpFxzpjTOBfWz8Do1BHZak_"
    //         "W1KBWDyfnEqc8RtxZmc4yE1dko5B8GUyfplMrEFa2tO899hnGe7pqRVdiwFF5QkY\" }",

    //         NULL,
    //     };

    //     cjose_jwk_t *jwk = NULL;
    //     for (int i = 0; JWK[i] != NULL; ++i)
    //     {
    //         // do import
    //         jwk = cjose_jwk_import(JWK[i], strlen(JWK[i]), &err);
    //         ck_assert_msg(NULL != jwk, "expected a cjose_jwk_t, but got NULL (%s) : "
    //                                    "%s, file: %s, function: %s, line: %ld",
    //                       JWK[i], err.message, err.file, err.function, err.line);

    //         // get json representation of "before"
    //         json_t *left_json = json_loads(JWK[i], 0, NULL);
    //         ck_assert(NULL != left_json);

    //         // get json representation of "after"
    //         char *jwk_str = cjose_jwk_to_json(jwk, true, &err);
    //         json_t *right_json = json_loads(jwk_str, 0, NULL);
    //         ck_assert(NULL != right_json);

    //         // check that cooresponding attributes match up
    //         const char *attrs[] = { "kty", "crv", "x", "y", "d", "kid", "e", "n", "p", "q", "dp", "dq", "qi", NULL };
    //         if (!_match_string_attrs(left_json, right_json, attrs))
    //         {
    //             ck_assert_str_eq(JWK[i], jwk_str);
    //         }

    //         free(jwk_str);
    //         json_decref(left_json);
    //         json_decref(right_json);
    //         cjose_jwk_release(jwk);
    //     }
    // }
    // END_TEST

    // START_TEST(test_cjose_jwk_import_invalid)
    // {
    //     cjose_err err;
    //     static const char *JWK[] = {
    //         // EC P-256 invalid 'kty'
    //         "{ \"kty\": \"EMC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"0406E98B-CE84-4C78-965A-84C53BA73A1E\" }",

    //         // EC P-256 missing 'kty'
    //         "{ \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"EE05B07C-22ED-4059-A50B-4AD0A48E28D4\" }",

    //         // EC P-256 invalid 'crv'
    //         "{ \"kty\": \"EC\", \"crv\": \"P-257\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"BB70E4BD-9547-4566-9195-1C45777D368B\" }",

    //         // EC P-256 missing 'crv'
    //         "{ \"kty\": \"EC\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"928D103F-8DF2-41D5-A42B-7A72508FC70E\" }",

    //         // EC P-256 invalid 'x' (truncated)
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"685A7314-EBE1-4E1A-A81D-8AB4A1B56452\" }",

    //         // EC P-256 invalid 'x' (a number)
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": 42, "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"5B3F3AB3-E716-4D85-8E4A-4BAC0D7D64E8\" }",

    //         // EC P-256 missing 'x'
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //         "\"kid\": \"9354D170-5FA4-46B5-901D-38098716E28A\" }",

    //         // EC P-256 invalid 'y' (truncated)
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRg\", "
    //         "\"kid\": \"262DDF7E-1AB5-43D1-91EA-13B99779DF16\" }",

    //         // EC P-256 invalid 'y' (an object)
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"y\": {}, "
    //         "\"kid\": \"1BEFD34C-A86E-4512-B206-7A2B94D82D27\" }",

    //         // EC P-256 missing 'y'
    //         "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //         "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //         "\"kid\": \"CBA61EED-3C61-45B3-9A35-9DE03F247720\" }",

    //         // EC P-384 invalid 'x' (truncated)
    //         "{ \"kty\": \"EC\", \"crv\": \"P-384\", "
    //         "\"x\": \"pO1SWmH7uOJfrtU1ibqVVK7VHffbpZtGfPYMPP_5KLQO9Dtsy41UEkMlL3BWHJD\", "
    //         "\"y\": \"RdBNoaV42bRE55V8PJR3Toeo8omQAIHPboOa7LlbQSGPYp6H6zW0tKroPquJYr3w\", "
    //         "\"kid\": \"FFC23684-88C8-4783-BBA3-ABF29971943B\" }",

    //         // EC P-521 invalid 'x' (truncated)
    //         "{ \"kty\": \"EC\", \"crv\": \"P-521\", "
    //         "\"x\": \"AVq9Y0jEvSINQJzcExSIUWYjo73cJcVTz_QHXCU7p9rbmC8chFdACiGLKDKlzdgW6lhZzA5qnp8mkpS2qJO_EVxU\", "
    //         "\"y\": \"AQHcQF8s_dhS_84CKLll0vkr0xCqWLp5XXdb79coYWI7Ev9SwZ4UZZVPxgu7ZGyp_2WdtaWw68uYeUVU4WiyKfP\", "
    //         "\"kid\": \"3930AC1C-C02F-46DA-9730-87785F405FE8\" }",

    //         // RSA 2048 missing 'n' (needed for both public and private)
    //         "{ \"kty\": \"RSA\", "
    //         "\"e\": \"AQAB\", "
    //         "\"kid\": \"05F24DC3-59F4-4AC5-9849-F2F5EA8A6F3E\" }",

    //         // empty object
    //         "{}",

    //         // empty string
    //         "\"\"",

    //         // null JWK
    //         "null",

    //         // a number
    //         "5",

    //         // nothing
    //         "",

    //         // junk
    //         "!@#$%^&*()",

    //         NULL,
    //     };

    //     cjose_jwk_t *jwk = NULL;
    //     for (int i = 0; JWK[i] != NULL; ++i)
    //     {
    //         jwk = cjose_jwk_import(JWK[i], strlen(JWK[i]), &err);
    //         ck_assert_msg(NULL == jwk, "expected NULL, received a cjose_jwk_t");
    //         ck_assert_int_eq(err.code, CJOSE_ERR_INVALID_ARG);
    //         cjose_jwk_release(jwk);
    //     }
    // }
    // END_TEST

    // START_TEST(test_cjose_jwk_import_underflow_length)
    // {
    //     cjose_err err;
    //     static const char *JWK = "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //                              "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //                              "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //                              "\"kid\": \"CF21823B-D7C3-4C7F-BBE9-F11745E6BD21\" }";

    //     cjose_jwk_t *jwk = NULL;

    //     // test zero json doc length
    //     jwk = cjose_jwk_import(JWK, 0, &err);
    //     ck_assert_msg(NULL == jwk, "expected NULL, received a cjose_jwk_t");
    //     cjose_jwk_release(jwk);

    //     // test truncated length
    //     jwk = cjose_jwk_import(JWK, 10, &err);
    //     ck_assert_msg(NULL == jwk, "expected NULL, received a cjose_jwk_t");
    //     cjose_jwk_release(jwk);
    // }
    // END_TEST

    // START_TEST(test_cjose_jwk_import_no_zero_termination)
    // {
    //     cjose_err err;
    //     static const char *JWK = "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //                              "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //                              "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //                              "\"kid\": \"7CD876ED-6404-443A-8BBD-D4C1C99B6F71\" }, "
    //                              "{ \"kty\": \"EC\", \"crv\": \"P-384\", "
    //                              "\"x\": \"pO1SWmH7uOJfrtU1ibqVVK7VHffbpZtGfPYMPP_5KLQO9Dtsy41UEkMlL3BWHJD\", "
    //                              "\"y\": \"RdBNoaV42bRE55V8PJR3Toeo8omQAIHPboOa7LlbQSGPYp6H6zW0tKroPquJYr3w\", "
    //                              "\"kid\": \"7CD876ED-6404-443A-8BBD-D4C1C99B6F71\" }";

    //     cjose_jwk_t *jwk = NULL;

    //     // do import providing length of just the first key (which is length 182)
    //     jwk = cjose_jwk_import(JWK, 182, &err);
    //     ck_assert_msg(NULL != jwk, "expected a cjose_jwk_t, but got NULL");

    //     // get json representation of "before"
    //     json_t *left_json = json_loads(JWK, JSON_DISABLE_EOF_CHECK, NULL);
    //     ck_assert(NULL != left_json);

    //     // get json representation of "after"
    //     char *jwk_str = cjose_jwk_to_json(jwk, true, &err);
    //     json_t *right_json = json_loads(jwk_str, 0, NULL);
    //     ck_assert(NULL != right_json);

    //     // check that cooresponding attributes match up
    //     const char *attrs[] = { "kty", "crv", "x", "y", "d", "kid", NULL };
    //     if (!_match_string_attrs(left_json, right_json, attrs))
    //     {
    //         ck_assert_str_eq(JWK, jwk_str);
    //     }

    //     free(jwk_str);
    //     json_decref(left_json);
    //     json_decref(right_json);
    //     cjose_jwk_release(jwk);
    // }
    // END_TEST

    // START_TEST(test_cjose_jwk_import_with_base64url_padding)
    // {
    //     cjose_err err;
    //     static const char *JWK_IN = "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //                                 "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M=\", "
    //                                 "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ=\", "
    //                                 "\"kid\": \"BEB14BFF-1D35-4AC0-9D0A-3FD44D1C834D\" }";

    //     static const char *JWK_OUT = "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //                                  "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
    //                                  "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
    //                                  "\"kid\": \"BEB14BFF-1D35-4AC0-9D0A-3FD44D1C834D\" }";

    //     cjose_jwk_t *jwk = NULL;

    //     // do import
    //     jwk = cjose_jwk_import(JWK_IN, strlen(JWK_IN), &err);
    //     ck_assert_msg(NULL != jwk, "expected a cjose_jwk_t, but got NULL");

    //     // get json representation of "expected" (i.e. no padding)
    //     json_t *left_json = json_loads(JWK_OUT, 0, NULL);
    //     ck_assert(NULL != left_json);

    //     // get json representation of "actual" (i.e. reserialized original)
    //     char *jwk_str = cjose_jwk_to_json(jwk, true, &err);
    //     json_t *right_json = json_loads(jwk_str, 0, NULL);
    //     ck_assert(NULL != right_json);

    //     // check that cooresponding attributes match up
    //     const char *attrs[] = { "kty", "crv", "x", "y", "d", "kid", NULL };
    //     if (!_match_string_attrs(left_json, right_json, attrs))
    //     {
    //         ck_assert_str_eq(JWK_OUT, jwk_str);
    //     }

    //     free(jwk_str);
    //     json_decref(left_json);
    //     json_decref(right_json);
    //     cjose_jwk_release(jwk);
    // }
    // END_TEST

    // START_TEST(test_cjose_jwk_EC_import_with_priv_export_with_pub)
    // {
    //     cjose_err err;
    //     static const char *JWK_IN = "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //                                 "\"kid\": \"7302734F-A854-40BC-A44F-93F6F72B0D34\", "
    //                                 "\"d\": \"hWdoUQvCWta1UQhC0nkTG0fHLFjWpDLv5wucVyq4-HY\" }";

    //     static const char *JWK_OUT = "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
    //                                  "\"x\": \"ccXrxIe0aS32y9kBkZFfAh6f7UvdcowtGH5uxCIo7eY\", "
    //                                  "\"y\": \"GGQACnDgoiQvdQTsv1KxNUzOjZgnNoO4wQe_F75-bb0\", "
    //                                  "\"kid\": \"7302734F-A854-40BC-A44F-93F6F72B0D34\", "
    //                                  "\"d\": \"hWdoUQvCWta1UQhC0nkTG0fHLFjWpDLv5wucVyq4-HY\" }";

    //     cjose_jwk_t *jwk = NULL;

    //     // do import which includes just the private key 'd'
    //     jwk = cjose_jwk_import(JWK_IN, strlen(JWK_IN), &err);
    //     ck_assert_msg(NULL != jwk, "expected a cjose_jwk_t, but got NULL");

    //     // get json representation of "expected" (i.e. includes 'x' and 'y')
    //     json_t *left_json = json_loads(JWK_OUT, 0, NULL);
    //     ck_assert(NULL != left_json);

    //     // get json representation of "actual" (i.e. reserialized original)
    //     char *jwk_str = cjose_jwk_to_json(jwk, true, &err);
    //     json_t *right_json = json_loads(jwk_str, 0, NULL);
    //     ck_assert(NULL != right_json);

    //     // check that cooresponding attributes match up
    //     const char *attrs[] = { "kty", "crv", "x", "y", "d", "kid", NULL };
    //     if (!_match_string_attrs(left_json, right_json, attrs))
    //     {
    //         ck_assert_str_eq(JWK_OUT, jwk_str);
    //     }

    //     free(jwk_str);
    //     json_decref(left_json);
    //     json_decref(right_json);
    //     cjose_jwk_release(jwk);
    // }
    // END_TEST

    // START_TEST(test_cjose_jwk_hkdf)
    // {
    //     cjose_err err;

    //     const char *ikm = "source key material";
    //     size_t ikm_len = strlen(ikm);

    //     size_t ephemeral_key_len = 32;
    //     uint8_t *ephemeral_key = (uint8_t *)malloc(ephemeral_key_len);
    //     bool ok
    //         = cjose_jwk_hkdf(EVP_sha256(), (uint8_t *)"", 0, (uint8_t *)"", 0, ikm, ikm_len, ephemeral_key, ephemeral_key_len, &err);
    //     ck_assert_msg(ok, "Failed to compute HKDF");

    //     // the following is the expected output of HKDF with the ikm given above,
    //     // SHA256, no salt, no info, and an extend length of 256 bits, as provided
    //     // by the Ruby impl. of HKDF found here: https://github.com/jtdowney/hkdf
    //     const uint8_t expected[] = { 0x0C, 0x23, 0xF4, 0x62, 0x98, 0x9B, 0x7F, 0x77, 0x3E, 0x7C, 0x2F, 0x7C, 0x6B, 0xF4, 0x6B, 0xB7,
    //                                  0xB9, 0x11, 0x65, 0xC5, 0x92, 0xD1, 0x0C, 0x48, 0xFD, 0x47, 0x94, 0x76, 0x74, 0xB4, 0x14, 0xCE };
    //     for (int i = 0; i < ephemeral_key_len; i++)
    //     {
    //         ck_assert_msg(ephemeral_key[i] == expected[i], "HKDF failed on byte: %d", i);
    //     }
    //     free(ephemeral_key);
    // }
    // END_TEST

    // START_TEST(test_cjose_jwk_get_and_set_kid)
    // {
    //     cjose_err err;

    //     const char *oldKid = "725cad72-23c6-4bf7-84c3-4583a6cf5fe9";
    //     const char *newKid = "aec1cebf-ddec-4d5f-8a61-f29e2f68dc41";

    //     static const char *JWK_BEFORE[] = { // OCT key
    //                                         "{\"kty\":\"oct\","
    //                                         "\"kid\":\"725cad72-23c6-4bf7-84c3-4583a6cf5fe9\","
    //                                         "\"k\":\"wsL6R8uXG4RnsckLggj9Lg-kE5MMSJ8luzIBA8j7WXE\"}",

    //                                         // EC key
    //                                         "{\"kty\":\"EC\","
    //                                         "\"kid\":\"725cad72-23c6-4bf7-84c3-4583a6cf5fe9\","
    //                                         "\"crv\":\"P-256\","
    //                                         "\"x\":\"ccXrxIe0aS32y9kBkZFfAh6f7UvdcowtGH5uxCIo7eY\","
    //                                         "\"y\":\"GGQACnDgoiQvdQTsv1KxNUzOjZgnNoO4wQe_F75-bb0\","
    //                                         "\"d\":\"hWdoUQvCWta1UQhC0nkTG0fHLFjWpDLv5wucVyq4-HY\"}",

    //                                         // RSA key
    //                                         "{\"kty\":\"RSA\","
    //                                         "\"kid\":\"725cad72-23c6-4bf7-84c3-4583a6cf5fe9\","
    //                                         "\"e\":\"AQAB\","
    //                                         "\"n\":\"zSNO12-ydrm-bheszVm2ZvycKrSV2CN0xqQHPxB4yT8MFlWfopMA2Im"
    //                                         "t4EkILfPfZPeUYV6lElCjoY_4GBtQOy_e4RvDSMC0pqt5X4e6mjQvLsaAClkBmh"
    //                                         "hCYd-Vn9XIC3rSeAmBpSJDuwq_RTweXSG0hb_bn5FHf1Bl_ekEBUsm0Xq4p6N5D"
    //                                         "jC0ImNP74G0qxBVJzu07qsCJzYpifYYoEYkwIY7S4jqyHv55wiuMt89VTl37y8V"
    //                                         "FR3ll6RPiPFa4Raiminw5wKNJEmrGEukabibspiC0XvWEMXj_zk0YnVTGAGdZeD"
    //                                         "PwnjYY6JUOJ9KgcYkiQYb9SXetsjSbyheZw\"}",

    //                                         NULL

    //     };

    //     static const char *JWK_AFTER[] = { // OCT key
    //                                        "{\"kty\":\"oct\","
    //                                        "\"kid\":\"aec1cebf-ddec-4d5f-8a61-f29e2f68dc41\","
    //                                        "\"k\":\"wsL6R8uXG4RnsckLggj9Lg-kE5MMSJ8luzIBA8j7WXE\"}",

    //                                        // EC key
    //                                        "{\"kty\":\"EC\","
    //                                        "\"kid\":\"aec1cebf-ddec-4d5f-8a61-f29e2f68dc41\","
    //                                        "\"crv\":\"P-256\","
    //                                        "\"x\":\"ccXrxIe0aS32y9kBkZFfAh6f7UvdcowtGH5uxCIo7eY\","
    //                                        "\"y\":\"GGQACnDgoiQvdQTsv1KxNUzOjZgnNoO4wQe_F75-bb0\","
    //                                        "\"d\":\"hWdoUQvCWta1UQhC0nkTG0fHLFjWpDLv5wucVyq4-HY\"}",

    //                                        // RSA key
    //                                        "{\"kty\":\"RSA\","
    //                                        "\"kid\":\"aec1cebf-ddec-4d5f-8a61-f29e2f68dc41\","
    //                                        "\"e\":\"AQAB\","
    //                                        "\"n\":\"zSNO12-ydrm-bheszVm2ZvycKrSV2CN0xqQHPxB4yT8MFlWfopMA2Im"
    //                                        "t4EkILfPfZPeUYV6lElCjoY_4GBtQOy_e4RvDSMC0pqt5X4e6mjQvLsaAClkBmh"
    //                                        "hCYd-Vn9XIC3rSeAmBpSJDuwq_RTweXSG0hb_bn5FHf1Bl_ekEBUsm0Xq4p6N5D"
    //                                        "jC0ImNP74G0qxBVJzu07qsCJzYpifYYoEYkwIY7S4jqyHv55wiuMt89VTl37y8V"
    //                                        "FR3ll6RPiPFa4Raiminw5wKNJEmrGEukabibspiC0XvWEMXj_zk0YnVTGAGdZeD"
    //                                        "PwnjYY6JUOJ9KgcYkiQYb9SXetsjSbyheZw\"}",

    //                                        NULL
    //     };

    //     // because stuff happens
    //     ck_assert(sizeof(JWK_BEFORE) == sizeof(JWK_AFTER));

    //     const char *kid = NULL;
    //     char *json = NULL;
    //     for (int i = 0; JWK_BEFORE[i] != NULL; ++i)
    //     {
    //         // import the before state
    //         cjose_jwk_t *jwk = cjose_jwk_import(JWK_BEFORE[i], strlen(JWK_BEFORE[i]), &err);
    //         ck_assert_msg(NULL != jwk, "expected a cjose_jwk_t, but got NULL");

    //         // check that kid was imported correctly
    //         kid = cjose_jwk_get_kid(jwk, &err);
    //         ck_assert_msg(!strcmp(kid, oldKid), "match on imported JWK kid failed: %d", i);

    //         // change the kid
    //         ck_assert(cjose_jwk_set_kid(jwk, newKid, strlen(newKid), &err));

    //         // check that the kid was changed
    //         kid = cjose_jwk_get_kid(jwk, &err);
    //         ck_assert_msg(!strcmp(kid, newKid), "match on modified JWK kid failed: %d", i);

    //         // check that the kid is exported correctly
    //         json = cjose_jwk_to_json(jwk, true, &err);
    //         ck_assert_msg(!strcmp(json, JWK_AFTER[i]), "match on modified JWK JSON failed: %d", i);

    //         // freedom!
    //         cjose_jwk_release(jwk);
    //         free(json);
    //     }
    // }
    // END_TEST

    // Suite *cjose_jwk_suite()
    // {
    //     Suite *suite = suite_create("jwk");

    //     TCase *tc_jwk = tcase_create("core");
    //     tcase_set_timeout(tc_jwk, 120.0);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_name_for_kty);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_create_RSA_spec);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_create_RSA_random);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_create_EC_P256_spec);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_create_EC_P256_random);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_create_EC_P384_spec);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_create_EC_P384_random);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_create_EC_P521_spec);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_create_EC_P521_random);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_create_oct_spec);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_create_oct_random);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_create_oct_random_inval);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_retain_release);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_get_kty);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_to_json_oct);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_to_json_ec);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_to_json_rsa);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_import_json_valid);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_import_json_invalid);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_import_valid);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_import_invalid);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_import_underflow_length);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_import_no_zero_termination);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_import_with_base64url_padding);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_EC_import_with_priv_export_with_pub);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_hkdf);
    //     tcase_add_test(tc_jwk, test_cjose_jwk_get_and_set_kid);
    //     suite_add_tcase(suite, tc_jwk);

    //     return suite;
    // }
}
