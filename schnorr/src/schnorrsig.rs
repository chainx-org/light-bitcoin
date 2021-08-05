#![allow(non_snake_case)]

use core::ops::Neg;

use crate::{
    signature::Signature,
    taggedhash::{HashAdd, Tagged},
    xonly::XOnly,
};
use digest::Digest;
use secp256k1::{
    curve::{Affine, Field, Jacobian, Scalar, ECMULT_CONTEXT},
    util::{TAG_PUBKEY_EVEN, TAG_PUBKEY_ODD},
    Error, Message, PublicKey, SecretKey,
};

/// Construct schnorr sig challenge
/// hash(R_x|P_x|msg)
pub fn schnorrsig_challenge(rx: &XOnly, pkx: &XOnly, msg: &Message) -> Scalar {
    let mut bytes = [0u8; 32];
    let hash = sha2::Sha256::default().tagged(b"BIP0340/challenge");
    let tagged = hash.add(rx).add(pkx).add(&msg.0).finalize();

    bytes.copy_from_slice(tagged.as_slice());
    let mut scalar = Scalar::default();
    let _ = scalar.set_b32(&bytes);
    scalar
}

/// Generate nonce k and nonce point R
pub fn nonce_function_bip340(
    bip340_sk: &Scalar,
    bip340_pkx: &XOnly,
    msg: &Message,
    aux: &Message,
) -> (Scalar, Affine) {
    let aux_hash = sha2::Sha256::default().tagged(b"BIP0340/aux");
    let aux_tagged = aux_hash.add(&aux.0).finalize();
    let sec_bytes: [u8; 32] = bip340_sk.b32();
    let mut aux_bytes = [0u8; 32];
    aux_bytes.copy_from_slice(&aux_tagged);

    // bitwise xor the hashed randomness with secret
    for (i, byte) in aux_bytes.iter_mut().enumerate() {
        *byte ^= sec_bytes[i]
    }

    let nonce_hash = sha2::Sha256::default().tagged(b"BIP0340/nonce");
    let nonce_tagged = nonce_hash
        .add(&aux_bytes)
        .add(bip340_pkx)
        .add(&msg.0)
        .finalize();

    let mut nonce_bytes = [0u8; 32];
    nonce_bytes.copy_from_slice(nonce_tagged.as_slice());
    let mut scalar = Scalar::default();
    let _ = scalar.set_b32(&nonce_bytes);
    let k = SecretKey::parse(&scalar.b32()).unwrap();
    let R = PublicKey::from_secret_key(&k);
    (k.into(), R.into())
}

/// Sign a message using the secret key with aux
pub fn sign_with_aux(
    msg: Message,
    aux: Message,
    seckey: SecretKey,
    pubkey: PublicKey,
) -> Signature {
    let mut pk: Affine = pubkey.into();

    pk.x.normalize();
    pk.y.normalize();

    let pkx = XOnly::from_field(&mut pk.x).unwrap();

    let sk: Scalar = seckey.clone().into();
    let sec = if pk.y.is_odd() { sk.neg() } else { sk };

    // Get nonce k and nonce point R
    let (k, mut R) = nonce_function_bip340(&sec, &pkx, &msg, &aux);
    R.y.normalize();
    R.x.normalize();
    let k_even = if R.y.is_odd() { k.neg() } else { k };

    // Generate s = k + tagged_hash("BIP0340/challenge", R_x|P_x|msg) * d
    let rx = XOnly::from_bytes(R.x.b32()).unwrap();
    let h = schnorrsig_challenge(&rx, &pkx, &msg);
    let s = k_even + h * seckey.into();

    // Generate sig = R_x|s
    Signature { rx, s }
}

/// Sign a message with context
pub fn sign_with_context() {
    unimplemented!()
}

/// Verify a schnorr signature
pub fn verify(sig: &Signature, msg: &Message, pubkey: PublicKey) -> bool {
    let (rx, s) = sig.as_tuple();

    let mut P: Affine = pubkey.into();

    if !P.is_valid_var() {
        return false;
    }
    let mut pj = Jacobian::default();
    pj.set_ge(&P);

    let pkx = XOnly::from_field(&mut P.x).unwrap();

    let h = schnorrsig_challenge(rx, &pkx, msg);

    let mut rj = Jacobian::default();
    ECMULT_CONTEXT.ecmult(&mut rj, &pj, &h.neg(), s);

    let mut R = Affine::from_gej(&rj);

    if R.is_infinity() {
        return false;
    }
    R.y.normalize_var();

    if R.y.is_odd() {
        return false;
    }

    // S == R + h * P
    let Rx = XOnly::from_field(&mut R.x).unwrap();
    rx == &Rx
}

pub fn message_from_str(str: &str) -> Message {
    let mut m = [0u8; 32];
    m.copy_from_slice(&hex::decode(str).unwrap()[..]);
    Message::parse(&m)
}

pub fn pubkey_from_str(str: &str) -> Result<PublicKey, Error> {
    let mut p = [0u8; 32];
    p.copy_from_slice(&hex::decode(str).unwrap()[..]);
    let mut f = Field::default();
    let _ = f.set_b32(&p);
    f.normalize();
    let tag = if f.is_odd() {
        TAG_PUBKEY_EVEN
    } else {
        TAG_PUBKEY_ODD
    };
    let mut c = [0u8; 33];
    for (i, byte) in c.iter_mut().enumerate() {
        if i == 0 {
            *byte = tag;
            continue;
        }
        *byte = p[i - 1];
    }
    PublicKey::parse_compressed(&c)
}

#[cfg(test)]
mod tests {
    use crate::keypair::KeyPair;

    use super::*;

    /// BIP340 test vectors
    /// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
    const SECRET_0: &str = "0000000000000000000000000000000000000000000000000000000000000003";
    const SECRET_1: &str = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF";
    const SECRET_2: &str = "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9";
    const SECRET_3: &str = "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710";

    const PUBKEY_4: &str = "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9";
    const PUBKEY_5: &str = "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34";
    const PUBKEY_6: &str = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659";
    const PUBKEY_7: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30";

    const AUX_0: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const AUX_1: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const AUX_2: &str = "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906";
    const AUX_3: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    const MESSAGE_0: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const MESSAGE_1: &str = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89";
    const MESSAGE_2: &str = "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C";
    const MESSAGE_3: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    const MESSAGE_4: &str = "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703";
    const MESSAGE_5: &str = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89";

    const SIGNATURE_0: &str = "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0";
    const SIGNATURE_1: &str = "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A";
    const SIGNATURE_2: &str = "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7";
    const SIGNATURE_3: &str = "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3";
    const SIGNATURE_4: &str = "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4";
    const SIGNATURE_5: &str = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B";
    const SIGNATURE_6: &str = "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2";
    const SIGNATURE_7: &str = "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD";
    const SIGNATURE_8: &str = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6";
    const SIGNATURE_9: &str = "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051";
    const SIGNATURE_10: &str = "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197";
    const SIGNATURE_11: &str = "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B";
    const SIGNATURE_12: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B";
    const SIGNATURE_13: &str = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    const SIGNATURE_14: &str = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B";

    fn check_sign(secret: &str, msg: &str, aux: &str, signature: &str) -> bool {
        let m = message_from_str(msg);
        let a = message_from_str(aux);
        let keypair = KeyPair::from_secret_str(secret);
        let sig = sign_with_aux(m, a, keypair.secret().clone(), keypair.public().clone());
        hex::encode_upper(sig.to_bytes()) == signature
    }

    fn check_verify(sig: &str, msg: &str, pubkey: &str) -> bool {
        if Signature::from_str(sig).is_none() {
            return false;
        }
        let s = Signature::from_str(sig).unwrap();
        if pubkey_from_str(pubkey).is_err() {
            return false;
        }
        let p = pubkey_from_str(pubkey).unwrap();
        let m = message_from_str(msg);
        verify(&s, &m, p)
    }

    #[test]
    fn test_sign() {
        assert!(check_sign(SECRET_0, MESSAGE_0, AUX_0, SIGNATURE_0));
        assert!(check_sign(SECRET_1, MESSAGE_1, AUX_1, SIGNATURE_1));
        assert!(check_sign(SECRET_2, MESSAGE_2, AUX_2, SIGNATURE_2));
        // check fails if msg is reduced modulo p or n
        assert!(!check_sign(SECRET_3, MESSAGE_3, AUX_3, SIGNATURE_3));
    }

    #[test]
    fn test_verify() {
        assert!(check_verify(SIGNATURE_4, MESSAGE_4, PUBKEY_4));
        // public key not on the curve
        assert!(!check_verify(SIGNATURE_5, MESSAGE_5, PUBKEY_5));
        // has_even_y(R) is false
        assert!(!check_verify(SIGNATURE_6, MESSAGE_5, PUBKEY_6));
        // negated message
        assert!(!check_verify(SIGNATURE_7, MESSAGE_5, PUBKEY_6));
        // negated s value
        assert!(!check_verify(SIGNATURE_8, MESSAGE_5, PUBKEY_6));
        // sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0
        assert!(!check_verify(SIGNATURE_9, MESSAGE_5, PUBKEY_6));
        // sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1
        assert!(!check_verify(SIGNATURE_10, MESSAGE_5, PUBKEY_6));
        // sig[0:32] is not an X coordinate on the curve
        assert!(!check_verify(SIGNATURE_11, MESSAGE_5, PUBKEY_6));
        // sig[0:32] is equal to field size
        assert!(!check_verify(SIGNATURE_12, MESSAGE_5, PUBKEY_6));
        // sig[32:64] is equal to curve order
        assert!(!check_verify(SIGNATURE_13, MESSAGE_5, PUBKEY_6));
        // public key is not a valid X coordinate because it exceeds the field size
        assert!(!check_verify(SIGNATURE_14, MESSAGE_5, PUBKEY_7));
    }
}
