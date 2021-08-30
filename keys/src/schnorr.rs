//! This is the basic implementation of the schnorr signature algorithm.
//!
//! Here are some implementation references:
//! [`bitcoin`]: https://github.com/bitcoin/bitcoin/blob/3820090bd6/src/secp256k1/src/modules/schnorrsig/main_impl.h
//! [`taproot-workshop`]: https://github.com/bitcoinops/taproot-workshop/blob/master/solutions/1.1-schnorr-signatures-solutions.ipynb
#![allow(non_snake_case)]

use core::convert::TryInto;
use core::ops::Neg;

use crate::{
    public::XOnly,
    signature::SchnorrSignature,
    tagged::{HashAdd, Tagged},
    Error, Message,
};
use digest::Digest;
use secp256k1::{
    curve::{Affine, Jacobian, Scalar, ECMULT_CONTEXT},
    PublicKey,
};

/// Verify a schnorr signature
pub fn verify_schnorr(
    sig: &SchnorrSignature,
    msg: &Message,
    xonlypubkey: XOnly,
) -> Result<bool, Error> {
    let (rx, s) = (&sig.rx, &sig.s);

    // Determine if the x coordinate is on the elliptic curve
    // Also here it will be verified that there are two y's at point x
    if rx.on_curve().is_err() {
        return Err(Error::XCoordinateNotExist);
    }

    // Detect signature overflow
    let mut s_check = Scalar::default();
    let s_choice = s_check.set_b32(&s.b32());
    if s_choice.unwrap_u8() == 1 {
        return Err(Error::SignatureOverflow);
    }

    let pubkey: PublicKey = xonlypubkey.try_into()?;
    let mut P: Affine = pubkey.into();

    let mut pj = secp256k1::curve::Jacobian::default();
    pj.set_ge(&P);

    let pkx = (&mut P.x).into();

    let h = schnorrsig_challenge(rx, &pkx, msg);

    let mut rj = Jacobian::default();
    ECMULT_CONTEXT.ecmult(&mut rj, &pj, &h.neg(), s);

    let mut R = Affine::from_gej(&rj);

    if R.is_infinity() {
        return Err(Error::InvalidNoncePoint);
    }
    R.y.normalize_var();

    if R.y.is_odd() {
        return Err(Error::InvalidNoncePoint);
    }

    // S == R + h * P
    let Rx: XOnly = (&mut R.x).into();
    if rx == &Rx {
        Ok(true)
    } else {
        Err(Error::InvalidSignature)
    }
}

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

#[cfg(test)]
mod tests {
    use core::convert::{TryFrom, TryInto};

    use super::*;

    /// BIP340 test vectors
    /// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
    const PUBKEY_4: &str = "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9";
    const PUBKEY_5: &str = "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34";
    const PUBKEY_6: &str = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659";
    const PUBKEY_7: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30";

    const MESSAGE_4: &str = "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703";
    const MESSAGE_5: &str = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89";

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

    fn check_verify(sig: &str, msg: &str, pubkey: &str) -> Result<bool, Error> {
        let s = sig.try_into()?;

        let px = XOnly::try_from(pubkey)?;
        let m = Message::from_slice(&hex::decode(msg)?[..]);

        verify_schnorr(&s, &m, px)
    }

    #[test]
    fn test_verify() {
        assert_eq!(check_verify(SIGNATURE_4, MESSAGE_4, PUBKEY_4), Ok(true));
        // public key not on the curve
        assert_eq!(
            check_verify(SIGNATURE_5, MESSAGE_5, PUBKEY_5),
            Err(Error::InvalidPublic)
        );
        // has_even_y(R) is false
        assert_eq!(
            check_verify(SIGNATURE_6, MESSAGE_5, PUBKEY_6),
            Err(Error::InvalidNoncePoint)
        );
        // negated message
        assert_eq!(
            check_verify(SIGNATURE_7, MESSAGE_5, PUBKEY_6),
            Err(Error::InvalidNoncePoint)
        );
        // negated s value
        assert_eq!(
            check_verify(SIGNATURE_8, MESSAGE_5, PUBKEY_6),
            Err(Error::InvalidSignature)
        );
        // sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0
        assert_eq!(
            check_verify(SIGNATURE_9, MESSAGE_5, PUBKEY_6),
            Err(Error::XCoordinateNotExist)
        );
        // sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1
        assert_eq!(
            check_verify(SIGNATURE_10, MESSAGE_5, PUBKEY_6),
            Err(Error::InvalidNoncePoint)
        );
        // sig[0:32] is not an X coordinate on the curve
        assert_eq!(
            check_verify(SIGNATURE_11, MESSAGE_5, PUBKEY_6),
            Err(Error::XCoordinateNotExist)
        );
        // sig[0:32] is equal to field size
        assert_eq!(
            check_verify(SIGNATURE_12, MESSAGE_5, PUBKEY_6),
            Err(Error::XCoordinateNotExist)
        );
        // sig[32:64] is equal to curve order
        assert_eq!(
            check_verify(SIGNATURE_13, MESSAGE_5, PUBKEY_6),
            Err(Error::InvalidSignature)
        );
        // public key is not a valid X coordinate because it exceeds the field size
        assert_eq!(
            check_verify(SIGNATURE_14, MESSAGE_5, PUBKEY_7),
            Err(Error::InvalidSignature)
        );
    }
}
