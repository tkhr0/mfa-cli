use super::hmac_sha1;
use digest::generic_array::typenum::U20;
use digest::generic_array::GenericArray;

type OutputSize = U20;

/// Generating HOTP function
///
/// Step 1: Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)  // HS is a 20-byte string
///
/// Step 2: Generate a 4-byte string (Dynamic Truncation)
/// Let Sbits = DT(HS)   //  DT, defined below,
///                      //  returns a 31-bit string
///
/// Step 3: Compute an HOTP value
/// Let Snum  = StToNum(Sbits)   // Convert S to a number in 0...2^{31}-1
/// Return D = Snum mod 10^Digit //  D is a number in the range 0...10^{Digit}-1
pub fn hotp(secret: &[u8], counter: &[u8], digits: u8) -> Result<String, String> {
    let hmac = match hmac_sha1::gen_hmac_sha1(secret, counter) {
        Ok(hmac) => hmac,
        Err(err) => return Err(err),
    };
    let sbits = truncate(hmac);

    bit_to_decimal_code(sbits, digits)
}

// Dynamic Truncate
fn truncate(hmac: GenericArray<u8, OutputSize>) -> u32 {
    let hash = hmac.as_slice();
    let len = hash.len();
    let offset: usize = (hash[len - 1] & 0x0f) as usize;

    let mut result: u32 = 0;
    result |= (((hmac[offset] as u32) & 0x7f) << 24)
        | (((hmac[offset + 1] as u32) & 0xff) << 16)
        | (((hmac[offset + 2] as u32) & 0xff) << 8)
        | ((hmac[offset + 3] as u32) & 0xff);
    result
}

// HMAC-SHA-1 を指定の桁に丸め込む
fn bit_to_decimal_code(sbits: u32, digits: u8) -> Result<String, String> {
    if !(1..=31).contains(&digits) {
        return Err(format!("The digits is out of range (1~31): {}", digits));
    }

    let code = (sbits % 10_u32.pow(digits as u32)).to_string();

    Ok(zero_padding(code, digits as usize))
}

// 文字を左から 0埋めする
fn zero_padding(string: String, length: usize) -> String {
    let mut value = string;

    while value.len() < length {
        value = format!("0{}", value)
    }

    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_padding_test() {
        assert_eq!(zero_padding("1".to_string(), 5), "00001")
    }

    #[test]
    fn to_decima_too_small() {
        assert!(bit_to_decimal_code(0, 0).is_err())
    }
    #[test]
    fn to_decima_too_large() {
        assert!(bit_to_decimal_code(0, 32).is_err())
    }

    #[test]
    fn truncate_test() {
        let arr = GenericArray::from([
            0x00_u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xbb, 0xbb, 0xbb,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
        ]);
        let result = truncate(arr);

        assert_eq!(result, 0x7f_bb_bb_bb);
    }

    #[test]
    fn rfc_4226_truncate_0() {
        let hmac_sha1 = GenericArray::from([
            0xcc_u8, 0x93, 0xcf, 0x18, 0x50, 0x8d, 0x94, 0x93, 0x4c, 0x64, 0xb6, 0x5d, 0x8b, 0xa7,
            0x66, 0x7f, 0xb7, 0xcd, 0xe4, 0xb0,
        ]);

        assert_eq!(truncate(hmac_sha1), 0x4c93_cf18);
    }

    #[test]
    fn rfc_4226_truncate_1() {
        let hmac_sha1 = GenericArray::from([
            0x75_u8, 0xa4, 0x8a, 0x19, 0xd4, 0xcb, 0xe1, 0x00, 0x64, 0x4e, 0x8a, 0xc1, 0x39, 0x7e,
            0xea, 0x74, 0x7a, 0x2d, 0x33, 0xab,
        ]);

        assert_eq!(truncate(hmac_sha1), 0x4139_7eea);
    }

    #[test]
    fn rfc_4226_to_code_2() {
        assert_eq!(bit_to_decimal_code(0x82f_ef30, 6), Ok("359152".to_string()));
    }

    #[test]
    fn rfc_4226_to_code_3() {
        assert_eq!(
            bit_to_decimal_code(0x66ef_7655, 6),
            Ok("969429".to_string())
        );
    }

    #[test]
    fn rfc_4226_hotp_4() {
        let code = hotp(b"12345678901234567890", &[0_u8, 0, 0, 0, 0, 0, 0, 4], 6);
        assert_eq!(code, Ok("338314".to_string()));
    }

    #[test]
    fn rfc_4226_hotp_5() {
        let code = hotp(b"12345678901234567890", &[0_u8, 0, 0, 0, 0, 0, 0, 5], 6);
        assert_eq!(code, Ok("254676".to_string()));
    }
}
