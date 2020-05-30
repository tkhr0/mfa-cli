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
pub fn hotp(secret: &[u8], counter: &[u8]) -> Result<String, String> {
    let hmac = match hmac_sha1::gen_hmac_sha1(secret, counter) {
        Ok(hmac) => hmac,
        Err(err) => return Err(err),
    };
    let sbits = truncate(hmac);

    Ok(bit_to_decimal_code(sbits))
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
fn bit_to_decimal_code(sbits: u32) -> String {
    let code = sbits % 1000000_u32; // TODO: dynamic digits

    format!("{:06}", code)
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

    assert_eq!(truncate(hmac_sha1), 0x4c93cf18);
}

#[test]
fn rfc_4226_truncate_1() {
    let hmac_sha1 = GenericArray::from([
        0x75_u8, 0xa4, 0x8a, 0x19, 0xd4, 0xcb, 0xe1, 0x00, 0x64, 0x4e, 0x8a, 0xc1, 0x39, 0x7e,
        0xea, 0x74, 0x7a, 0x2d, 0x33, 0xab,
    ]);

    assert_eq!(truncate(hmac_sha1), 0x41397eea);
}

#[test]
fn rfc_4226_to_code_2() {
    assert_eq!(bit_to_decimal_code(0x82fef30), "359152");
}

#[test]
fn rfc_4226_to_code_3() {
    assert_eq!(bit_to_decimal_code(0x66ef7655), "969429");
}

#[test]
fn rfc_4226_hotp_4() {
    let code = hotp(b"12345678901234567890", &[0_u8, 0, 0, 0, 0, 0, 0, 4]).unwrap();
    assert_eq!(code, "338314");
}

#[test]
fn rfc_4226_hotp_5() {
    let code = hotp(b"12345678901234567890", &[0_u8, 0, 0, 0, 0, 0, 0, 5]).unwrap();
    assert_eq!(code, "254676");
}
