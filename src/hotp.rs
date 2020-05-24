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

    let code = sbits % 1000000_u32; // TODO: dynamic digits

    Ok(format!("{:06}", code))
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

#[test]
fn truncate_test() {
    let arr = GenericArray::clone_from_slice(&vec![
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0b1111_1111,
        0xbb,
        0xbb,
        0xbb,
        0,
        0,
        0,
        0,
        0,
        0x0a,
    ]);
    let result = truncate(arr);

    assert_eq!(result, 0x7f_bb_bb_bb);
}
