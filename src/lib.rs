use sha256::Sha256;

const BS: usize = 64;
static OPAD: [u8; BS] = [0x5c; BS];
static IPAD: [u8; BS] = [0x36; BS];

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let computed_key = compute_key(key);
    let inner_key = xor_arr(&computed_key, &IPAD);
    let inner_hash = Sha256::new().write(&inner_key).write(message).finish();
    let outer_key = xor_arr(&computed_key, &OPAD);
    Sha256::new().write(&outer_key).write(&inner_hash).finish()
}

fn xor_arr(a: &[u8; BS], b: &[u8; BS]) -> [u8; BS] {
    let mut res: [u8; BS] = *a;
    for i in 0..BS {
        res[i] ^= b[i];
    }
    res
}

fn compute_key(key: &[u8]) -> [u8; BS] {
    let mut ckey: [u8; BS] = [0; BS];
    if key.len() < BS {
        ckey[..key.len()].copy_from_slice(key);
    } else {
        ckey[..32].copy_from_slice(&sha256::sha256(key));
    }
    ckey
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_works() {
        let message = "";
        let key = "";
        let hmac = hex::encode(&hmac_sha256(key.as_bytes(), message.as_bytes()));
        let expected = "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad";
        assert_eq!(expected, hmac);
    }

    #[test]
    fn long_key_works() {
        let message = "Hello, world!";
        let key = "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad\
                    b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad";
        let hmac = hex::encode(&hmac_sha256(key.as_bytes(), message.as_bytes()));
        let expected = "70d67669a0e6e3516d37feb9af403d4b36e6aed4efad091ef50c7133b2f9df95";
        assert_eq!(expected, hmac);
    }
}
