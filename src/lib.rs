const BS: usize = 64;
static OPAD: [u8; BS] = [0x5c; BS];
static IPAD: [u8; BS] = [0x36; BS];

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let computed_key = compute_key(key);
    let inner_key = xor_arr(&computed_key, &IPAD);
    let mut inner_message: Vec<u8> = Vec::with_capacity(inner_key.len() + message.len());
    inner_message.extend(inner_key);
    inner_message.extend(message);
    let inner_hash = sha256::sha256(&inner_message);
    let outer_key = xor_arr(&computed_key, &OPAD);
    let mut outer_message: [u8; 96] = [0; 96];
    outer_message[..BS].copy_from_slice(&outer_key);
    outer_message[BS..].copy_from_slice(&inner_hash);
    sha256::sha256(&outer_message)
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
        let key = "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5adb613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad";
        let hmac = hex::encode(&hmac_sha256(key.as_bytes(), message.as_bytes()));
        let expected = "70d67669a0e6e3516d37feb9af403d4b36e6aed4efad091ef50c7133b2f9df95";
        assert_eq!(expected, hmac);
    }
}
