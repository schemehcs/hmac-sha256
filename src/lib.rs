use sha256::{HASH_LEN, Sha256};

pub const HMAC_LEN: usize = HASH_LEN;
pub type Hmac = sha256::Hash;

const BS: usize = HMAC_LEN * 2;
type Block = [u8; BS];

static OPAD: Block = [0x5c; BS];
static IPAD: Block = [0x36; BS];

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Hmac {
    let computed_key = compute_key(key);
    let inner_key = xor_arr(&computed_key, &IPAD);
    let inner_hash = Sha256::new().write(&inner_key).write(message).finish();
    let outer_key = xor_arr(&computed_key, &OPAD);
    Sha256::new().write(&outer_key).write(&inner_hash).finish()
}

fn xor_arr(a: &Block, b: &Block) -> Block {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| x ^ y)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn compute_key(key: &[u8]) -> Block {
    let mut padded_key: Block = [0; BS];
    if key.len() < BS {
        padded_key[..key.len()].copy_from_slice(key);
    } else {
        padded_key[..HASH_LEN].copy_from_slice(&sha256::digest(key));
    }
    padded_key
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
