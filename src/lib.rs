use hasher_style::HasherStyle;
use sha256::{BLOCK_LEN, HASH_LEN, Sha256};

pub const HMAC_LEN: usize = HASH_LEN;
pub type Mac = [u8; HMAC_LEN];

const BL: usize = BLOCK_LEN;
type Block = [u8; BL];

static OPAD: Block = [0x5c; BL];
static IPAD: Block = [0x36; BL];

pub struct Hmac {
    hasher: Sha256,
    key: Block,
}

impl Hmac {
    pub fn new(key: &[u8]) -> Self {
        let key = Self::compute_key(key);
        let ikey = xor_arr(&key, &IPAD);
        let mut hasher = Sha256::new();
        hasher.write(&ikey);
        Hmac { hasher, key }
    }

    fn compute_key(key: &[u8]) -> Block {
        let mut padded_key: Block = [0; BL];
        if key.len() <= BL {
            padded_key[..key.len()].copy_from_slice(key);
        } else {
            padded_key[..HASH_LEN].copy_from_slice(&sha256::digest(key));
        }
        padded_key
    }
}

impl HasherStyle for Hmac {
    type Output = Mac;
    fn write(&mut self, slice: &[u8]) -> &mut Self {
        self.hasher.write(slice);
        self
    }

    fn finish(&mut self) -> Self::Output {
        let inner_hash = self.hasher.finish();
        let okey = xor_arr(&self.key, &OPAD);
        Sha256::new().write(&okey).write(&inner_hash).finish()
    }
}

#[inline]
pub fn hmac(key: &[u8], message: &[u8]) -> Mac {
    Hmac::new(key).write(message).finish()
}

fn xor_arr(a: &Block, b: &Block) -> Block {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| x ^ y)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_works() {
        let message = "";
        let key = "";
        let hmac = hex::encode(&hmac(key.as_bytes(), message.as_bytes()));
        let expected = "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad";
        assert_eq!(expected, hmac);
    }

    #[test]
    fn long_key_works() {
        let message = "Hello, world!";
        let key = "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad\
                    b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad";
        let hmac = hex::encode(&hmac(key.as_bytes(), message.as_bytes()));
        let expected = "70d67669a0e6e3516d37feb9af403d4b36e6aed4efad091ef50c7133b2f9df95";
        assert_eq!(expected, hmac);
    }
}
