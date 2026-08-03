use super::Decryptor;
use crate::util::string_decryptor::DecrypterType;

#[derive(Debug)]
pub struct Pkg2Decryptor {
    iv: u64,
    enc_type: DecrypterType,
    keys: [u8; 8],
    /// KMST1204: position-dependent key material
    hash1: u64,
    hash_version: u64,
}

impl Default for Pkg2Decryptor {
    fn default() -> Self {
        Self {
            iv: 0,
            enc_type: DecrypterType::KMST1199,
            keys: [0; 8],
            hash1: 0,
            hash_version: 0,
        }
    }
}

impl Pkg2Decryptor {
    pub fn new_with_key(key: u64, enc_type: DecrypterType) -> Self {
        let mut decryptor: Pkg2Decryptor = Self::default();

        decryptor.set_iv(key, enc_type);

        decryptor
    }
    fn calculate_keys(&mut self, key: u64) {
        self.iv = key;

        let k = gen_pkg2_keys(key);

        self.keys[0] = k[0];
        self.keys[1] = k[1];

        self.keys[2] = k[2];
        self.keys[3] = k[3];

        self.keys[4] = k[4];
        self.keys[5] = k[5];

        self.keys[6] = k[6];
        self.keys[7] = k[7];
    }
}

impl Decryptor for Pkg2Decryptor {
    fn is_pkg2(&self) -> bool {
        true
    }

    fn set_iv(&mut self, key: u64, enc_type: DecrypterType) {
        self.enc_type = enc_type;
        if enc_type != DecrypterType::KMST1204 {
            self.calculate_keys(key);
        }
    }

    fn set_key_material(&mut self, hash1: u64, hash_version: u64, enc_type: DecrypterType) {
        self.enc_type = enc_type;
        self.hash1 = hash1;
        self.hash_version = hash_version;
        if enc_type == DecrypterType::KMST1204 {
            self.apply_file_position(0);
        } else if enc_type == DecrypterType::KMST1202 {
            self.calculate_keys(get_kmst1202_key(hash1, hash_version));
        } else if enc_type == DecrypterType::KMST1199 {
            self.calculate_keys(get_kmst1199_key(hash1 as u32, hash_version as u32) as u64);
        } else {
            self.calculate_keys(hash_version);
        }
    }

    fn apply_file_position(&mut self, file_position: u64) {
        if self.enc_type != DecrypterType::KMST1204 {
            return;
        }
        self.calculate_keys(get_kmst1204_key(
            self.hash1,
            self.hash_version,
            file_position,
        ));
    }

    fn get_enc_type(&self) -> DecrypterType {
        self.enc_type
    }
    fn get_iv_hash(&self) -> u64 {
        self.iv
    }
    fn is_enough(&self, _size: usize) -> bool {
        true
    }

    fn at(&mut self, index: usize) -> &u8 {
        &self.keys[index % 8]
    }

    fn try_at(&self, index: usize) -> Option<&u8> {
        self.keys.get(index % 8)
    }

    fn decrypt_slice(&self, data: &mut [u8]) {
        for (i, item) in data.iter_mut().enumerate() {
            *item ^= self.keys[i % 8];
        }
    }

    fn decrypt_slice_with_offset(&self, data: &mut [u8], offset: u64) {
        if self.enc_type == DecrypterType::KMST1204 {
            let keys = gen_pkg2_keys(get_kmst1204_key(self.hash1, self.hash_version, offset));
            for (i, item) in data.iter_mut().enumerate() {
                *item ^= keys[i % 8];
            }
            return;
        }
        self.decrypt_slice(data);
    }

    fn ensure_key_size(&mut self, _size: usize) -> Result<(), String> {
        Ok(())
    }
}

pub fn gen_pkg2_keys(key: u64) -> [u8; 8] {
    let k = key.to_le_bytes();

    [k[0], k[1], k[1], k[2], k[2], k[3], k[3], k[4]]
}

pub fn get_kmst1199_key(hash1: u32, hash_version: u32) -> u32 {
    let base_hash = hash1 ^ hash_version ^ 0x6D4C3B2A;
    mix_kmst1199(mix_kmst1199(base_hash) ^ 0x4F4CB34A)
}

pub fn get_kmst1202_key(hash1: u64, hash_version: u64) -> u64 {
    hash1 ^ hash_version ^ 0x66B57FEE317FD3DF
}

/// KMST1204 position-dependent directory string key.
#[inline]
pub fn get_kmst1204_key(hash1: u64, hash_version: u64, file_position: u64) -> u64 {
    hash1
        ^ hash_version
        ^ 0x21810F65FEC32BDC_u64
        ^ 0x9E3779B97F4A7C15_u64.wrapping_mul(file_position)
}

#[inline(always)]
pub(crate) fn mix_kmst1199(mut key: u32) -> u32 {
    key ^= key >> 16;
    key = key.wrapping_mul(0x7FEB352D);
    key ^= key >> 15;
    key = key.wrapping_mul(0x846CA68B);
    key ^ (key >> 16)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pkg2_decryptor_u32() {
        let key = 0xDEADBEEF_u32;
        let decryptor = Pkg2Decryptor::new_with_key(key as u64, DecrypterType::KMST1198);
        let mut decrypted = b"Hello, world!".to_vec();
        decryptor.decrypt_slice(&mut decrypted);
        decryptor.decrypt_slice(&mut decrypted);
        assert_eq!(decrypted, b"Hello, world!");

        let mut decrypted2 = "你好世界".bytes().collect::<Vec<_>>();

        decryptor.decrypt_slice(&mut decrypted2);
        decryptor.decrypt_slice(&mut decrypted2);
        assert_eq!(decrypted2, "你好世界".bytes().collect::<Vec<_>>());
    }

    #[test]
    fn test_pkg2_decryptor_u64() {
        let key = 0xDEADBEEFDEADBEEF;
        let decryptor = Pkg2Decryptor::new_with_key(key, DecrypterType::KMST1198);
        let mut decrypted = b"Hello, world!".to_vec();
        decryptor.decrypt_slice(&mut decrypted);
        decryptor.decrypt_slice(&mut decrypted);
        assert_eq!(decrypted, b"Hello, world!");
    }
}
