use super::Decryptor;
use crate::util::string_decryptor::DecrypterType;

#[derive(Debug)]
pub struct Pkg2Decryptor {
    iv: u64,
    enc_type: DecrypterType,
    keys: [u8; 8],
    /// KMST1204/1205: position-dependent key material
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
        if !matches!(enc_type, DecrypterType::KMST1204 | DecrypterType::KMST1205) {
            self.calculate_keys(key);
        }
    }

    fn set_key_material(&mut self, hash1: u64, hash_version: u64, enc_type: DecrypterType) {
        self.enc_type = enc_type;
        self.hash1 = hash1;
        self.hash_version = hash_version;
        if matches!(enc_type, DecrypterType::KMST1204 | DecrypterType::KMST1205) {
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
        match self.enc_type {
            DecrypterType::KMST1204 => self.calculate_keys(get_kmst1204_key(
                self.hash1,
                self.hash_version,
                file_position,
            )),
            DecrypterType::KMST1205 => self.calculate_keys(get_kmst1205_key(
                self.hash1,
                self.hash_version,
                file_position,
            )),
            _ => {}
        }
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
        let keys = match self.enc_type {
            DecrypterType::KMST1204 => {
                gen_pkg2_keys(get_kmst1204_key(self.hash1, self.hash_version, offset))
            }
            DecrypterType::KMST1205 => {
                gen_pkg2_keys(get_kmst1205_key(self.hash1, self.hash_version, offset))
            }
            _ => self.keys,
        };
        for (i, item) in data.iter_mut().enumerate() {
            *item ^= keys[i % 8];
        }
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

/// Core KMST1205 64-bit mixer shared by hash, offset, and string-key calculations.
#[inline]
pub(crate) fn mix_kmst1205(hash_version: u64, hash1: u64) -> u64 {
    let v2 = (hash1 ^ 0x81B4_A012_24AA_B10C).rotate_left(31);

    let t1 = 0xFF51_AFD7_ED55_8CCD_u64.wrapping_mul(v2 ^ (v2 >> 33));
    let mut v3 = 0xC4CE_B9FE_1A85_EC53_u64.wrapping_mul(t1 ^ (t1 >> 29));
    v3 ^= v3 >> 32;

    let a = hash_version.wrapping_sub(0x2E4A_B5CD_2E6D_12FD);
    let t2 = a ^ 0x84CA_A73B_2BB7_0682;
    let v4 = 0xBF58_476D_1CE4_E5B9_u64
        .wrapping_mul(t2 ^ (t2 >> 30))
        .rotate_right(27);
    let v5x = 0x94D0_49BB_1331_11EB_u64.wrapping_mul(v4 ^ (v4 >> 27));
    let v5 = v5x ^ (v5x >> 31);
    let v6 = v5.wrapping_add(0x510E_527F_ADE6_82D1);
    let v7 = v5.rotate_left(17);

    let tmp = v3.wrapping_add(v6);
    let v8 =
        0x9FB2_1C65_1E98_DF25_u64.wrapping_mul(tmp ^ tmp.rotate_right(25) ^ tmp.rotate_right(47));
    let f = v3 ^ v8 ^ v7 ^ (v8 >> 28);
    let fx = 0x94D0_49BB_1331_11EB_u64.wrapping_mul(f ^ (f >> 29));
    fx ^ (fx >> 32)
}

/// KMST1205 position-dependent directory string key.
#[inline]
pub fn get_kmst1205_key(hash1: u64, hash_version: u64, file_position: u64) -> u64 {
    let mixed = mix_kmst1205(hash_version, hash1);
    let mul1 = 0xD1B5_4A32_D192_ED03_u64.wrapping_mul(file_position);
    let v43 = mul1 ^ mul1.rotate_left(32);

    let t1 = v43 ^ mixed ^ 0x6A09_E667_F3BC_C908;
    let v44 = 0x2545_F491_4F6C_DD1D_u64.wrapping_mul(t1 ^ t1.rotate_left(23) ^ t1.rotate_left(41));

    let sum1 = v43.wrapping_add(mixed).wrapping_add(0x510E_527F_ADE6_82D1);
    let v45 = 0x9FB2_1C65_1E98_DF25_u64
        .wrapping_mul(sum1 ^ sum1.rotate_right(25) ^ sum1.rotate_right(47));

    let t2 = 0xBF58_476D_1CE4_E5B9_u64.wrapping_mul(v44 ^ (v44 >> 32) as u32 as u64);
    let inner = v45 ^ t2 ^ (t2 >> 29) ^ (v45 >> 28);
    let v46 = inner.rotate_left((v43 & 0x3F) as u32);
    v46 ^ (v46 >> 29)
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

    #[test]
    fn test_kmst1205_mix_and_position_keys() {
        let hash1 = 0x0123_4567_89AB_CDEF;
        let hash_version = 0x8F08_109B_6A61_D954;

        assert_eq!(mix_kmst1205(hash_version, hash1), 0x5D5B_C539_CFB6_833A);
        assert_eq!(
            get_kmst1205_key(hash1, hash_version, 0),
            0x3EDE_499D_1F39_EBF1
        );
        assert_eq!(
            get_kmst1205_key(hash1, hash_version, 123),
            0x01AA_2681_3C6C_358D
        );
    }
}
