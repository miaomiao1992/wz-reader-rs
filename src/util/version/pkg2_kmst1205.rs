//! Shared KMST 1205 hash primitives, ported from WzComparerR2 `Pkg2Kmst1205Hash`.

pub const KMST1205_VERSION_STRINGS: &[&str] = &["v410_260106_1_A1F3C9E2"];

// hardcoded version hash
pub const KMST1205_HASH_VERSION: u64 = 0x8F08_109B_6A61_D954;

const MAGIC1: u64 = 0x84CA_A73B_2BB7_0682;
const MAGIC2: u64 = 0x510E_527F_ADE6_82D1;
const MAGIC3: u64 = 0xBF58_476D_1CE4_E5B9;
const MAGIC4: u64 = 0x94D0_49BB_1331_11EB;
const MAGIC5: u64 = 0x2545_F491_4F6C_DD1D;
const MAGIC6: u64 = 0x6A09_E667_F3BC_C908;
const MAGIC7: u32 = 0x2545_F491;
const MAGIC8: u32 = 0x85EB_CA77;
const MIX_MUL: u64 = 0x9FB2_1C65_1E98_DF25;

const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
const FNV_BASIS: u64 = 0xD7A2_44EE_D55C_C84D;

pub fn compute_pkg2_hash_version(version: &str) -> u64 {
    let mut hash = FNV_BASIS;
    for byte in version.as_bytes() {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
    }
    hash = MAGIC3.wrapping_mul(xor_shift_right(hash, 30));
    hash = MAGIC4.wrapping_mul(xor_shift_right(hash, 27));
    xor_shift_right(hash, 31)
}

/// Hash-version candidates to try against a KMST 1205 header: version strings
/// first (add a build here as clients ship), then the known 64-bit seed.
pub fn kmst1205_hash_version_candidates() -> impl Iterator<Item = u64> {
    KMST1205_VERSION_STRINGS
        .iter()
        .copied()
        .map(compute_pkg2_hash_version)
        .chain(core::iter::once(KMST1205_HASH_VERSION))
}

#[inline(always)]
fn xor_shift_right_u32(value: u32, shift: u32) -> u32 {
    value ^ (value >> shift)
}

#[inline(always)]
fn xor_shift_right(value: u64, shift: u32) -> u64 {
    value ^ (value >> shift)
}

#[inline(always)]
fn xor_fold_64_to_32(value: u64) -> u32 {
    value as u32 ^ (value >> 32) as u32
}

#[inline(always)]
fn multiply_xor_right(value: u64, multiplier: u64, shift: u32) -> u64 {
    multiplier.wrapping_mul(xor_shift_right(value, shift))
}

#[inline(always)]
fn rotate_multiply_xor_right_30(value: u64) -> u64 {
    multiply_xor_right(value, MAGIC3, 30).rotate_right(27)
}

#[inline(always)]
fn multiply_rotate_xor_right_25_47(value: u64) -> u64 {
    MIX_MUL.wrapping_mul(value ^ value.rotate_right(25) ^ value.rotate_right(47))
}

#[inline(always)]
fn multiply_rotate_xor_left_23_41(value: u64) -> u64 {
    MAGIC5.wrapping_mul(value ^ value.rotate_left(23) ^ value.rotate_left(41))
}

#[inline(always)]
fn multiply_xor_right_27(value: u64) -> u64 {
    multiply_xor_right(value, MAGIC4, 27)
}

pub fn compute_shared_hash(hash1: u64, hash_version: u64) -> u64 {
    let mut tmp1 = (hash1 ^ 0x81B4_A012_24AA_B10C).rotate_left(31);
    tmp1 = multiply_xor_right(tmp1, 0xFF51_AFD7_ED55_8CCD, 33);
    tmp1 = multiply_xor_right(tmp1, 0xC4CE_B9FE_1A85_EC53, 29);
    tmp1 = xor_shift_right(tmp1, 32);

    let mut temp2 =
        rotate_multiply_xor_right_30(hash_version.wrapping_sub(0x2E4A_B5CD_2E6D_12FD) ^ MAGIC1);
    temp2 = xor_shift_right(multiply_xor_right_27(temp2), 31);

    let mut value = multiply_rotate_xor_right_25_47(tmp1.wrapping_add(temp2).wrapping_add(MAGIC2));
    value = tmp1 ^ value ^ temp2.rotate_left(17) ^ (value >> 28);
    value = multiply_xor_right(value, MAGIC4, 29);
    xor_shift_right(value, 32)
}

pub fn compute_hash2(hash1: u64, hash_version: u64) -> u64 {
    let shared_hash = compute_shared_hash(hash1, hash_version);
    let mut value = rotate_multiply_xor_right_30(shared_hash ^ MAGIC1);
    value = multiply_xor_right_27(value);
    xor_shift_right(value, 31)
}

pub fn compute_directory_count_key(hash1: u64, hash_version: u64) -> u64 {
    let mut tmp1 = rotate_multiply_xor_right_30(hash1 ^ MAGIC1);
    let tmp2 = multiply_xor_right_27(tmp1);
    tmp1 = multiply_rotate_xor_right_25_47(hash_version.wrapping_add(MAGIC2));
    tmp1 = xor_shift_right(tmp1, 28) ^ (tmp2 >> 31);
    tmp1 ^= tmp2;

    let mut key = hash_version.wrapping_add(hash1) ^ MAGIC6;
    key = multiply_rotate_xor_left_23_41(key);
    key = MAGIC3.wrapping_mul(xor_shift_right(key, 32));
    key = xor_shift_right(key, 29) ^ tmp1.wrapping_add(tmp1.rotate_left(23));
    xor_shift_right(key, 31)
}

pub fn compute_dir_entry_name_key(hash1: u64, hash_version: u64, file_pos: u64) -> u64 {
    let shared_hash = compute_shared_hash(hash1, hash_version);
    let mut position_hash = 0xD1B5_4A32_D192_ED03_u64.wrapping_mul(file_pos);
    position_hash ^= position_hash.rotate_left(32);

    let tmp1 = multiply_rotate_xor_right_25_47(
        position_hash.wrapping_add(shared_hash).wrapping_add(MAGIC2),
    );
    let tmp2 = multiply_rotate_xor_left_23_41(position_hash ^ shared_hash ^ MAGIC6);

    let mut key = MAGIC3.wrapping_mul(xor_shift_right(tmp2, 32));
    key = xor_shift_right(tmp1, 28) ^ xor_shift_right(key, 29);
    key = key.rotate_left((position_hash & 0x3F) as u32);
    xor_shift_right(key, 29)
}

pub fn compute_entry_field_key(hash1: u64, hash_version: u64, file_pos: u32) -> u32 {
    let mixed = xor_fold_64_to_32(compute_shared_hash(hash1, hash_version));
    let hash1_low = hash1 as u32;
    let hash_version_low = hash_version as u32;
    let mut key = mixed
        .wrapping_add(MAGIC7.wrapping_mul(xor_shift_right_u32(file_pos, 15)))
        .wrapping_add(hash1_low ^ hash_version_low);
    key = key.rotate_left((mixed ^ hash1_low) & 0x1F);
    key = xor_shift_right_u32(MAGIC8.wrapping_mul(key), 13);
    key = key.wrapping_sub(0x3D4D_51C3_u32.wrapping_mul(mixed));
    key ^ key.rotate_left(16)
}

pub fn compute_image_offset(
    hash1: u64,
    hash_version: u64,
    header_len: u32,
    file_pos: u32,
    hashed_offset: u32,
) -> u32 {
    let mixed = compute_shared_hash(hash1, hash_version) as u32;
    let hash1_low = hash1 as u32;
    let hash_version_low = hash_version as u32;
    let mut key = (mixed ^ MAGIC7).wrapping_add(hash1_low ^ hash_version_low);
    key = key
        .wrapping_mul(!file_pos.wrapping_sub(header_len))
        .wrapping_add(MAGIC7);
    key ^= 0xC2B2_AE3D_u32.wrapping_mul(mixed) ^ MAGIC8.wrapping_mul(hash1_low);
    key = key.rotate_left((mixed ^ hash1_low ^ hash_version_low) & 0x1F);
    (!hashed_offset ^ key).wrapping_add(header_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH1: u64 = 0x0123_4567_89AB_CDEF;

    #[test]
    fn compute_pkg2_hash_version_yields_known_seed() {
        assert_eq!(
            compute_pkg2_hash_version("v410_260106_1_A1F3C9E2"),
            KMST1205_HASH_VERSION
        );
        assert_ne!(
            compute_pkg2_hash_version("v410_260106_1_A1F3C9E3"),
            KMST1205_HASH_VERSION
        );
    }

    #[test]
    fn computes_shared_and_name_keys() {
        let hash_version = KMST1205_HASH_VERSION;
        assert_eq!(
            compute_shared_hash(HASH1, hash_version),
            0x5D5B_C539_CFB6_833A
        );
        assert_eq!(
            compute_dir_entry_name_key(HASH1, hash_version, 0),
            0x3EDE_499D_1F39_EBF1
        );
        assert_eq!(
            compute_dir_entry_name_key(HASH1, hash_version, 123),
            0x01AA_2681_3C6C_358D
        );
    }
}
