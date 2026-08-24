use crate::{directory, reader::Error, WzHeader};

type Result<T> = std::result::Result<T, Error>;
type EntryCountResult<T> = std::result::Result<T, directory::Error>;

static WZ_OFFSET: u32 = 0x581C3F6D;

#[derive(Debug, Clone, Copy, Default)]
pub enum WzOffsetVersion {
    #[default]
    Pkg1,
    Pkg2V1,
    Pkg2V2,
    Pkg2V3,
    Pkg2_64V1,
    Pkg2_64V2,
}

impl WzOffsetVersion {
    pub fn get_calculator(&self) -> OffsetCalculator {
        match self {
            WzOffsetVersion::Pkg1 => read_wz_offset,
            WzOffsetVersion::Pkg2V1 => read_wz_offset_pkg2,
            WzOffsetVersion::Pkg2V2 => read_wz_offset_pkg2_v2,
            WzOffsetVersion::Pkg2V3 => read_wz_offset_pkg2_v3,
            WzOffsetVersion::Pkg2_64V1 => read_wz_offset_pkg2_64_v1,
            WzOffsetVersion::Pkg2_64V2 => read_wz_offset_pkg2_64_v2,
        }
    }
    pub fn get_entry_count_calculator(&self) -> EntryCountCalculator {
        match self {
            WzOffsetVersion::Pkg2_64V1 => decrypt_pkg2_entry_count_64_v1,
            WzOffsetVersion::Pkg2_64V2 => decrypt_pkg2_entry_count_64_v2,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WzOffsetMeta {
    pub hash: u64,
    pub encrypted_offset: u32,
    pub offset: usize,
}

impl WzOffsetMeta {
    #[inline]
    pub fn hash_u32(&self) -> u32 {
        self.hash as u32
    }
}

pub type OffsetCalculator = fn(&WzHeader, &WzOffsetMeta) -> Result<usize>;
pub type EntryCountCalculator = fn(&WzHeader, u64, i64) -> EntryCountResult<usize>;

/// calculate the offset of the specific data like wz image/directory in wz file,
/// only work in pkg1
#[inline]
pub fn read_wz_offset(header: &WzHeader, meta: &WzOffsetMeta) -> Result<usize> {
    let header_size = header.fstart;
    let offset = meta.offset;
    let hash = meta.hash_u32() as usize;

    let offset = offset.wrapping_sub(header_size) ^ 0xFFFFFFFF;
    let offset = offset.wrapping_mul(hash) & 0xFFFFFFFF;
    let offset = offset.wrapping_sub(WZ_OFFSET as usize);
    // it's pretty important need to cast to i32 first usize.rotate_left will give wrong result
    let offset = (offset as i32).rotate_left((offset as u32) & 0x1F) as usize & 0xFFFFFFFF;

    let offset = (offset ^ (meta.encrypted_offset as usize)) & 0xFFFFFFFF;
    let offset = offset.wrapping_add(header_size * 2) & 0xFFFFFFFF;

    Ok(offset)
}

/// calculate the offset of the specific data like wz image/directory in wz file,
/// only work in pkg2 with version 1196-1197
#[inline]
pub fn read_wz_offset_pkg2(header: &WzHeader, meta: &WzOffsetMeta) -> Result<usize> {
    let offset = meta.offset as u32;
    let header_size = header.fstart as u32;
    let hash = meta.hash_u32();
    let hash1 = header.hash1_u32();

    let distance = ((hash ^ hash1) & 0x1F) as u8;

    let offset = offset.wrapping_sub(header_size);
    let offset = !offset;
    let offset = offset.wrapping_mul(hash);
    let offset = offset.wrapping_sub(WZ_OFFSET);
    let offset = offset ^ hash1.wrapping_mul(0x01010101);
    let offset = offset.rotate_left(distance as u32);

    let offset = offset ^ meta.encrypted_offset;
    let offset = offset.wrapping_add(header_size);

    Ok(offset as usize)
}

/// calculate the offset of the specific data like wz image/directory in wz file,
/// only work in pkg2 with version 1198
#[inline]
pub fn read_wz_offset_pkg2_v2(header: &WzHeader, meta: &WzOffsetMeta) -> Result<usize> {
    let offset = meta.offset as u32;
    let header_size = header.fstart as u32;
    let hash = meta.hash_u32();
    let hash1 = header.hash1_u32();

    let distance = ((hash ^ hash1) & 0x1F) as u8 as u32;

    let offset = offset.wrapping_sub(header_size);
    let offset = !offset;
    let offset = offset.wrapping_mul(hash ^ hash1);
    let offset = offset.wrapping_sub(WZ_OFFSET);
    let offset = offset ^ hash1.wrapping_mul(0x01010101);
    let offset = offset.rotate_left(distance);

    let offset = offset ^ !meta.encrypted_offset;
    let offset = offset.wrapping_add(header_size);

    Ok(offset as usize)
}

/// calculate the offset of the specific data like wz image/directory in wz file,
/// only work in pkg2 with version 1199-1200
#[inline]
pub fn read_wz_offset_pkg2_v3(header: &WzHeader, meta: &WzOffsetMeta) -> Result<usize> {
    let offset = meta.offset as u32;
    let header_size = header.fstart as u32;
    let hash = meta.hash_u32();
    let hash1 = header.hash1_u32();
    let pre_hash = hash1 ^ hash;
    let mixed_hash =
        crate::util::string_decryptor::pkg2_decryptor::mix_kmst1199(pre_hash ^ 0x6D4C3B2A)
            ^ 0x91E10DA5;
    let distance = (pre_hash ^ mixed_hash) & 0x1F;

    let offset = offset.wrapping_sub(header_size);
    let offset = !offset;
    let offset = offset.wrapping_mul(pre_hash.wrapping_add(mixed_hash ^ 0xA7E3C093));
    let offset = offset.wrapping_sub(WZ_OFFSET);
    let offset = offset ^ hash1.wrapping_mul(0x01010101);
    let offset = offset ^ mixed_hash.wrapping_mul(0x9E3779B9);
    let offset = offset.rotate_left(distance);
    let offset = offset ^ !meta.encrypted_offset;
    let offset = offset.wrapping_add(header_size);

    Ok(offset as usize)
}

/// Shared key used by KMST1202/1204 offset and length decryption.
#[inline]
pub fn calc_pkg2_64_v1_shared_key(header: &WzHeader, hash: u64, file_pos: u32) -> u32 {
    let header_size = header.fstart as u32;
    let pre_hash = header.hash1_u32() ^ (hash as u32);
    let mixed_hash = pre_hash ^ 0x33BBBB33;

    let mut key = file_pos.wrapping_sub(header_size);
    key = !key;
    key = key.wrapping_mul(pre_hash.wrapping_add(mixed_hash ^ 0xA7E3C093));
    key = key.wrapping_sub(WZ_OFFSET);
    key ^= header.hash1_u32().wrapping_mul(0x01010101);
    key ^= mixed_hash.wrapping_mul(0x9E3779B9);
    key.rotate_left(19)
}

/// KMST1204 encrypts directory entry size/checksum with the shared offset key.
#[inline]
pub fn calc_pkg2_64_v1_length(
    header: &WzHeader,
    hash: u64,
    file_pos: u32,
    encrypted_value: i32,
) -> i32 {
    encrypted_value ^ (calc_pkg2_64_v1_shared_key(header, hash, file_pos) as i32)
}

/// calculate the offset of the specific data like wz image/directory in wz file,
/// only work in pkg2 with version 1202-1204
#[inline]
pub fn read_wz_offset_pkg2_64_v1(header: &WzHeader, meta: &WzOffsetMeta) -> Result<usize> {
    let header_size = header.fstart as u32;
    let offset = calc_pkg2_64_v1_shared_key(header, meta.hash, meta.offset as u32);
    let offset = offset ^ !meta.encrypted_offset;
    let offset = offset.wrapping_add(header_size);

    Ok(offset as usize)
}

#[inline]
pub fn decrypt_pkg2_entry_count_64_v1(
    header: &WzHeader,
    hash: u64,
    encrypted_entry_count: i64,
) -> EntryCountResult<usize> {
    let dir_count =
        (encrypted_entry_count ^ header.hash1 as i64 ^ hash as i64 ^ 0x550EC4DD02C468EC) >> 16;
    if dir_count > i32::MAX as i64 {
        return Err(directory::Error::InvalidEntryCount);
    }
    Ok(dir_count as usize)
}

#[inline]
fn calc_pkg2_64_v2_shared_key(header: &WzHeader, hash: u64, file_pos: u32) -> u32 {
    use crate::util::string_decryptor::pkg2_decryptor::mix_kmst1205;

    let mixed = mix_kmst1205(hash, header.hash1);
    let folded = mixed as u32 ^ (mixed >> 32) as u32;
    let relative_pos = file_pos.wrapping_sub(header.fstart as u32);
    let inner = folded
        .wrapping_add(0x2545_F491_u32.wrapping_mul(relative_pos ^ (relative_pos >> 15)))
        .wrapping_add(hash as u32 ^ header.hash1_u32());
    let rolled = inner.rotate_left((folded ^ header.hash1_u32()) & 0x1F);
    let v6lo = 0x85EB_CA77_u32.wrapping_mul(rolled);
    let t = (v6lo ^ (v6lo >> 13)).wrapping_sub(0x3D4D_51C3_u32.wrapping_mul(folded));
    t ^ t.rotate_left(16)
}

/// KMST1205 encrypts directory entry size/checksum with its new shared key.
#[inline]
pub fn calc_pkg2_64_v2_length(
    header: &WzHeader,
    hash: u64,
    file_pos: u32,
    encrypted_value: i32,
) -> i32 {
    encrypted_value ^ calc_pkg2_64_v2_shared_key(header, hash, file_pos) as i32
}

/// Calculate an image/directory offset for KMST1205.
#[inline]
pub fn read_wz_offset_pkg2_64_v2(header: &WzHeader, meta: &WzOffsetMeta) -> Result<usize> {
    use crate::util::string_decryptor::pkg2_decryptor::mix_kmst1205;

    let mixed = mix_kmst1205(meta.hash, header.hash1) as u32;
    let hash1 = header.hash1_u32();
    let hash_version = meta.hash as u32;
    let file_pos = meta.offset as u32;
    let header_size = header.fstart as u32;

    let part1 = 0xC2B2_AE3D_u32.wrapping_mul(mixed);
    let part2 = 0x85EB_CA77_u32.wrapping_mul(hash1);
    let part3 = (hash1 ^ hash_version)
        .wrapping_add(mixed ^ 0x2545_F491)
        .wrapping_mul(!file_pos.wrapping_sub(header_size));
    let key = part1 ^ part2 ^ part3.wrapping_add(0x2545_F491);
    let rotation = (mixed ^ hash1 ^ hash_version) & 0x1F;

    let offset = (!meta.encrypted_offset ^ key.rotate_left(rotation)).wrapping_add(header_size);
    Ok(offset as usize)
}

#[inline]
fn mix_pkg2_64_v2_entry_count(hash_version: u64, hash1: u64) -> u64 {
    let t1 = hash1 ^ 0x84CA_A73B_2BB7_0682;
    let v3 = 0xBF58_476D_1CE4_E5B9_u64
        .wrapping_mul(t1 ^ (t1 >> 30))
        .rotate_right(27);

    let sum1 = hash_version.wrapping_add(0x510E_527F_ADE6_82D1);
    let v4 = 0x9FB2_1C65_1E98_DF25_u64
        .wrapping_mul(sum1 ^ sum1.rotate_right(25) ^ sum1.rotate_right(47));
    let tmp2 = 0x94D0_49BB_1331_11EB_u64.wrapping_mul(v3 ^ (v3 >> 27));
    let v5 = v4 ^ ((v4 ^ (tmp2 >> 3)) >> 28);

    let t4 = hash_version.wrapping_add(hash1) ^ 0x6A09_E667_F3BC_C908;
    let v6 = 0x2545_F491_4F6C_DD1D_u64.wrapping_mul(t4 ^ t4.rotate_left(23) ^ t4.rotate_left(41));
    let tmp3 = 0xBF58_476D_1CE4_E5B9_u64.wrapping_mul(v6 ^ (v6 >> 32) as u32 as u64);
    let x = tmp2 ^ v5;
    let v7 = (tmp3 ^ (tmp3 >> 29)) ^ x.wrapping_add(x.rotate_left(23));
    v7 ^ (v7 >> 31)
}

#[inline]
pub fn decrypt_pkg2_entry_count_64_v2(
    header: &WzHeader,
    hash: u64,
    encrypted_entry_count: i64,
) -> EntryCountResult<usize> {
    let dir_count =
        (encrypted_entry_count as u64 ^ mix_pkg2_64_v2_entry_count(hash, header.hash1)) >> 16;
    if dir_count > i32::MAX as u64 {
        return Err(directory::Error::InvalidEntryCount);
    }
    Ok(dir_count as usize)
}
