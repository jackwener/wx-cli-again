pub mod sqlcipher;
pub mod wal;

use aes::Aes256;
use anyhow::{bail, Result};
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use std::io::{Read, Write};
use std::path::Path;

type Block = aes::cipher::Block<Aes256>;
type HmacSha512 = Hmac<Sha512>;

pub const PAGE_SZ: usize = 4096;
pub const SALT_SZ: usize = 16;
pub const RESERVE_SZ: usize = 80; // IV(16) + HMAC(64)
pub const IV_SZ: usize = 16;
pub const HMAC_SZ: usize = 64;

/// SQLite 文件头魔数（16字节）
pub const SQLITE_HDR: &[u8] = b"SQLite format 3\x00";

type Aes256CbcDec = Decryptor<Aes256>;

/// 解密单个 SQLCipher 4 页
///
/// - `enc_key`: 32字节 AES 密钥
/// - `page_data`: 原始加密页面数据（PAGE_SZ 字节）
/// - `pgno`: 页码（从1开始）
///
/// 返回解密后的完整页面（PAGE_SZ 字节）
pub fn decrypt_page(enc_key: &[u8; 32], page_data: &[u8], pgno: u32) -> Result<Vec<u8>> {
    if page_data.len() < PAGE_SZ {
        bail!("页面数据不足 {} 字节", PAGE_SZ);
    }

    // IV 位于页面末尾 RESERVE_SZ 区域的前16字节
    let iv_offset = PAGE_SZ - RESERVE_SZ;
    let iv: &[u8; 16] = page_data[iv_offset..iv_offset + 16]
        .try_into()
        .expect("IV 长度固定为 16");

    let mut result = vec![0u8; PAGE_SZ];

    if pgno == 1 {
        // 第一页：跳过 salt(16字节)，解密 [SALT_SZ..PAGE_SZ-RESERVE_SZ]
        let enc = &page_data[SALT_SZ..PAGE_SZ - RESERVE_SZ];
        let dec = aes_cbc_decrypt(enc_key, iv, enc)?;
        // 写入 SQLite 文件头
        result[..16].copy_from_slice(SQLITE_HDR);
        // 写入解密数据（从第16字节开始）
        result[16..PAGE_SZ - RESERVE_SZ].copy_from_slice(&dec);
        // 末尾 RESERVE_SZ 字节补零
        // （已经是零，无需显式操作）
    } else {
        // 其他页：解密 [0..PAGE_SZ-RESERVE_SZ]
        let enc = &page_data[..PAGE_SZ - RESERVE_SZ];
        let dec = aes_cbc_decrypt(enc_key, iv, enc)?;
        result[..PAGE_SZ - RESERVE_SZ].copy_from_slice(&dec);
        // 末尾 RESERVE_SZ 字节补零
    }

    Ok(result)
}

/// 用数据库第一页验证 32-byte raw key（优先 SQLCipher 4 HMAC-SHA512）。
pub fn validate_raw_key_for_db(db_path: &Path, enc_key: &[u8; 32]) -> bool {
    let mut page = [0u8; PAGE_SZ];
    let Ok(mut file) = std::fs::File::open(db_path) else {
        return false;
    };
    if file.read_exact(&mut page).is_err() {
        return false;
    }
    if verify_hmac_page1(&page, enc_key) {
        return true;
    }
    decrypt_page(enc_key, &page, 1)
        .map(|plain| has_valid_sqlite_page1_header(&plain))
        .unwrap_or(false)
}

/// SQLCipher 4 第 1 页 HMAC-SHA512 校验。
pub fn verify_hmac_page1(page: &[u8], enc_key: &[u8; 32]) -> bool {
    if page.len() < PAGE_SZ {
        return false;
    }
    let salt = &page[..SALT_SZ];
    let mut mac_salt = [0u8; SALT_SZ];
    for (i, b) in salt.iter().enumerate() {
        mac_salt[i] = b ^ 0x3a;
    }
    let mut mac_key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(enc_key, &mac_salt, 2, &mut mac_key);

    let content_end = PAGE_SZ - RESERVE_SZ;
    let content = &page[SALT_SZ..content_end];
    let iv = &page[content_end..content_end + IV_SZ];
    let stored = &page[content_end + IV_SZ..content_end + IV_SZ + HMAC_SZ];

    let Ok(mut mac) = HmacSha512::new_from_slice(&mac_key) else {
        return false;
    };
    mac.update(content);
    mac.update(iv);
    mac.update(&1u32.to_le_bytes());
    mac.verify_slice(stored).is_ok()
}

fn has_valid_sqlite_page1_header(page: &[u8]) -> bool {
    if page.len() < 24 || &page[..16] != SQLITE_HDR {
        return false;
    }
    let page_size = u16::from_be_bytes([page[16], page[17]]);
    page_size as usize == PAGE_SZ
        && matches!(page[18], 1 | 2)
        && matches!(page[19], 1 | 2)
        && page[20] as usize == RESERVE_SZ
        && page[21..24] == [64, 32, 32]
}

/// AES-256-CBC 解密（不去除 padding，SQLCipher 不使用 PKCS#7 padding）
fn aes_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || data.len() % 16 != 0 {
        bail!("密文长度不是 AES 块大小的倍数: {}", data.len());
    }
    // 将 &[u8] 复制为 Block 数组，避免 unsafe from_raw_parts_mut
    let mut blocks: Vec<Block> = data.chunks_exact(16).map(Block::clone_from_slice).collect();
    Aes256CbcDec::new(key.into(), iv.into()).decrypt_blocks_mut(&mut blocks);
    Ok(blocks.iter().flat_map(|b| b.iter().copied()).collect())
}

/// 完整解密一个 SQLCipher 数据库文件（流式，逐页读写避免全量载入内存）
///
/// 读取 `db_path`，按 PAGE_SZ 分页解密，写入 `out_path`
pub fn full_decrypt(db_path: &Path, out_path: &Path, enc_key: &[u8; 32]) -> Result<()> {
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut input = std::fs::File::open(db_path)?;
    let file_size = input.metadata()?.len() as usize;
    if file_size == 0 {
        bail!("数据库文件为空: {}", db_path.display());
    }

    let mut output = crate::private_fs::create_new(out_path)?;
    let total_pages = (file_size + PAGE_SZ - 1) / PAGE_SZ;
    let mut page_buf = vec![0u8; PAGE_SZ];

    for pgno in 1..=total_pages {
        let page_start = (pgno - 1) * PAGE_SZ;
        let bytes_remaining = file_size.saturating_sub(page_start);
        read_page(&mut input, &mut page_buf, bytes_remaining)?;
        let dec = decrypt_page(enc_key, &page_buf, pgno as u32)?;
        output.write_all(&dec)?;
    }

    Ok(())
}

fn read_page(
    input: &mut impl Read,
    page_buf: &mut [u8],
    bytes_remaining: usize,
) -> std::io::Result<usize> {
    let expected = bytes_remaining.min(PAGE_SZ);
    input.read_exact(&mut page_buf[..expected])?;
    if expected < PAGE_SZ {
        page_buf[expected..].fill(0);
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use super::{read_page, PAGE_SZ};
    use std::io::{self, Read};

    struct ChunkedReader {
        chunks: Vec<Vec<u8>>,
        chunk_idx: usize,
        offset: usize,
    }

    impl ChunkedReader {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            Self {
                chunks,
                chunk_idx: 0,
                offset: 0,
            }
        }
    }

    impl Read for ChunkedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.chunk_idx >= self.chunks.len() {
                return Ok(0);
            }
            let chunk = &self.chunks[self.chunk_idx];
            let remaining = &chunk[self.offset..];
            let n = remaining.len().min(buf.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.offset += n;
            if self.offset == chunk.len() {
                self.chunk_idx += 1;
                self.offset = 0;
            }
            Ok(n)
        }
    }

    #[test]
    fn read_page_reads_across_short_chunks() {
        let mut reader = ChunkedReader::new(vec![vec![1; 32], vec![2; PAGE_SZ - 32]]);
        let mut page_buf = vec![0u8; PAGE_SZ];

        let n = read_page(&mut reader, &mut page_buf, PAGE_SZ).unwrap();

        assert_eq!(n, PAGE_SZ);
        assert_eq!(page_buf[0], 1);
        assert_eq!(page_buf[31], 1);
        assert_eq!(page_buf[32], 2);
        assert_eq!(page_buf[PAGE_SZ - 1], 2);
    }

    #[test]
    fn read_page_zero_pads_last_partial_page() {
        let mut reader = ChunkedReader::new(vec![vec![7; 8], vec![9; 4]]);
        let mut page_buf = vec![0u8; PAGE_SZ];

        let n = read_page(&mut reader, &mut page_buf, 12).unwrap();

        assert_eq!(n, 12);
        assert_eq!(&page_buf[..8], &[7; 8]);
        assert_eq!(&page_buf[8..12], &[9; 4]);
        assert!(page_buf[12..].iter().all(|&b| b == 0));
    }

    #[test]
    fn read_page_errors_on_early_eof() {
        let mut reader = ChunkedReader::new(vec![vec![1; 8]]);
        let mut page_buf = vec![0u8; PAGE_SZ];

        let err = read_page(&mut reader, &mut page_buf, 16).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
