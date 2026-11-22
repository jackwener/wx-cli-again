/// Linux WeChat 进程内存密钥扫描器
///
/// 保留明文 x'<64hex><32hex>' 扫描，并按 issue #7 的 Linux 4.1 布局
/// 从 WCDB Config.Cipher 中还原循环 XOR 混淆的 keyspec。
use anyhow::{Context, Result};
use regex::bytes::Regex;
use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::{
    collect_db_salts, decode_key_hex, match_raw_keys, merge_key_entries, scan_key_patterns,
    KeyEntry, MAX_PATTERN_BYTES,
};

const CHUNK_SIZE: usize = 2 * 1024 * 1024;
const CIPHER_NAME: &[u8] = b"com.Tencent.WCDB.Config.Cipher";
const CIPHER_BLOB_OFFSET: u64 = 0x98; // Linux 4.1；Windows 的偏移不同
                                      // keyspec 通常只有 99 字节。限制异常长度，避免失效指针导致巨量分配。
const MAX_CIPHER_BLOB_BYTES: usize = 1024 * 1024;
const CIPHER_MASK: [u8; 32] = [
    0xd2, 0xc7, 0x44, 0x24, 0x58, 0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x50, 0x48, 0x8b,
    0x45, 0x00, 0x48, 0x84, 0x4c, 0x24, 0x48, 0x48, 0x89, 0x44, 0x25, 0x40, 0x48, 0x58, 0x4c, 0x24,
];

#[derive(Default)]
struct KeyCandidates {
    plain: Vec<(String, String)>,
    obfuscated: Vec<(String, String)>,
}

/// 查找 WeChat 进程 PID
fn find_wechat_pid() -> Option<u32> {
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let comm_path = format!("/proc/{}/comm", name_str);
        if let Ok(comm) = std::fs::read_to_string(&comm_path) {
            let comm = comm.trim().to_lowercase();
            if comm == "wechat" || comm == "weixin" {
                if let Ok(pid) = name_str.parse::<u32>() {
                    return Some(pid);
                }
            }
        }
    }
    None
}

/// 包括只读映射：Config.Cipher 名称可能位于 rodata。
fn parse_readable_maps(content: &str) -> Vec<(u64, u64)> {
    let mut regions = Vec::new();
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !perms.starts_with('r') {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        if let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        {
            if start < end {
                regions.push((start, end));
            }
        }
    }
    regions.sort_unstable();
    regions
}

pub fn scan_keys(db_dir: &Path) -> Result<Vec<KeyEntry>> {
    let pid = find_wechat_pid().context("找不到 WeChat 进程，请确认 WeChat 正在运行")?;
    eprintln!("WeChat PID: {}", pid);
    let db_salts = collect_db_salts(db_dir);
    eprintln!("找到 {} 个加密数据库", db_salts.len());

    eprintln!("扫描进程内存...");
    let maps_path = format!("/proc/{}/maps", pid);
    let maps =
        std::fs::read_to_string(&maps_path).with_context(|| format!("读取 {} 失败", maps_path))?;
    let regions = parse_readable_maps(&maps);
    eprintln!("找到 {} 个可读内存区域", regions.len());
    let mem_path = format!("/proc/{}/mem", pid);
    let mut mem_file = std::fs::File::open(&mem_path)
        .with_context(|| format!("打开 {} 失败，请以 root 权限运行", mem_path))?;

    let candidates = scan_memory(&mut mem_file, &regions);
    let count = candidates.plain.len() + candidates.obfuscated.len();
    eprintln!(
        "找到 {} 个候选密钥（明文 {}，XOR 还原 {}）",
        count,
        candidates.plain.len(),
        candidates.obfuscated.len()
    );
    let plain = match_raw_keys(db_dir, &candidates.plain, &db_salts);
    let obfuscated = match_obfuscated_keys(db_dir, &candidates.obfuscated, &db_salts);
    let entries = merge_key_entries(&plain, &obfuscated);
    eprintln!(
        "匹配到 {}/{} 个数据库密钥（来自 {} 个候选 key）",
        entries.len(),
        db_salts.len(),
        count
    );
    Ok(entries)
}

fn scan_memory(mem: &mut (impl Read + Seek), regions: &[(u64, u64)]) -> KeyCandidates {
    let mut keys = KeyCandidates::default();
    let mut names = HashSet::new();
    let name_pattern = Regex::new(r"(?-u:com\.Tencent\.WCDB\.Config\.Cipher)").unwrap();
    read_regions(mem, regions, |addr, buf| {
        scan_key_patterns(buf, &mut keys.plain);
        for found in name_pattern.find_iter(buf) {
            names.insert(addr + found.start() as u64);
        }
    });
    if names.is_empty() {
        return keys;
    }

    // 第二遍查找 (名称地址 A, 长度 30)；不要求指针在扫描块内对齐。
    let length_pattern = Regex::new(r"(?-u:\x1e\x00{7})").unwrap();
    let mut nodes = HashSet::new();
    read_regions(mem, regions, |addr, buf| {
        for found in length_pattern.find_iter(buf) {
            let Some(i) = found.start().checked_sub(8) else {
                continue;
            };
            if names.contains(&le_u64(&buf[i..i + 8])) {
                if let Some(node) = (addr + i as u64).checked_sub(0x10) {
                    nodes.insert(node);
                }
            }
        }
    });

    let mut seen_blobs = HashSet::new();
    for node_addr in nodes {
        let mut node = [0u8; 0x50];
        if read_memory(mem, regions, node_addr, &mut node).is_none()
            || !names.contains(&le_u64(&node[0x10..0x18]))
            || le_u64(&node[0x18..0x20]) != CIPHER_NAME.len() as u64
        {
            continue;
        }
        let cfg = le_u64(&node[0x28..0x30]);
        let Some(descriptor_addr) = cfg.checked_add(CIPHER_BLOB_OFFSET).filter(|_| cfg != 0) else {
            continue;
        };
        let mut descriptor = [0u8; 16];
        if read_memory(mem, regions, descriptor_addr, &mut descriptor).is_none() {
            continue;
        }
        let blob_addr = le_u64(&descriptor[..8]);
        let Ok(blob_len) = usize::try_from(le_u64(&descriptor[8..])) else {
            continue;
        };
        if !(MAX_PATTERN_BYTES..=MAX_CIPHER_BLOB_BYTES).contains(&blob_len)
            || !seen_blobs.insert((blob_addr, blob_len))
        {
            continue;
        }
        let mut blob = vec![0u8; blob_len];
        if read_memory(mem, regions, blob_addr, &mut blob).is_none() {
            continue;
        }
        // 相位从 blob 起点计算，而不是从内存地址或 keyspec 起点计算。
        for (i, byte) in blob.iter_mut().enumerate() {
            *byte ^= CIPHER_MASK[i % CIPHER_MASK.len()];
        }
        scan_key_patterns(&blob, &mut keys.obfuscated);
    }
    keys
}

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("8-byte pointer or length"))
}

/// 有界流式扫描；保留跨块/相邻映射的尾部，短读后继续，失效页只跳过一页。
fn read_regions(
    mem: &mut (impl Read + Seek),
    regions: &[(u64, u64)],
    mut visit: impl FnMut(u64, &[u8]),
) {
    let mut buf = vec![0u8; CHUNK_SIZE + MAX_PATTERN_BYTES];
    let mut carry = 0;
    let mut previous_end = None;
    for &(start, end) in regions {
        if previous_end != Some(start) {
            carry = 0;
        }
        let mut addr = start;
        while addr < end {
            let size = (end - addr).min(CHUNK_SIZE as u64) as usize;
            let read = mem
                .seek(SeekFrom::Start(addr))
                .and_then(|_| mem.read(&mut buf[carry..carry + size]));
            match read {
                Ok(n) if n > 0 => {
                    let len = carry + n;
                    visit(addr - carry as u64, &buf[..len]);
                    carry = len.min(MAX_PATTERN_BYTES);
                    buf.copy_within(len - carry..len, 0);
                    addr += n as u64;
                }
                _ => {
                    carry = 0;
                    addr += (end - addr).min(4096);
                }
            }
        }
        previous_end = Some(end);
    }
}

/// 校验整段地址都在可读映射中，允许跨相邻映射；忽略扫描期间失效的指针。
fn read_memory(
    mem: &mut (impl Read + Seek),
    regions: &[(u64, u64)],
    addr: u64,
    buf: &mut [u8],
) -> Option<()> {
    if addr == 0 {
        return None;
    }
    let end = addr.checked_add(buf.len() as u64)?;
    let mut cursor = addr;
    for &(start, stop) in regions {
        if stop <= cursor {
            continue;
        }
        if start > cursor {
            return None;
        }
        cursor = stop.min(end);
        if cursor == end {
            mem.seek(SeekFrom::Start(addr)).ok()?;
            return mem.read_exact(buf).ok();
        }
    }
    None
}

/// XOR 候选必须 salt 配对且通过第一页 HMAC；不采用明文路径的解密头部回退。
fn match_obfuscated_keys(
    db_dir: &Path,
    raw_keys: &[(String, String)],
    db_salts: &[(String, String)],
) -> Vec<KeyEntry> {
    let mut entries = Vec::new();
    if raw_keys.is_empty() {
        return entries;
    }
    for (salt, name) in db_salts {
        let mut page = [0u8; crate::crypto::PAGE_SZ];
        if std::fs::File::open(db_dir.join(name))
            .and_then(|mut file| file.read_exact(&mut page))
            .is_err()
            || super::hex::encode(&page[..crate::crypto::SALT_SZ]) != *salt
        {
            continue;
        }
        for (key_hex, key_salt) in raw_keys {
            if key_salt != salt {
                continue;
            }
            let Some(key) = decode_key_hex(key_hex) else {
                continue;
            };
            if crate::crypto::verify_hmac_page1(&page, &key) {
                entries.push(KeyEntry {
                    db_name: name.clone(),
                    enc_key: key_hex.clone(),
                    salt: salt.clone(),
                });
                break;
            }
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    const NAME: usize = 0x100;
    const NODE: usize = 0x280;
    const CFG: usize = 0x400;
    const BLOB: usize = 0x603; // 故意不按 32 字节对齐

    fn put_u64(mem: &mut [u8], offset: usize, value: u64) {
        mem[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn add_cipher(mem: &mut [u8], layout: [usize; 4], key: &str, salt: &str, prefix: usize) {
        let [name, node, cfg, blob] = layout;
        mem[name..name + 30].copy_from_slice(b"com.Tencent.WCDB.Config.Cipher");
        put_u64(mem, node + 0x10, name as u64);
        put_u64(mem, node + 0x18, 30);
        put_u64(mem, node + 0x28, cfg as u64);
        let mut plain = vec![0x55; prefix];
        plain.extend_from_slice(format!("x'{key}{salt}'").as_bytes());
        plain.extend_from_slice(b"suffix");
        put_u64(mem, cfg + 0x98, blob as u64);
        put_u64(mem, cfg + 0xa0, plain.len() as u64);
        // 独立使用 issue #7 给出的十六进制掩码，不引用被测实现的常量。
        let mask_hex = "d2c7442458020000004889442450488b450048844c2448488944254048584c24";
        let mask: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&mask_hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        for (i, byte) in plain.iter().enumerate() {
            mem[blob + i] = byte ^ mask[i % 32];
        }
    }

    fn fixture(prefix: usize) -> Vec<u8> {
        let mut mem = vec![0u8; 0x2000];
        add_cipher(
            &mut mem,
            [NAME, NODE, CFG, BLOB],
            &"23".repeat(32),
            &"ab".repeat(16),
            prefix,
        );
        mem
    }

    fn scan_bytes(mem: Vec<u8>) -> KeyCandidates {
        let len = mem.len() as u64;
        scan_memory(&mut Cursor::new(mem), &[(0, len)])
    }

    #[test]
    fn maps_include_readonly_names_and_ignore_unreadable_or_invalid_ranges() {
        let maps = "2000-3000 rw-p 0 00:00 0\n1000-2000 r--p 0 00:00 0\n\
                    3000-4000 r-xp 0 00:00 0\n4000-5000 ---p 0 00:00 0\n\
                    5000-4000 rw-p\ninvalid rw-p\n6000-6000 r--p\n";
        assert_eq!(
            parse_readable_maps(maps),
            vec![(0x1000, 0x2000), (0x2000, 0x3000), (0x3000, 0x4000)]
        );
    }

    #[test]
    fn issue7_extracts_xor_only_key_at_every_blob_phase() {
        for prefix in 0..32 {
            let keys = scan_bytes(fixture(prefix));
            assert!(keys.plain.is_empty());
            assert_eq!(
                keys.obfuscated,
                vec![("23".repeat(32), "ab".repeat(16))],
                "prefix={prefix}"
            );
        }
    }

    #[test]
    fn plaintext_scanning_still_finds_keys_across_chunk_boundaries() {
        let mut mem = vec![0u8; CHUNK_SIZE + 256];
        let literal = format!("x'{}{}'", "42".repeat(32), "cd".repeat(16));
        let start = CHUNK_SIZE - 30;
        mem[start..start + literal.len()].copy_from_slice(literal.as_bytes());
        let keys = scan_bytes(mem);
        assert_eq!(keys.plain, vec![("42".repeat(32), "cd".repeat(16))]);
        assert!(keys.obfuscated.is_empty());
    }

    #[test]
    fn finds_name_and_pointer_pair_across_chunks_without_alignment_assumptions() {
        let mut mem = vec![0u8; 2 * CHUNK_SIZE + 256];
        add_cipher(
            &mut mem,
            [CHUNK_SIZE - 15, 2 * CHUNK_SIZE - 12 - 0x10, CFG, BLOB],
            &"23".repeat(32),
            &"ab".repeat(16),
            17,
        );
        assert_eq!(scan_bytes(mem).obfuscated.len(), 1);
    }

    #[test]
    fn adjacent_readable_mappings_can_split_name_and_blob() {
        let mem = fixture(17);
        let regions = [(0, 0x110), (0x110, 0x610), (0x610, mem.len() as u64)];
        let keys = scan_memory(&mut Cursor::new(mem), &regions);
        assert_eq!(keys.obfuscated.len(), 1);
    }

    #[test]
    fn duplicate_names_and_nodes_do_not_duplicate_keys_or_hide_plaintext() {
        let mut mem = fixture(17);
        add_cipher(
            &mut mem,
            [0x140, 0x320, 0x800, 0xa00],
            &"23".repeat(32),
            &"ab".repeat(16),
            9,
        );
        // 第三个节点引用同一个 blob。
        put_u64(&mut mem, 0xb10, NAME as u64);
        put_u64(&mut mem, 0xb18, 30);
        put_u64(&mut mem, 0xb28, CFG as u64);
        let literal = format!("x'{}{}'", "42".repeat(32), "cd".repeat(16));
        mem[0xc00..0xc00 + literal.len()].copy_from_slice(literal.as_bytes());
        let keys = scan_bytes(mem);
        assert_eq!(keys.obfuscated, vec![("23".repeat(32), "ab".repeat(16))]);
        assert_eq!(keys.plain, vec![("42".repeat(32), "cd".repeat(16))]);
    }

    #[test]
    fn malformed_stale_and_oversized_pointers_are_ignored() {
        for (offset, value) in [
            (NODE + 0x10, 0),
            (NODE + 0x18, 29),
            (NODE + 0x28, 0),
            (NODE + 0x28, u64::MAX - 8),
            (NODE + 0x28, 0xffff),
            (CFG + 0x98, 0),
            (CFG + 0x98, 0xffff),
            (CFG + 0x98, u64::MAX - 8),
            (CFG + 0xa0, 0),
            (CFG + 0xa0, 98),
            (CFG + 0xa0, 1024 * 1024 + 1),
            (CFG + 0xa0, u64::MAX),
        ] {
            let mut mem = fixture(17);
            put_u64(&mut mem, offset, value);
            assert!(scan_bytes(mem).obfuscated.is_empty(), "offset={offset:x}");
        }
        let mut mem = fixture(17);
        mem.truncate(BLOB + 50);
        assert!(scan_bytes(mem).obfuscated.is_empty());
        let mut mem = Cursor::new(fixture(17));
        // blob 穿过一个不可读映射缺口。
        assert!(scan_memory(&mut mem, &[(0, 0x610), (0x620, 0x2000)])
            .obfuscated
            .is_empty());
    }

    struct InterruptedMemory {
        mem: Cursor<Vec<u8>>,
        max_read: usize,
        hole: (u64, u64),
    }

    impl Read for InterruptedMemory {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let pos = self.mem.position();
            if (self.hole.0..self.hole.1).contains(&pos) {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            let mut len = buf.len().min(self.max_read);
            if pos < self.hole.0 {
                len = len.min((self.hole.0 - pos) as usize);
            }
            self.mem.read(&mut buf[..len])
        }
    }

    impl Seek for InterruptedMemory {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.mem.seek(pos)
        }
    }

    #[test]
    fn short_reads_preserve_patterns_and_pointer_reads() {
        let mut mem = InterruptedMemory {
            mem: Cursor::new(fixture(17)),
            max_read: 7,
            hole: (0, 0),
        };
        let keys = scan_memory(&mut mem, &[(0, 0x2000)]);
        assert_eq!(keys.obfuscated.len(), 1);
    }

    #[test]
    fn unreadable_page_does_not_skip_later_keys_in_the_same_chunk() {
        let mut bytes = vec![0u8; 0x8000];
        add_cipher(
            &mut bytes,
            [0x3000, 0x4000, 0x5000, 0x6000],
            &"23".repeat(32),
            &"ab".repeat(16),
            17,
        );
        let mut mem = InterruptedMemory {
            mem: Cursor::new(bytes),
            max_read: CHUNK_SIZE,
            hole: (0x1000, 0x2000),
        };
        assert_eq!(scan_memory(&mut mem, &[(0, 0x8000)]).obfuscated.len(), 1);
    }

    fn encrypted_db(dir: &Path, name: &str, key: &str) -> String {
        let path = dir.join(name);
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch(&format!(
            "PRAGMA key = \"x'{key}'\"; CREATE TABLE sample(value TEXT); \
             INSERT INTO sample VALUES ('synthetic issue 7 fixture');"
        ))
        .unwrap();
        drop(db);
        super::super::read_db_salt(&path).unwrap()
    }

    #[test]
    fn recovered_keys_match_multiple_real_sqlcipher_databases_by_salt_and_hmac() {
        let dir = tempfile::tempdir().unwrap();
        let key1 = "23".repeat(32);
        let key2 = "42".repeat(32);
        let salt1 = encrypted_db(dir.path(), "one.db", &key1);
        let salt2 = encrypted_db(dir.path(), "two.db", &key2);
        let mut mem = vec![0u8; 0x2000];
        add_cipher(&mut mem, [NAME, NODE, CFG, BLOB], &key1, &salt1, 17);
        add_cipher(&mut mem, [0x140, 0x320, 0x800, 0xa00], &key2, &salt2, 7);
        let keys = scan_bytes(mem);
        assert!(keys.plain.is_empty());
        let salts = collect_db_salts(dir.path());
        let entries = match_obfuscated_keys(dir.path(), &keys.obfuscated, &salts);
        assert_eq!(entries.len(), 2);
        for entry in entries {
            let db = crate::crypto::sqlcipher::open_encrypted_readonly(
                &dir.path().join(&entry.db_name),
                &entry.enc_key,
            )
            .unwrap();
            let value: String = db
                .query_row("SELECT value FROM sample", [], |r| r.get(0))
                .unwrap();
            assert_eq!(value, "synthetic issue 7 fixture");
        }
        assert!(match_obfuscated_keys(dir.path(), &[(key2, salt1)], &salts).is_empty());
        assert!(match_obfuscated_keys(dir.path(), &[(key1, salt2)], &salts).is_empty());
    }

    #[test]
    fn corrupted_hmac_is_rejected_even_if_the_sqlite_header_decrypts() {
        let dir = tempfile::tempdir().unwrap();
        let key = "23".repeat(32);
        let salt = encrypted_db(dir.path(), "one.db", &key);
        let path = dir.path().join("one.db");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[4095] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        // 明文旧路径的头部回退仍成功，但 XOR 路径必须拒绝失败的 HMAC。
        assert!(crate::crypto::validate_raw_key_for_db(&path, &[0x23; 32]));
        let salts = collect_db_salts(dir.path());
        assert!(match_obfuscated_keys(dir.path(), &[(key, salt)], &salts).is_empty());
    }
}
