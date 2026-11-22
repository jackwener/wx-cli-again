use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// 扫描到的一条密钥记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// 相对路径，如 "message/message_0.db"
    pub db_name: String,
    /// 32字节 AES 密钥（hex）
    pub enc_key: String,
    /// 16字节 salt（hex，来自数据库文件头）
    pub salt: String,
}

/// 从进程内存中扫描所有 SQLCipher 密钥
///
/// 需要以 root/Administrator 权限运行（macOS ad-hoc 包的 LLDB hook 路径除外）
#[allow(dead_code)] // 跨平台/外部入口保留；CLI 走 scan_keys_with_options
pub fn scan_keys(db_dir: &Path) -> Result<Vec<KeyEntry>> {
    scan_keys_with_options(db_dir, ScanOptions::default())
}

/// 密钥扫描选项（目前主要影响 macOS LLDB hook）
#[derive(Debug, Clone)]
pub struct ScanOptions<'a> {
    /// LLDB hook 等待秒数；0 表示禁用 hook
    pub hook_seconds: u64,
    /// 内存扫描未配齐时是否自动进入 hook
    pub auto_hook: bool,
    /// 已有仍有效的密钥（避免已配齐时仍进入 hook）
    pub known: &'a [KeyEntry],
}

impl Default for ScanOptions<'static> {
    fn default() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            hook_seconds: macos::DEFAULT_HOOK_SECONDS,
            #[cfg(not(target_os = "macos"))]
            hook_seconds: 0,
            auto_hook: true,
            known: &[],
        }
    }
}

pub fn scan_keys_with_options(db_dir: &Path, opts: ScanOptions<'_>) -> Result<Vec<KeyEntry>> {
    #[cfg(target_os = "macos")]
    return macos::scan_keys_with_options(db_dir, opts.hook_seconds, opts.auto_hook, opts.known);
    #[cfg(target_os = "linux")]
    {
        let _ = opts;
        return linux::scan_keys(db_dir);
    }
    #[cfg(target_os = "windows")]
    {
        let _ = opts;
        return windows::scan_keys(db_dir);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = opts;
        anyhow::bail!("当前平台不支持自动密钥扫描")
    }
}

/// 读取 DB 文件前 16 字节作为 salt（hex），如果是明文 SQLite 则返回 None
pub fn read_db_salt(path: &Path) -> Option<String> {
    let mut buf = [0u8; 16];
    let mut f = std::fs::File::open(path).ok()?;
    use std::io::Read;
    f.read_exact(&mut buf).ok()?;
    // 明文 SQLite：头部是 "SQLite format 3"
    if &buf[..15] == b"SQLite format 3" {
        return None;
    }
    Some(hex::encode(&buf))
}

/// 遍历 db_dir，收集所有 .db 文件的 salt -> 相对路径 映射
pub fn collect_db_salts(db_dir: &Path) -> Vec<(String, String)> {
    let mut result = Vec::new();
    collect_recursive(db_dir, db_dir, &mut result);
    result
}

/// 将内存中的候选 key 映射到实际数据库文件。
///
/// 旧版 WCDB 会把 `raw key + file salt` 连续保存在内存字符串里，因此 salt
/// 相同的候选优先尝试；最终仍以数据库第一页的 HMAC/解密结果为准。新版构建即使
/// 不再保留 key/salt 邻接关系，也能从其余候选中找到对应 key。
#[allow(dead_code)] // Linux/Windows 扫描器使用；macOS 走 match_key_hexes
pub(crate) fn match_raw_keys(
    db_dir: &Path,
    raw_keys: &[(String, String)],
    db_salts: &[(String, String)],
) -> Vec<KeyEntry> {
    let pure_keys: Vec<String> = unique_key_hexes(raw_keys);
    match_key_hexes(db_dir, &pure_keys, raw_keys, db_salts)
}

/// 用一组候选 32-byte key（hex）去匹配数据库。
///
/// `raw_keys` 可选：若提供，会优先尝试 salt 与 DB 相同的候选。
pub(crate) fn match_key_hexes(
    db_dir: &Path,
    key_hexes: &[String],
    raw_keys: &[(String, String)],
    db_salts: &[(String, String)],
) -> Vec<KeyEntry> {
    let mut entries = Vec::new();

    for (db_salt, db_name) in db_salts {
        let db_path = db_dir.join(db_name);
        let mut seen_keys = std::collections::HashSet::new();

        // 1) salt 配对优先（x'key+salt' 模式的传统路径）
        let salt_matched = raw_keys
            .iter()
            .filter(|(_, candidate_salt)| candidate_salt == db_salt)
            .map(|(k, _)| k.as_str());
        // 2) 其余候选（含 hook / salt-adjacent 提取到的纯 key）
        let rest = key_hexes.iter().map(|k| k.as_str());

        for key_hex in salt_matched.chain(rest) {
            if !seen_keys.insert(key_hex.to_string()) {
                continue;
            }
            let Some(key) = decode_key_hex(key_hex) else {
                continue;
            };
            if crate::crypto::validate_raw_key_for_db(&db_path, &key) {
                entries.push(KeyEntry {
                    db_name: db_name.clone(),
                    enc_key: key_hex.to_string(),
                    salt: db_salt.clone(),
                });
                break;
            }
        }
    }

    entries
}

/// 从 `(key_hex, salt_hex)` 列表提取去重后的 key。
pub(crate) fn unique_key_hexes(raw_keys: &[(String, String)]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (k, _) in raw_keys {
        if k.len() == 64 && seen.insert(k.clone()) {
            out.push(k.clone());
        }
    }
    out
}

/// 合并两批 KeyEntry：同名 DB 以 `primary` 优先，缺失的用 `fallback` 补齐。
pub fn merge_key_entries(primary: &[KeyEntry], fallback: &[KeyEntry]) -> Vec<KeyEntry> {
    let mut map = std::collections::BTreeMap::new();
    for e in fallback {
        map.insert(e.db_name.clone(), e.clone());
    }
    for e in primary {
        map.insert(e.db_name.clone(), e.clone());
    }
    map.into_values().collect()
}

/// 磁盘上存在但尚未拿到密钥的加密 DB（含文件大小，按严重度排序）。
#[derive(Debug, Clone)]
pub struct MissingDb {
    /// 相对 `db_dir` 的路径（正斜杠）
    pub rel: String,
    /// 文件字节数；无法 stat 时为 0
    pub size: u64,
}

/// 列出磁盘上存在但尚未拿到密钥的加密 `.db` 相对路径。
pub fn missing_encrypted_dbs(db_dir: &Path, known: &[KeyEntry]) -> Vec<String> {
    list_missing_encrypted_dbs(db_dir, known)
        .into_iter()
        .map(|m| m.rel)
        .collect()
}

/// 列出缺失密钥的加密 DB，附大小；**聊天分片优先**，其次按 size 降序。
pub fn list_missing_encrypted_dbs(db_dir: &Path, known: &[KeyEntry]) -> Vec<MissingDb> {
    let known_names: std::collections::HashSet<&str> =
        known.iter().map(|e| e.db_name.as_str()).collect();
    let mut out: Vec<MissingDb> = collect_db_salts(db_dir)
        .into_iter()
        .map(|(_, name)| name)
        .filter(|name| !known_names.contains(name.as_str()))
        .map(|rel| {
            let size = std::fs::metadata(db_dir.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR)))
                .map(|m| m.len())
                .unwrap_or(0);
            MissingDb { rel, size }
        })
        .collect();
    out.sort_by(|a, b| {
        missing_db_rank(&a.rel)
            .cmp(&missing_db_rank(&b.rel))
            .then_with(|| b.size.cmp(&a.size))
            .then_with(|| a.rel.cmp(&b.rel))
    });
    out
}

/// `message/message_<N>.db` 聊天历史分片（影响 history/sessions 完整性）。
pub fn is_chat_message_shard(rel: &str) -> bool {
    let n = rel.replace('\\', "/");
    let Some(name) = n.strip_prefix("message/") else {
        return false;
    };
    let Some(rest) = name.strip_prefix("message_") else {
        return false;
    };
    let Some(num) = rest.strip_suffix(".db") else {
        return false;
    };
    !num.is_empty() && num.chars().all(|c| c.is_ascii_digit())
}

/// 缺失时是否应判定为「健康检查失败」（聊天分片 / 核心库）。
/// `migrate/*` 等旁路库缺失不阻断日常查询。
pub fn is_critical_missing_db(rel: &str) -> bool {
    let n = rel.replace('\\', "/");
    if is_chat_message_shard(&n) {
        return true;
    }
    matches!(
        n.as_str(),
        "session/session.db"
            | "contact/contact.db"
            | "message/message_fts.db"
            | "message/media_0.db"
    ) || n.starts_with("message/biz_message_")
}

/// 排序键：数字越小越优先展示 / 处理。
pub fn missing_db_rank(rel: &str) -> u8 {
    let n = rel.replace('\\', "/");
    if is_chat_message_shard(&n) {
        0
    } else if n.starts_with("message/") || n.starts_with("session/") || n.starts_with("contact/") {
        1
    } else if n.starts_with("migrate/") {
        9
    } else {
        5
    }
}

/// 人类可读的体积（B / KB / MB）。
pub fn format_db_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}B")
    }
}

pub(crate) fn decode_key_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).ok()?;
        key[index] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(key)
}

/// 公开给 init 等模块复用的 hex → 32-byte key 解码。
pub fn decode_key_hex_pub(value: &str) -> Option<[u8; 32]> {
    decode_key_hex(value)
}

/// 把 16 字节 salt 的 hex 解码为原始字节。
pub(crate) fn decode_salt_hex(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut salt = [0u8; 16];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).ok()?;
        salt[index] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(salt)
}

/// Windows `PAGE_*` base protect（不含 modifier）。与 WinNT.h 一致，便于跨平台单测。
/// 非 Windows 构建里仅测试引用；生产路径在 `scanner/windows.rs`。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WIN_PAGE_READWRITE: u32 = 0x04;
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WIN_PAGE_WRITECOPY: u32 = 0x08;
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WIN_PAGE_EXECUTE_READWRITE: u32 = 0x40;
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WIN_PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WIN_PAGE_GUARD: u32 = 0x100;
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WIN_PAGE_NOCACHE: u32 = 0x200;
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WIN_PAGE_WRITECOMBINE: u32 = 0x400;

/// 判断 Windows 页面保护是否可读可写（剥离 GUARD/NOCACHE/WRITECOMBINE 后比 base）。
///
/// 从 old-main #54 捞回：仅匹配 `PAGE_READWRITE` 会漏掉 WRITECOPY /
/// EXECUTE_READWRITE 等同样含密钥的堆页。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn is_writable_readable_page(protect: u32) -> bool {
    let base = protect & !(WIN_PAGE_GUARD | WIN_PAGE_NOCACHE | WIN_PAGE_WRITECOMBINE);
    matches!(
        base,
        x if x == WIN_PAGE_READWRITE
            || x == WIN_PAGE_WRITECOPY
            || x == WIN_PAGE_EXECUTE_READWRITE
            || x == WIN_PAGE_EXECUTE_WRITECOPY
    )
}

/// `x'<64hex_key><32hex_salt>'` 模式的最大字节长度（含前后引号）。
pub(crate) const MAX_PATTERN_BYTES: usize = 99; // x' + 96 hex + '
const HEX_PATTERN_LEN: usize = 96; // 64(key) + 32(salt)

/// 微信 4.1+（Linux 4.1.x / macOS 4.2.x 等）在 `WCDB.Config.Cipher` 中对 99 字节
/// `x'<64hex_key><32hex_salt>'` 字面量使用的固定 32 字节循环 XOR 掩码。
const WCDB_CIPHER_XOR_MASK: [u8; 32] = [
    0xd2, 0xc7, 0x44, 0x24, 0x58, 0x02, 0x00, 0x00,
    0x00, 0x48, 0x89, 0x44, 0x24, 0x50, 0x48, 0x8b,
    0x45, 0x00, 0x48, 0x84, 0x4c, 0x24, 0x48, 0x48,
    0x89, 0x44, 0x25, 0x40, 0x48, 0x58, 0x4c, 0x24,
];
const XOR_PREFIX_0: u8 = b'x' ^ WCDB_CIPHER_XOR_MASK[0];
const XOR_PREFIX_1: u8 = b'\'' ^ WCDB_CIPHER_XOR_MASK[1];
const XOR_SUFFIX: u8 = b'\'' ^ WCDB_CIPHER_XOR_MASK[(MAX_PATTERN_BYTES - 1) % 32];

fn decode_xhex_pattern(window: &[u8], mask: Option<&[u8; 32]>) -> Option<(String, String)> {
    debug_assert_eq!(window.len(), MAX_PATTERN_BYTES);
    let mut lower_hex = [0u8; HEX_PATTERN_LEN];
    for (j, out) in lower_hex.iter_mut().enumerate() {
        let m = mask.map_or(0, |k| k[(2 + j) % k.len()]);
        let ch = window[2 + j] ^ m;
        if !ch.is_ascii_hexdigit() {
            return None;
        }
        *out = ch.to_ascii_lowercase();
    }

    let key_hex = String::from_utf8_lossy(&lower_hex[..64]).into_owned();
    let salt_hex = String::from_utf8_lossy(&lower_hex[64..96]).into_owned();
    Some((key_hex, salt_hex))
}

fn push_unique_key_pattern(results: &mut Vec<(String, String)>, (key_hex, salt_hex): (String, String)) {
    if !results.iter().any(|(k, s)| k == &key_hex && s == &salt_hex) {
        results.push((key_hex, salt_hex));
    }
}

/// 在缓冲区中搜索 WCDB 缓存的 `x'<key><salt>'` 字符串模式（兼容明文及 4.1+ XOR 混淆）。
pub(crate) fn scan_key_patterns(buf: &[u8], results: &mut Vec<(String, String)>) {
    let total = MAX_PATTERN_BYTES;
    if buf.len() < total {
        return;
    }

    let mut i = 0;
    while i + total <= buf.len() {
        let end = i + total;
        let matched = if buf[i] == b'x' && buf[i + 1] == b'\'' && buf[end - 1] == b'\'' {
            decode_xhex_pattern(&buf[i..end], None)
        } else if buf[i] == XOR_PREFIX_0
            && buf[i + 1] == XOR_PREFIX_1
            && buf[end - 1] == XOR_SUFFIX
        {
            decode_xhex_pattern(&buf[i..end], Some(&WCDB_CIPHER_XOR_MASK))
        } else {
            None
        };

        if let Some(pair) = matched {
            push_unique_key_pattern(results, pair);
            i += total;
        } else {
            i += 1;
        }
    }
}

/// 在缓冲区中寻找与已知 DB salt 相邻的 32 字节 binary key。
///
/// 微信 4.x 每个 DB 使用独立 AES-256 key；密钥材料常以「key || salt」或
/// 「salt || key」形式出现在堆上（不一定是 `x'<hex>'` 字符串）。
pub(crate) fn collect_salt_adjacent_keys(
    buf: &[u8],
    salts: &[[u8; 16]],
    out_keys: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
) {
    if salts.is_empty() || buf.len() < 48 {
        return;
    }
    // 关键偏移：key 紧邻 salt，以及常见的 8/16 字节对齐填充
    const BEFORE: [usize; 3] = [32, 40, 48];
    const AFTER: [usize; 3] = [0, 8, 16];

    for salt in salts {
        let mut start = 0usize;
        while start + 16 <= buf.len() {
            // 简单 memmem：找 salt
            if let Some(rel) = find_slice(&buf[start..], salt) {
                let i = start + rel;
                for off in BEFORE {
                    if i >= off {
                        push_raw_key(&buf[i - off..i - off + 32], out_keys, seen);
                    }
                }
                for off in AFTER {
                    let kstart = i + 16 + off;
                    if kstart + 32 <= buf.len() {
                        push_raw_key(&buf[kstart..kstart + 32], out_keys, seen);
                    }
                }
                start = i + 1;
            } else {
                break;
            }
        }
    }
}

fn find_slice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn push_raw_key(
    key: &[u8],
    out_keys: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
) {
    if key.len() != 32 {
        return;
    }
    // 过滤明显不是密钥的全零 / 低熵块
    if key.iter().all(|&b| b == 0) || key.iter().all(|&b| b == key[0]) {
        return;
    }
    let hex = key.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    if seen.insert(hex.clone()) {
        out_keys.push(hex);
    }
}

fn collect_recursive(base: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_recursive(base, &path, out);
        } else if path.extension().map(|e| e == "db").unwrap_or(false) {
            if let Some(salt) = read_db_salt(&path) {
                if let Ok(rel) = path.strip_prefix(base) {
                    let rel_str = rel.to_string_lossy().replace('\\', "/");
                    out.push((salt, rel_str));
                }
            }
        }
    }
}

// hex encoding helper (avoid adding hex crate by implementing inline)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// 创建一个进程唯一的临时目录（测试用），返回路径；测试结束后调用方负责删除
    fn make_temp_dir(label: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        // 用 label + thread id 保证同进程内并发测试不冲突
        p.push(format!(
            "wx-cli-test-{}-{:?}",
            label,
            std::thread::current().id()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    // ── read_db_salt ──────────────────────────────────────────────────────────

    #[test]
    fn test_read_db_salt_plaintext_sqlite() {
        let dir = make_temp_dir("salt-plain");
        let path = dir.join("plain.db");
        // 明文 SQLite 头：前 15 字节是 "SQLite format 3"
        let mut content = b"SQLite format 3\x00".to_vec();
        content.extend_from_slice(&[0u8; 100]);
        fs::write(&path, &content).unwrap();

        assert!(read_db_salt(&path).is_none(), "明文 SQLite 应返回 None");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_read_db_salt_encrypted() {
        let dir = make_temp_dir("salt-enc");
        let path = dir.join("enc.db");
        // 非 SQLite 头 → 视为加密数据库，取前 16 字节作为 salt
        let header: [u8; 16] = [
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c,
        ];
        fs::write(&path, &header).unwrap();

        let salt = read_db_salt(&path).expect("加密 DB 应返回 Some");
        assert_eq!(salt, "deadbeef0102030405060708090a0b0c");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_read_db_salt_too_short() {
        let dir = make_temp_dir("salt-short");
        let path = dir.join("short.db");
        fs::write(&path, b"tooshort").unwrap(); // < 16 bytes

        assert!(read_db_salt(&path).is_none(), "文件太短应返回 None");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_read_db_salt_nonexistent() {
        assert!(read_db_salt(Path::new("/nonexistent/surely/not/here.db")).is_none());
    }

    #[test]
    fn test_read_db_salt_exactly_16_bytes() {
        let dir = make_temp_dir("salt-16");
        let path = dir.join("exact.db");
        let header = [0xabu8; 16];
        fs::write(&path, &header).unwrap();

        let salt = read_db_salt(&path).unwrap();
        // 0xab × 16 → "ab" × 16 = 32 chars
        assert_eq!(salt, "ab".repeat(16));
        fs::remove_dir_all(&dir).ok();
    }

    // ── collect_db_salts ──────────────────────────────────────────────────────

    #[test]
    fn test_collect_db_salts_empty_dir() {
        let dir = make_temp_dir("collect-empty");
        let salts = collect_db_salts(&dir);
        assert!(salts.is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_collect_db_salts_skips_plaintext_sqlite() {
        let dir = make_temp_dir("collect-plain");
        let mut content = b"SQLite format 3\x00".to_vec();
        content.extend_from_slice(&[0u8; 100]);
        fs::write(dir.join("plain.db"), &content).unwrap();

        assert!(collect_db_salts(&dir).is_empty(), "明文 SQLite 应被跳过");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_collect_db_salts_finds_encrypted() {
        let dir = make_temp_dir("collect-enc");
        let header = [0x11u8; 16];
        fs::write(dir.join("msg.db"), &header).unwrap();

        let salts = collect_db_salts(&dir);
        assert_eq!(salts.len(), 1);
        assert_eq!(salts[0].0, "11".repeat(16)); // 0x11 × 16 → "11" × 16
        assert_eq!(salts[0].1, "msg.db");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_collect_db_salts_recursive() {
        let dir = make_temp_dir("collect-rec");
        let subdir = dir.join("sub");
        fs::create_dir_all(&subdir).unwrap();

        let header = [0xaau8; 16];
        fs::write(dir.join("root.db"), &header).unwrap();
        fs::write(subdir.join("nested.db"), &header).unwrap();
        fs::write(dir.join("ignored.txt"), b"text file").unwrap();

        let salts = collect_db_salts(&dir);
        assert_eq!(salts.len(), 2, "应递归找到 2 个加密 .db");

        let names: Vec<&str> = salts.iter().map(|(_, n)| n.as_str()).collect();
        assert!(names.contains(&"root.db"));
        assert!(names.contains(&"sub/nested.db"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_collect_db_salts_ignores_non_db_extensions() {
        let dir = make_temp_dir("collect-ext");
        let header = [0xbbu8; 16];
        fs::write(dir.join("data.txt"), &header).unwrap();
        fs::write(dir.join("data.json"), &header).unwrap();
        fs::write(dir.join("data.sqlite"), &header).unwrap();

        assert!(collect_db_salts(&dir).is_empty(), "非 .db 文件应被忽略");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_collect_db_salts_multiple_files_unique_salts() {
        let dir = make_temp_dir("collect-multi");
        fs::write(dir.join("a.db"), &[0x11u8; 16]).unwrap();
        fs::write(dir.join("b.db"), &[0x22u8; 16]).unwrap();
        fs::write(dir.join("c.db"), &[0x33u8; 16]).unwrap();

        let salts = collect_db_salts(&dir);
        assert_eq!(salts.len(), 3);

        let salt_vals: std::collections::HashSet<&str> =
            salts.iter().map(|(s, _)| s.as_str()).collect();
        assert!(salt_vals.contains("11".repeat(16).as_str()));
        assert!(salt_vals.contains("22".repeat(16).as_str()));
        assert!(salt_vals.contains("33".repeat(16).as_str()));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_decode_key_hex() {
        let key = decode_key_hex(&"ab".repeat(32)).unwrap();
        assert_eq!(key, [0xabu8; 32]);
        assert!(decode_key_hex("not-a-key").is_none());
        assert!(decode_key_hex(&"gg".repeat(32)).is_none());
    }

    #[test]
    fn writable_readable_page_accepts_common_rw_bases() {
        assert!(is_writable_readable_page(WIN_PAGE_READWRITE));
        assert!(is_writable_readable_page(WIN_PAGE_WRITECOPY));
        assert!(is_writable_readable_page(WIN_PAGE_EXECUTE_READWRITE));
        assert!(is_writable_readable_page(WIN_PAGE_EXECUTE_WRITECOPY));
        // modifier bits must not hide a writable base
        assert!(is_writable_readable_page(WIN_PAGE_READWRITE | WIN_PAGE_GUARD));
        assert!(is_writable_readable_page(
            WIN_PAGE_WRITECOPY | WIN_PAGE_NOCACHE | WIN_PAGE_WRITECOMBINE
        ));
    }

    #[test]
    fn writable_readable_page_rejects_readonly_and_execute_only() {
        const PAGE_READONLY: u32 = 0x02;
        const PAGE_EXECUTE: u32 = 0x10;
        const PAGE_EXECUTE_READ: u32 = 0x20;
        assert!(!is_writable_readable_page(PAGE_READONLY));
        assert!(!is_writable_readable_page(PAGE_EXECUTE));
        assert!(!is_writable_readable_page(PAGE_EXECUTE_READ));
        assert!(!is_writable_readable_page(0));
    }

    #[test]
    fn chat_message_shard_classifier() {
        assert!(is_chat_message_shard("message/message_0.db"));
        assert!(is_chat_message_shard("message/message_12.db"));
        assert!(is_chat_message_shard(r"message\message_1.db"));
        assert!(!is_chat_message_shard("message/message_fts.db"));
        assert!(!is_chat_message_shard("message/message_resource.db"));
        assert!(!is_chat_message_shard("message/biz_message_0.db"));
        assert!(!is_chat_message_shard("migrate/unspportmsg.db"));
        assert!(!is_chat_message_shard("session/session.db"));
    }

    #[test]
    fn critical_missing_vs_optional() {
        assert!(is_critical_missing_db("message/message_1.db"));
        assert!(is_critical_missing_db("session/session.db"));
        assert!(is_critical_missing_db("message/message_fts.db"));
        assert!(!is_critical_missing_db("migrate/unspportmsg.db"));
        assert!(!is_critical_missing_db("solitaire/solitaire.db"));
    }

    #[test]
    fn missing_db_rank_orders_chat_first() {
        assert!(missing_db_rank("message/message_2.db") < missing_db_rank("message/media_0.db"));
        assert!(missing_db_rank("message/media_0.db") < missing_db_rank("migrate/x.db"));
    }

    #[test]
    fn format_db_size_human() {
        assert_eq!(format_db_size(500), "500B");
        assert_eq!(format_db_size(2048), "2.0KB");
        assert_eq!(format_db_size(2 * 1024 * 1024), "2.0MB");
    }

    #[test]
    fn list_missing_sorted_by_rank_and_size() {
        let dir = make_temp_dir("missing-sort");
        let msg = dir.join("message");
        fs::create_dir_all(&msg).unwrap();
        let mig = dir.join("migrate");
        fs::create_dir_all(&mig).unwrap();
        // encrypted headers (non-SQLite magic)
        let big = [0xAAu8; 16];
        let small = [0xBBu8; 16];
        let mid = [0xCCu8; 16];
        fs::write(msg.join("message_1.db"), {
            let mut v = big.to_vec();
            v.extend(vec![1u8; 1000]);
            v
        })
        .unwrap();
        fs::write(msg.join("message_2.db"), {
            let mut v = mid.to_vec();
            v.extend(vec![1u8; 100]);
            v
        })
        .unwrap();
        fs::write(mig.join("unspportmsg.db"), {
            let mut v = small.to_vec();
            v.extend(vec![1u8; 50]);
            v
        })
        .unwrap();

        let known = vec![KeyEntry {
            db_name: "message/message_2.db".into(),
            enc_key: "00".repeat(32),
            salt: String::new(),
        }];
        let miss = list_missing_encrypted_dbs(&dir, &known);
        assert_eq!(miss.len(), 2);
        assert_eq!(miss[0].rel, "message/message_1.db");
        assert_eq!(miss[1].rel, "migrate/unspportmsg.db");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_key_patterns_finds_xhex() {
        let key = "aa".repeat(32);
        let salt = "bb".repeat(16);
        let mut buf = b"noise".to_vec();
        buf.extend(format!("x'{key}{salt}'").into_bytes());
        buf.extend(b"tail");
        let mut results = Vec::new();
        scan_key_patterns(&buf, &mut results);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, key);
        assert_eq!(results[0].1, salt);
    }

    fn xor_encode_pattern(pattern: &[u8]) -> Vec<u8> {
        pattern
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ WCDB_CIPHER_XOR_MASK[i % WCDB_CIPHER_XOR_MASK.len()])
            .collect()
    }

    #[test]
    fn scan_key_patterns_finds_xor_obfuscated_xhex() {
        let key = "0123456789abcdef".repeat(4);
        let salt = "fedcba9876543210".repeat(2);
        let plain = format!("x'{key}{salt}'");
        let mut buf = vec![0x7au8; 17];
        buf.extend(xor_encode_pattern(plain.as_bytes()));
        buf.extend_from_slice(&[0xffu8; 19]);
        let mut results = Vec::new();
        scan_key_patterns(&buf, &mut results);
        assert_eq!(results, vec![(key, salt)]);
    }

    #[test]
    fn scan_key_patterns_xor_normalizes_uppercase_and_dedups_with_plaintext() {
        let key = "a1b2c3d4e5f60718".repeat(4);
        let salt = "89abcdef01234567".repeat(2);
        let upper_plain = format!("x'{}{}'", key.to_ascii_uppercase(), salt.to_ascii_uppercase());
        let mut buf = xor_encode_pattern(upper_plain.as_bytes());
        buf.extend_from_slice(b"sep");
        buf.extend(format!("x'{key}{salt}'").into_bytes());
        let mut results = Vec::new();
        scan_key_patterns(&buf, &mut results);
        assert_eq!(results, vec![(key, salt)]);
    }

    #[test]
    fn scan_key_patterns_xor_rejects_invalid_hex_and_suffix() {
        let key = "ab".repeat(32);
        let salt = "cd".repeat(16);
        let valid = format!("x'{key}{salt}'");

        let mut bad_hex = valid.as_bytes().to_vec();
        bad_hex[10] = b'g';
        let mut results = Vec::new();
        scan_key_patterns(&xor_encode_pattern(&bad_hex), &mut results);
        assert!(results.is_empty());

        let mut bad_suffix = valid.into_bytes();
        bad_suffix[MAX_PATTERN_BYTES - 1] = b'"';
        let mut results = Vec::new();
        scan_key_patterns(&xor_encode_pattern(&bad_suffix), &mut results);
        assert!(results.is_empty());
    }

    #[test]
    fn scan_key_patterns_finds_mixed_plaintext_and_xor() {
        let key1 = "11".repeat(32);
        let salt1 = "22".repeat(16);
        let key2 = "33".repeat(32);
        let salt2 = "44".repeat(16);
        let mut buf = format!("x'{key1}{salt1}'").into_bytes();
        buf.extend_from_slice(&[0x00u8; 13]);
        buf.extend(xor_encode_pattern(format!("x'{key2}{salt2}'").as_bytes()));
        let mut results = Vec::new();
        scan_key_patterns(&buf, &mut results);
        assert_eq!(results, vec![(key1, salt1), (key2, salt2)]);
    }

    #[test]
    fn salt_adjacent_picks_key_before_salt() {
        let salt = [0x11u8; 16];
        // non-uniform key (all-same bytes are filtered as low-entropy)
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        let mut buf = key.to_vec();
        buf.extend_from_slice(&salt);
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        collect_salt_adjacent_keys(&buf, &[salt], &mut out, &mut seen);
        let expect = key.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert!(out.iter().any(|h| h == &expect), "got {out:?}");
    }
}
