//! 用 SQLCipher 在线打开微信加密数据库（无需 full_decrypt）。
//!
//! 密钥来自 all_keys.json 的 32-byte raw page key（与我们的 AES 页解密一致）。
//! keyspec 使用 SQLCipher raw-key 语法：`x'<64hex>'`（跳过 PBKDF2）。

use anyhow::{bail, Context, Result};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// 用 32-byte hex 密钥只读打开加密 DB。
///
/// 成功后会探测 `sqlite_master` 校验密钥正确。
pub fn open_encrypted_readonly(path: &Path, key_hex: &str) -> Result<Connection> {
    if key_hex.len() != 64 || !key_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("SQLCipher key 必须是 64 位 hex，实际 len={}", key_hex.len());
    }
    if !path.exists() {
        bail!("数据库不存在: {}", path.display());
    }

    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("打开加密 DB 失败: {}", path.display()))?;

    // Prefer raw key only (matches our page-AES keys). Fall back to key||salt
    // for SQLCipher builds that expect the salt-suffixed form.
    let key_only = format!("x'{}'", key_hex.to_lowercase());
    if try_apply_key(&conn, &key_only).is_ok() {
        let _ = conn.execute_batch("PRAGMA query_only = ON");
        return Ok(conn);
    }

    let salt_hex = read_salt_hex(path).unwrap_or_default();
    if salt_hex.len() == 32 {
        let key_salt = format!("x'{}{}'", key_hex.to_lowercase(), salt_hex);
        try_apply_key(&conn, &key_salt)
            .with_context(|| format!("SQLCipher 密钥不匹配: {}", path.display()))?;
    } else {
        bail!("SQLCipher 密钥不匹配: {}", path.display());
    }

    let _ = conn.execute_batch("PRAGMA query_only = ON");
    Ok(conn)
}

fn try_apply_key(conn: &Connection, keyspec: &str) -> Result<()> {
    let bytes = keyspec.as_bytes();
    // SAFETY: sqlite3_key is provided by SQLCipher; keyspec is a valid UTF-8 buffer
    // owned by us for the duration of the call.
    let rc = unsafe {
        rusqlite::ffi::sqlite3_key(
            conn.handle(),
            bytes.as_ptr() as *const std::ffi::c_void,
            bytes.len() as i32,
        )
    };
    if rc != 0 {
        bail!("sqlite3_key rc={}", rc);
    }
    // Probe: wrong key → SQLITE_NOTADB / error on first read
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
        .context("incorrect key or not SQLCipher DB")?;
    Ok(())
}

fn read_salt_hex(path: &Path) -> Option<String> {
    let mut buf = [0u8; 16];
    let mut f = std::fs::File::open(path).ok()?;
    use std::io::Read;
    f.read_exact(&mut buf).ok()?;
    Some(buf.iter().map(|b| format!("{:02x}", b)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_key_len() {
        let err = open_encrypted_readonly(Path::new("/nonexistent"), "abcd").unwrap_err();
        assert!(err.to_string().contains("64"));
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn bundled_database_engine_contains_wal_page_size_fix() {
        assert!(rusqlite::version_number() >= 3_054_000);
        let conn = Connection::open_in_memory().unwrap();
        let cipher: String = conn.query_row("PRAGMA cipher_version", [], |r| r.get(0)).unwrap();
        assert!(!cipher.is_empty(), "the build must still use SQLCipher");
    }

    #[test]
    fn upgraded_sqlcipher_reads_raw_keys_and_live_wal_without_allowing_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("encrypted.db");
        let key = "23".repeat(32);
        let writer = Connection::open(&path).unwrap();
        writer.execute_batch(&format!(
            "PRAGMA key = \"x'{}'\"; PRAGMA journal_mode = WAL;              CREATE TABLE messages(body TEXT); INSERT INTO messages VALUES ('synthetic message');", key
        )).unwrap();
        let reader = open_encrypted_readonly(&path, &key).unwrap();
        let body: String = reader.query_row("SELECT body FROM messages", [], |r| r.get(0)).unwrap();
        assert_eq!(body, "synthetic message");
        assert!(reader.execute("INSERT INTO messages VALUES ('must not write')", []).is_err());
        assert!(open_encrypted_readonly(&path, &"42".repeat(32)).is_err());
        assert!(!std::fs::read(&path).unwrap().starts_with(b"SQLite format 3"));
    }
}
