//! 媒体工具：语音等从本地加密库导出

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use crate::config;
use crate::crypto::sqlcipher;

/// 从 message/media_*.db 的 VoiceInfo 表按 svr_id 导出 voice_data。
pub fn cmd_voice_export(svr_id: i64, chat: Option<String>, output: String) -> Result<()> {
    let cfg = config::load_config().context("请先 wx init")?;
    let keys: serde_json::Value =
        serde_json::from_str(&crate::private_fs::read_private(&cfg.keys_file).context("读取密钥失败")?)?;

    // 候选 media 库
    let mut candidates: Vec<(PathBuf, String)> = Vec::new();
    for name in [
        "message/media_0.db",
        "message/media_1.db",
        "message/media_2.db",
        "message/media_3.db",
    ] {
        if let Some(key) = key_of(&keys, name) {
            let p = cfg.db_dir.join(name.replace('/', std::path::MAIN_SEPARATOR_STR));
            if p.exists() {
                candidates.push((p, key));
            }
        }
    }
    if candidates.is_empty() {
        bail!(
            "未找到带密钥的 media_*.db，请 {}",
            crate::config::RECOMMENDED_KEY_EXTRACT
        );
    }

    let out = PathBuf::from(&output);
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }

    for (path, key) in candidates {
        let conn = match sqlcipher::open_encrypted_readonly(&path, &key) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skip {}: {:#}", path.display(), e);
                continue;
            }
        };
        let has = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='VoiceInfo'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .is_ok();
        if !has {
            continue;
        }

        let blob: Option<Vec<u8>> = if let Some(ref chat_name) = chat {
            conn.query_row(
                "SELECT voice_data FROM VoiceInfo WHERE svr_id = ?1 AND chat_name_id = ?2 LIMIT 1",
                rusqlite::params![svr_id, chat_name],
                |r| r.get(0),
            )
            .ok()
            .or_else(|| {
                conn.query_row(
                    "SELECT voice_data FROM VoiceInfo WHERE svr_id = ?1 LIMIT 1",
                    [svr_id],
                    |r| r.get(0),
                )
                .ok()
            })
        } else {
            conn.query_row(
                "SELECT voice_data FROM VoiceInfo WHERE svr_id = ?1 LIMIT 1",
                [svr_id],
                |r| r.get(0),
            )
            .ok()
        };

        if let Some(data) = blob {
            if data.is_empty() {
                continue;
            }
            crate::private_fs::write_private(&out, &data)?;
            println!(
                "已导出 {} 字节 → {} (from {})",
                data.len(),
                out.display(),
                path.display()
            );
            return Ok(());
        }
    }

    bail!("未在 media_*.db 中找到 svr_id={}", svr_id);
}

fn key_of(keys: &serde_json::Value, rel: &str) -> Option<String> {
    let e = keys.get(rel)?;
    if let Some(s) = e.as_str() {
        return Some(s.to_string());
    }
    e.get("enc_key")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}
