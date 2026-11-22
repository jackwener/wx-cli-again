//! `wx key` — 密钥管理（extract / list / set）

use anyhow::{bail, Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use crate::config;
use crate::scanner::{self, KeyEntry};

pub fn cmd_key_list(json: bool, show_secrets: bool) -> Result<()> {
    let cfg = config::load_config().context("请先 wx init")?;
    let content = crate::private_fs::read_private(&cfg.keys_file)
        .with_context(|| format!("读取 {}", cfg.keys_file.display()))?;
    let v: serde_json::Value = serde_json::from_str(&content)?;
    let mut known = Vec::new();
    let mut rows = Vec::new();
    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            if k.starts_with('_') {
                continue;
            }
            let enc = val
                .as_str()
                .map(|s| s.to_string())
                .or_else(|| {
                    val.get("enc_key")
                        .and_then(|e| e.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_default();
            if enc.is_empty() {
                continue;
            }
            let preview = format!("{}…", &enc[..enc.len().min(12)]);
            known.push(KeyEntry {
                db_name: k.replace('\\', "/"),
                enc_key: enc.clone(),
                salt: String::new(),
            });
            if show_secrets {
                rows.push(json!({
                    "db": k,
                    "enc_key": enc,
                    "preview": preview,
                }));
            } else {
                rows.push(json!({
                    "db": k,
                    "preview": preview,
                }));
            }
        }
    }
    rows.sort_by(|a, b| {
        a["db"]
            .as_str()
            .unwrap_or("")
            .cmp(b["db"].as_str().unwrap_or(""))
    });

    let missing = scanner::list_missing_encrypted_dbs(&cfg.db_dir, &known);
    let critical: Vec<_> = missing
        .iter()
        .filter(|m| scanner::is_critical_missing_db(&m.rel))
        .cloned()
        .collect();
    let optional: Vec<_> = missing
        .iter()
        .filter(|m| !scanner::is_critical_missing_db(&m.rel))
        .cloned()
        .collect();

    if json {
        let miss_json: Vec<_> = missing
            .iter()
            .map(|m| {
                json!({
                    "db": m.rel,
                    "size": m.size,
                    "size_human": scanner::format_db_size(m.size),
                    "critical": scanner::is_critical_missing_db(&m.rel),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "count": rows.len(),
                "keys": rows,
                "missing": miss_json,
                "critical_missing": critical.len(),
                "optional_missing": optional.len(),
            }))?
        );
    } else {
        println!("密钥文件: {}", cfg.keys_file.display());
        println!("数据目录: {}", cfg.db_dir.display());
        println!("共 {} 个密钥", rows.len());
        for r in &rows {
            println!(
                "  {}  {}",
                r["db"].as_str().unwrap_or(""),
                r["preview"].as_str().unwrap_or("")
            );
        }
        if !show_secrets {
            println!("（完整 enc_key 需 --show-secrets）");
        }
        if !critical.is_empty() {
            println!(
                "\n✗ 关键缺失 {} 个（影响聊天完整性）：",
                critical.len()
            );
            for m in &critical {
                println!(
                    "  · {} ({})",
                    m.rel,
                    scanner::format_db_size(m.size)
                );
            }
            println!(
                "补齐：{}\n\
                 等待期间在微信中打开相关聊天。",
                config::RECOMMENDED_KEY_EXTRACT
            );
        } else if !missing.is_empty() {
            println!("\n✓ 关键聊天分片密钥齐全");
        } else {
            println!("\n✓ 磁盘加密 DB 均已覆盖");
        }
        if !optional.is_empty() {
            println!("旁路/可选缺失 {} 个：", optional.len());
            for m in optional.iter().take(6) {
                println!(
                    "  · {} ({})",
                    m.rel,
                    scanner::format_db_size(m.size)
                );
            }
        }
    }
    Ok(())
}

pub fn cmd_key_set(db_name: &str, enc_key: &str) -> Result<()> {
    let key = enc_key.trim().to_lowercase();
    if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("enc_key 必须是 64 位 hex");
    }
    let cfg = config::load_config().context("请先 wx init")?;
    let mut map: BTreeMap<String, serde_json::Value> = if cfg.keys_file.exists() {
        let content = crate::private_fs::read_private(&cfg.keys_file)?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        BTreeMap::new()
    };
    let rel = db_name.replace('\\', "/");
    // validate if file exists
    let path = cfg.db_dir.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
    if path.exists() {
        if let Some(raw) = scanner::decode_key_hex_pub(&key) {
            if !crate::crypto::validate_raw_key_for_db(&path, &raw) {
                bail!("密钥无法解密 {}，请确认 hex 正确", rel);
            }
        }
    }
    map.insert(rel.clone(), json!({ "enc_key": key }));
    crate::private_fs::ensure_private_dir(&config::cli_dir())?;
    crate::private_fs::write_private(&cfg.keys_file, serde_json::to_string_pretty(&map)?)?;
    println!("已写入密钥: {} → {}", rel, cfg.keys_file.display());
    // try hot-reload（会 invalidate 解密缓存）
    match super::transport::send(crate::ipc::Request::ReloadConfig) {
        Ok(resp) if resp.ok => {
            println!(
                "已热重载 daemon 配置（keys={}）",
                resp.data
                    .get("keys")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            );
        }
        Ok(resp) => {
            eprintln!(
                "daemon 热重载失败: {}；请执行 wx daemon restart",
                resp.error.unwrap_or_default()
            );
        }
        Err(e) => {
            eprintln!("daemon 未运行或无法连接（{}）；下次启动将加载新密钥", e);
        }
    }
    Ok(())
}

pub fn cmd_key_extract(hook_seconds: Option<u64>) -> Result<()> {
    println!(
        "提取密钥（内存扫描 + 可选 LLDB hook；推荐：{}）…",
        config::RECOMMENDED_KEY_EXTRACT
    );
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "警告: 建议使用 {}，以便 task_for_pid 读取进程内存",
            config::RECOMMENDED_KEY_EXTRACT
        );
    }
    super::init::cmd_init(true, hook_seconds)
}
