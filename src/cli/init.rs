use anyhow::{bail, Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config;
use crate::scanner::{self, KeyEntry, ScanOptions};

pub fn cmd_init(force: bool, hook_seconds: Option<u64>) -> Result<()> {
    // 查找 config.json
    let config_path = find_or_create_config_path();

    // 检查是否已初始化
    if !force && config_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&config_path) {
            if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&content) {
                let db_dir = cfg.get("db_dir").and_then(|v| v.as_str()).unwrap_or("");
                let keys_file = cfg
                    .get("keys_file")
                    .and_then(|v| v.as_str())
                    .unwrap_or("all_keys.json");
                let keys_path = resolve_keys_path(&config_path, keys_file);
                if !db_dir.is_empty()
                    && !db_dir.contains("your_wxid")
                    && Path::new(db_dir).exists()
                    && keys_path.exists()
                {
                    println!("已初始化，数据目录: {}", db_dir);
                    println!("如需重新扫描密钥，使用 --force");
                    // 仍检查磁盘上是否有未收录的分片
                    if let Ok(existing) = load_existing_entries(&keys_path, Path::new(db_dir)) {
                        let missing = scanner::missing_encrypted_dbs(Path::new(db_dir), &existing);
                        if !missing.is_empty() {
                            let critical: Vec<_> = missing
                                .iter()
                                .filter(|n| scanner::is_critical_missing_db(n))
                                .collect();
                            println!(
                                "[wx] 警告：磁盘上仍有 {} 个加密 DB 没有密钥（关键 {} 个，例如 {}）。\n\
                                 运行 {} 重新提取，并在等待期间打开对应聊天以触发冷分片解密。",
                                missing.len(),
                                critical.len(),
                                critical
                                    .first()
                                    .copied()
                                    .or(missing.first())
                                    .map(|s| s.as_str())
                                    .unwrap_or(""),
                                config::RECOMMENDED_KEY_EXTRACT
                            );
                        }
                    }
                    #[cfg(unix)]
                    drop_privileges_if_sudo()?;
                    crate::private_fs::ensure_private_dir(&config::cli_dir())?;
                    crate::private_fs::secure_existing(&keys_path)?;
                    return Ok(());
                }
            }
        }
    }

    // Step 1: 解析 db_dir —— 已有有效配置时优先沿用，避免多账号下 auto-detect 切错库。
    let db_dir = resolve_db_dir(&config_path)?;
    println!("数据目录: {}", db_dir.display());

    // 读取已有密钥（验证仍有效的保留，避免 force 扫描不全时丢 key）
    let keys_file_path = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("all_keys.json");
    let existing_entries = load_existing_entries(&keys_file_path, &db_dir).unwrap_or_default();
    if !existing_entries.is_empty() {
        println!(
            "已有 {} 个仍可解密的密钥，将与新扫描结果合并",
            existing_entries.len()
        );
    }

    // Step 2: 扫描密钥
    println!("扫描加密密钥…");
    let mut opts = ScanOptions {
        known: &existing_entries,
        ..ScanOptions::default()
    };
    if let Some(secs) = hook_seconds {
        opts.hook_seconds = secs;
        opts.auto_hook = secs > 0;
    }
    let scanned = scanner::scan_keys_with_options(&db_dir, opts)?;
    // scan 内部已合并 known；再 merge 一次保证兜底
    let entries = scanner::merge_key_entries(&scanned, &existing_entries);

    if entries.is_empty() {
        bail!(
            "没有任何候选 key 能解密所选数据目录中的数据库，已保留现有配置和 key 文件。\n\
             当前数据目录: {}\n\
             如果本机登录过多个微信账号，请确认该目录属于当前正在运行的账号；\
             退出其他账号并让当前账号产生一条新消息后，再运行：\n\
             {}\n\
             冷分片（久未打开的 message_N.db）同一命令，等待期间滚动/打开对应会话。",
            db_dir.display(),
            config::RECOMMENDED_KEY_EXTRACT
        );
    }

    // === 权限边界 ===
    // 扫描完成后立即 drop 到调用用户身份，后续文件写入都是用户属主。
    #[cfg(unix)]
    drop_privileges_if_sudo()?;

    crate::private_fs::ensure_private_dir(&config::cli_dir())?;

    // Step 3: 保存 all_keys.json（合并后的完整集合）
    let mut keys_json = serde_json::Map::new();
    for entry in &entries {
        keys_json.insert(
            entry.db_name.clone(),
            json!({
                "enc_key": entry.enc_key,
            }),
        );
    }
    crate::private_fs::write_private(&keys_file_path, serde_json::to_string_pretty(&keys_json)?)
        .context("写入 all_keys.json 失败")?;
    println!(
        "成功保存 {} 个数据库密钥（本次新匹配 {}）",
        entries.len(),
        scanned.len()
    );
    println!("密钥已保存: {}", keys_file_path.display());

    let missing = scanner::list_missing_encrypted_dbs(&db_dir, &entries);
    let critical: Vec<_> = missing
        .iter()
        .filter(|m| scanner::is_critical_missing_db(&m.rel))
        .collect();
    if !missing.is_empty() {
        println!(
            "[wx] 警告：仍有 {} 个加密 DB 没有密钥（其中 {} 个影响聊天完整性）：",
            missing.len(),
            critical.len()
        );
        for m in missing.iter().take(12) {
            let tag = if scanner::is_critical_missing_db(&m.rel) {
                " [关键]"
            } else {
                ""
            };
            println!(
                "  - {} ({}){}",
                m.rel,
                scanner::format_db_size(m.size),
                tag
            );
        }
        if missing.len() > 12 {
            println!("  … 另有 {} 个", missing.len() - 12);
        }
        if !critical.is_empty() {
            println!(
                "补齐关键分片：{}\n\
                 等待期间请在微信中打开相关聊天/滚动历史，触发冷分片加载。",
                config::RECOMMENDED_KEY_EXTRACT
            );
        }
    }

    // Step 4: 保存 config.json
    let mut cfg = HashMap::new();
    if config_path.exists() {
        if let Ok(c) = std::fs::read_to_string(&config_path) {
            if let Ok(v) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&c) {
                for (k, val) in v {
                    cfg.insert(k, val);
                }
            }
        }
    }
    cfg.insert("db_dir".into(), json!(db_dir.to_string_lossy()));
    cfg.entry("keys_file".into())
        .or_insert_with(|| json!("all_keys.json"));
    cfg.entry("decrypted_dir".into())
        .or_insert_with(|| json!("decrypted"));

    crate::private_fs::write_private(&config_path, serde_json::to_string_pretty(&cfg)?)
        .context("写入 config.json 失败")?;
    println!("配置已保存: {}", config_path.display());
    println!("初始化完成，可以使用 wx sessions / wx history 等命令了");

    #[cfg(target_os = "macos")]
    {
        println!();
        println!("[macOS] 说明：");
        println!("  · SIP 无需关闭；wx-cli 不会自动 ad-hoc 重签 WeChat.app。");
        println!(
            "  · 官网部分 4.x 包本身已是 ad-hoc，可直接用户态 LLDB hook，无需 sudo 重签。"
        );
        println!(
            "  · 官方 Hardened Runtime 包：内存扫描请 sudo；补冷分片用 --hook-seconds。"
        );
    }

    Ok(())
}

fn resolve_keys_path(config_path: &Path, keys_file: &str) -> PathBuf {
    if Path::new(keys_file).is_absolute() {
        PathBuf::from(keys_file)
    } else {
        config_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(keys_file)
    }
}

/// 优先使用 config 里已配置且仍存在的 `db_dir`；否则再 auto-detect。
///
/// 多账号场景下，`auto_detect` 按 mtime 选最新目录可能切到闲置号，
/// 导致 force 提取时已有密钥全部校验失败、用户误以为密钥丢了。
fn resolve_db_dir(config_path: &Path) -> Result<PathBuf> {
    if config_path.exists() {
        if let Ok(content) = std::fs::read_to_string(config_path) {
            if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(dir) = cfg.get("db_dir").and_then(|v| v.as_str()) {
                    let p = PathBuf::from(dir);
                    if !dir.is_empty()
                        && !dir.contains("your_wxid")
                        && p.is_dir()
                    {
                        // 若磁盘上另有更新的账号目录，仅提示，不擅自切换
                        if let Some(detected) = config::auto_detect_db_dir() {
                            if detected != p {
                                eprintln!(
                                    "[wx] 提示：检测到更新的微信数据目录 {}，\n\
                                     当前仍使用已配置的 {}。\n\
                                     若要切换账号，请编辑 config.json 的 db_dir 后重新 init。",
                                    detected.display(),
                                    p.display()
                                );
                            }
                        }
                        return Ok(p);
                    }
                }
            }
        }
    }
    println!("检测微信数据目录...");
    config::auto_detect_db_dir()
        .context("未能自动检测到微信数据目录\n请手动编辑 config.json 中的 db_dir 字段")
}

/// 加载已有 all_keys.json，并丢弃无法再解密对应 DB 的条目。
fn load_existing_entries(keys_path: &Path, db_dir: &Path) -> Result<Vec<KeyEntry>> {
    if !keys_path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(keys_path)?;
    let value: serde_json::Value = serde_json::from_str(&content)?;
    let mut out = Vec::new();
    let Some(obj) = value.as_object() else {
        return Ok(out);
    };
    for (db_name, v) in obj {
        if db_name.starts_with('_') {
            continue;
        }
        let enc_key = if let Some(s) = v.as_str() {
            s.to_string()
        } else if let Some(o) = v.as_object() {
            o.get("enc_key")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string()
        } else {
            continue;
        };
        if enc_key.len() != 64 {
            continue;
        }
        let db_path = db_dir.join(db_name);
        if !db_path.exists() {
            continue;
        }
        let Some(key) = scanner::decode_key_hex_pub(&enc_key) else {
            continue;
        };
        if crate::crypto::validate_raw_key_for_db(&db_path, &key) {
            let salt = scanner::read_db_salt(&db_path).unwrap_or_default();
            out.push(KeyEntry {
                db_name: db_name.replace('\\', "/"),
                enc_key: enc_key.to_lowercase(),
                salt,
            });
        }
    }
    Ok(out)
}

/// Scan with elevated read access, then drop all privileges before touching
/// user-owned paths. Never recursively chown a user-controlled directory.
#[cfg(unix)]
fn drop_privileges_if_sudo() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let uid = std::env::var("SUDO_UID").ok().and_then(|s| s.parse::<u32>().ok());
    let gid = std::env::var("SUDO_GID").ok().and_then(|s| s.parse::<u32>().ok());
    let (uid, gid) = match (uid, gid) {
        (Some(u), Some(g)) if u != 0 && u != u32::MAX && g != u32::MAX => (u, g),
        _ => bail!("无法确定 sudo 调用用户；拒绝以 root 保存密钥，请从普通用户通过 sudo 执行"),
    };
    unsafe {
        // setgid does not clear supplementary groups inherited from root.
        if libc::setgroups(0, std::ptr::null()) != 0 {
            bail!("清除附加用户组失败: {}", std::io::Error::last_os_error());
        }
        if libc::setgid(gid) != 0 {
            bail!("setgid({}) 失败: {}", gid, std::io::Error::last_os_error());
        }
        if libc::setuid(uid) != 0 {
            bail!("setuid({}) 失败: {}", uid, std::io::Error::last_os_error());
        }
    }
    crate::private_fs::require_unprivileged()
}

fn find_or_create_config_path() -> std::path::PathBuf {
    // 如果当前工作目录或可执行文件目录已有 config.json，沿用它（支持便携模式）
    if let Ok(cwd) = std::env::current_dir() {
        let p = cwd.join("config.json");
        if p.exists() {
            return p;
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("config.json");
            if p.exists() {
                return p;
            }
        }
    }
    // 默认写入 ~/.wx-cli/config.json（与 load_config 的最终查找路径保持一致）
    config::cli_dir().join("config.json")
}
