pub mod cache;
pub mod meta;
pub mod query;
pub mod server;
pub mod shard_meta;

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config;

fn normalized_rel_key(rel_key: &str) -> String {
    rel_key.replace('\\', "/")
}

pub(crate) fn is_msg_db_key(rel_key: &str) -> bool {
    let rel_key = normalized_rel_key(rel_key);
    rel_key.starts_with("message/message_")
        && rel_key.ends_with(".db")
        && !rel_key.contains("_fts")
        && !rel_key.contains("_resource")
}

pub(crate) fn is_biz_msg_db_key(rel_key: &str) -> bool {
    let rel_key = normalized_rel_key(rel_key);
    rel_key.starts_with("message/biz_message_")
        && rel_key.ends_with(".db")
        && !rel_key.contains("_fts")
        && !rel_key.contains("_resource")
}

pub(crate) fn collect_db_keys(
    all_keys: &HashMap<String, String>,
    predicate: fn(&str) -> bool,
) -> Vec<String> {
    let mut keys: Vec<String> = all_keys
        .keys()
        .filter(|k| predicate(k))
        .cloned()
        .collect();
    keys.sort();
    keys
}

/// daemon 入口
///
/// 当 WX_DAEMON_MODE 环境变量设置时，main() 调用此函数
pub fn run() {
    let rt = tokio::runtime::Runtime::new().expect("无法创建 tokio runtime");
    if let Err(e) = rt.block_on(async_run()) {
        eprintln!("[daemon] 启动失败: {}", e);
        std::process::exit(1);
    }
}

async fn async_run() -> Result<()> {
    // 确保工作目录存在
    let cli_dir = config::cli_dir();
    crate::private_fs::require_unprivileged()?;
    crate::private_fs::ensure_private_dir(&cli_dir)?;
    crate::private_fs::ensure_private_dir(&config::cache_dir())?;

    let pid = std::process::id();

    // 注册 SIGTERM / SIGINT 处理
    setup_signal_handler().await;

    eprintln!("[daemon] wx-daemon 启动 (PID {})", pid);

    // 加载配置
    let cfg = config::load_config()?;
    eprintln!("[daemon] DB_DIR: {}", cfg.db_dir.display());

    // 加载密钥
    let keys_content = crate::private_fs::read_private(&cfg.keys_file)
        .map_err(|e| anyhow::anyhow!("读取密钥文件 {:?} 失败: {}", cfg.keys_file, e))?;
    let keys_raw: serde_json::Value = serde_json::from_str(&keys_content)?;
    let all_keys = extract_keys(&keys_raw);
    eprintln!("[daemon] 密钥数量: {}", all_keys.len());
    warn_unknown_shards(&cfg.db_dir, &all_keys);

    // 初始化 DbCache
    let db = Arc::new(cache::DbCache::new(cfg.db_dir.clone(), all_keys.clone()).await?);

    // 收集消息 DB 列表
    let msg_db_keys = collect_db_keys(&all_keys, is_msg_db_key);
    let biz_msg_db_keys = collect_db_keys(&all_keys, is_biz_msg_db_key);

    // 预热：加载联系人 + 解密 session.db
    eprintln!("[daemon] 预热...");
    let names_raw = query::load_names(&*db).await.unwrap_or_else(|e| {
        eprintln!("[daemon] 加载联系人失败: {}", e);
        query::Names {
            map: HashMap::new(),
            md5_to_uname: HashMap::new(),
            msg_db_keys: Vec::new(),
            biz_msg_db_keys: Vec::new(),
            verify_flags: HashMap::new(),
        }
    });
    let mut names = names_raw;
    names.msg_db_keys = msg_db_keys;
    names.biz_msg_db_keys = biz_msg_db_keys;

    let _ = db.get("session/session.db").await;
    let _ = db.get("sns/sns.db").await;
    eprintln!("[daemon] 预热完成，联系人 {} 个", names.map.len());

    // 包一层内部 Arc：IPC 请求取 guard 后只做 Arc::clone（O(1)），
    // 避免每次请求都全量 clone 几千个联系人的 HashMap。
    // 用 tokio::sync::RwLock 允许 guard 跨 await（当前不跨，为未来 reload 留余地）。
    let names_arc = Arc::new(tokio::sync::RwLock::new(Arc::new(names)));

    // 启动 IPC server（阻塞）
    let serve_result = server::serve(Arc::clone(&db), Arc::clone(&names_arc)).await;
    cleanup_ipc_files();
    serve_result?;

    Ok(())
}

/// 磁盘上有加密分片但 all_keys 没有 → 查询结果可能不完整。
fn warn_unknown_shards(db_dir: &std::path::Path, all_keys: &HashMap<String, String>) {
    let disk = crate::scanner::collect_db_salts(db_dir);
    let mut missing: Vec<String> = disk
        .into_iter()
        .map(|(_, name)| name)
        .filter(|name| {
            let n = name.replace('\\', "/");
            let interesting = n.contains("message/message_")
                || n.contains("message/biz_message_")
                || n.contains("session/")
                || n == "contact/contact.db";
            interesting && !all_keys.contains_key(name) && !all_keys.contains_key(&n)
        })
        .collect();
    missing.sort();
    if missing.is_empty() {
        return;
    }
    eprintln!(
        "[wx] 警告：磁盘上发现 daemon 不认识的分片 {}，结果可能不完整；{}",
        missing.join(", "),
        crate::config::RECOMMENDED_KEY_EXTRACT_HINT
    );
}

/// 从 all_keys.json 提取 rel_key -> enc_key 映射
///
/// 兼容两种格式：
/// - `{ "rel/path.db": { "enc_key": "hex" } }`（Python 版原生格式）
/// - `{ "rel/path.db": "hex" }`（简化格式）
pub(crate) fn extract_keys(json: &serde_json::Value) -> HashMap<String, String> {
    let mut result = HashMap::new();
    if let Some(obj) = json.as_object() {
        for (k, v) in obj {
            if k.starts_with('_') {
                continue;
            }
            let enc_key = if let Some(s) = v.as_str() {
                s.to_string()
            } else if let Some(obj2) = v.as_object() {
                obj2.get("enc_key")
                    .and_then(|e| e.as_str())
                    .unwrap_or_default()
                    .to_string()
            } else {
                continue;
            };
            if !enc_key.is_empty() {
                // 统一路径分隔符
                let rel = k.replace('\\', "/");
                result.insert(rel, enc_key);
            }
        }
    }
    result
}

/// 设置信号处理（Unix: SIGTERM/SIGINT）
async fn setup_signal_handler() {
    #[cfg(unix)]
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("无法监听 SIGTERM");
        let mut int = signal(SignalKind::interrupt()).expect("无法监听 SIGINT");
        tokio::select! {
            _ = term.recv() => {},
            _ = int.recv() => {},
        }
        cleanup_and_exit();
    });
}

#[cfg(unix)]
fn cleanup_and_exit() {
    cleanup_ipc_files();
    std::process::exit(0);
}

fn cleanup_ipc_files() {
    let _ = std::fs::remove_file(config::sock_path());
    let _ = std::fs::remove_file(config::pid_path());
}

#[cfg(test)]
mod tests {
    use super::{is_biz_msg_db_key, is_msg_db_key};

    #[test]
    fn message_db_key_filter_ignores_biz_and_auxiliary_files() {
        assert!(is_msg_db_key("message/message_0.db"));
        assert!(is_msg_db_key("message\\message_12.db"));
        assert!(!is_msg_db_key("message/biz_message_0.db"));
        assert!(!is_msg_db_key("message/message_0.db-wal"));
        assert!(!is_msg_db_key("message/message_0_fts.db"));
        assert!(!is_msg_db_key("message/message_0_resource.db"));
    }

    #[test]
    fn biz_message_db_key_filter_matches_only_biz_shards() {
        assert!(is_biz_msg_db_key("message/biz_message_0.db"));
        assert!(is_biz_msg_db_key("message\\biz_message_3.db"));
        assert!(!is_biz_msg_db_key("message/message_0.db"));
        assert!(!is_biz_msg_db_key("message/biz_message_0.db-wal"));
        assert!(!is_biz_msg_db_key("message/biz_message_0_fts.db"));
        assert!(!is_biz_msg_db_key("message/biz_message_0_resource.db"));
    }
}
