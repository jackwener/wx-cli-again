//! 消息分片时间元数据：避免 history/search 对每个 message_N.db 全量解密。
//!
//! 持久化到 `~/.wx-cli/shard-meta.json`。
//! **按 talker 表（Msg_<md5>）分别记录 min/max**，避免用 A 会话的时间窗错误跳过仍含 B 会话消息的分片。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config;

const META_FILE: &str = "shard-meta.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TableBound {
    #[serde(default)]
    pub min_ts: i64,
    #[serde(default)]
    pub max_ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShardMetaEntry {
    /// 旧版字段：分片级 min/max。仅作兼容读取；路由改用 `tables`。
    #[serde(default)]
    pub min_ts: i64,
    #[serde(default)]
    pub max_ts: i64,
    /// `Timestamp` 表读到的分片起点（若有）
    #[serde(default)]
    pub shard_start: Option<i64>,
    /// 加密源文件 mtime（纳秒），用于判断是否过期
    #[serde(default)]
    pub source_mtime_ns: u64,
    /// 加密源 WAL（`<db>-wal`）mtime（纳秒）。
    ///
    /// 微信写入新消息时只追加 WAL，主库 mtime 可能长时间不变；只看主库 mtime
    /// 会把「已有新消息」的 meta 误判为新鲜，导致窄时间窗查询跳过整个分片
    /// （表现为 `找不到 xxx 的消息记录`）。见 `may_overlap`。
    #[serde(default)]
    pub wal_mtime_ns: u64,
    /// 是否确认某 talker 表不存在（可选加速，key 为 table name）
    #[serde(default)]
    pub missing_tables: Vec<String>,
    /// 按表记录的时间窗：`Msg_<md5>` -> bound
    #[serde(default)]
    pub tables: HashMap<String, TableBound>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShardMetaFile {
    /// rel_key -> meta，如 `message/message_0.db`
    #[serde(default)]
    pub shards: HashMap<String, ShardMetaEntry>,
    #[serde(default)]
    pub written_at_ns: u128,
}

pub fn meta_path() -> PathBuf {
    config::cli_dir().join(META_FILE)
}

pub fn load() -> ShardMetaFile {
    let path = meta_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return ShardMetaFile::default();
    };
    serde_json::from_str(&text).unwrap_or_default()
}

pub fn save(meta: &ShardMetaFile) {
    let path = meta_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut out = meta.clone();
    out.written_at_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    if let Ok(json) = serde_json::to_string_pretty(&out) {
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, json).is_ok() {
            let _ = std::fs::rename(tmp, path);
        }
    }
}

pub fn source_mtime_ns(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|t| {
            t.duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        })
        .unwrap_or(0)
}

/// SQLite 的 `-wal` 附属文件路径（`message_0.db` → `message_0.db-wal`）。
pub fn wal_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push("-wal");
    PathBuf::from(name)
}

/// 主库 + WAL 的当前 mtime（纳秒）。
pub fn source_mtimes(path: &Path) -> (u64, u64) {
    (source_mtime_ns(path), source_mtime_ns(&wal_path(path)))
}

/// 判断分片是否可能与 [since, until] 时间窗重叠。
///
/// 必须传入 `table`（`Msg_<md5>`）。只用该表的 bound；未知表则保守返回 true。
/// meta 缺失、主库 mtime 或 WAL mtime 更新时返回 true。
///
/// WAL 也必须参与新鲜度判断：微信收新消息只追加 `-wal`，主库 mtime 可能不变，
/// 否则会把滞后 per-table 界当成有效界，窄时间窗查询会错误跳过整个分片。
pub fn may_overlap(
    entry: Option<&ShardMetaEntry>,
    source_mtime: u64,
    wal_mtime: u64,
    table: &str,
    since: Option<i64>,
    until: Option<i64>,
) -> bool {
    let Some(e) = entry else {
        return true;
    };
    // 主库或 WAL 已更新 → meta 可能过期
    if e.source_mtime_ns > 0 && source_mtime > e.source_mtime_ns {
        return true;
    }
    if wal_mtime > 0 && (e.wal_mtime_ns == 0 || wal_mtime > e.wal_mtime_ns) {
        return true;
    }
    // 已知缺失
    if e.missing_tables.iter().any(|t| t == table) {
        return false;
    }

    let (lo, hi) = if let Some(tb) = e.tables.get(table) {
        let lo = if tb.min_ts > 0 {
            tb.min_ts
        } else {
            e.shard_start.unwrap_or(0)
        };
        let hi = tb.max_ts.max(lo);
        (lo, hi)
    } else {
        // 无该表记录：不因其它 talker 的旧分片级 min/max 跳过
        return true;
    };

    if hi <= 0 && lo <= 0 {
        return true;
    }
    let start = since.unwrap_or(i64::MIN);
    let end = until.unwrap_or(i64::MAX);
    lo <= end && hi >= start
}

/// 记录一次打开后的 **per-table** 时间范围。
pub fn record_open(
    meta: &mut ShardMetaFile,
    rel_key: &str,
    source_path: &Path,
    table: &str,
    min_ts: Option<i64>,
    max_ts: Option<i64>,
    shard_start: Option<i64>,
) {
    let e = meta.shards.entry(rel_key.to_string()).or_default();
    let (db_mtime, wal_mtime) = source_mtimes(source_path);
    e.source_mtime_ns = db_mtime;
    e.wal_mtime_ns = wal_mtime;
    if shard_start.is_some() {
        e.shard_start = shard_start;
    }
    // 从 missing 里移除（表实际存在）
    e.missing_tables.retain(|t| t != table);

    let tb = e.tables.entry(table.to_string()).or_default();
    if let Some(v) = min_ts {
        if v > 0 && (tb.min_ts <= 0 || v < tb.min_ts) {
            tb.min_ts = v;
        }
    }
    if let Some(v) = max_ts {
        if v > tb.max_ts {
            tb.max_ts = v;
        }
    }

    // 兼容字段：维护分片级 expanded union（仅观测，不用于跨 talker 路由）
    if let Some(v) = min_ts {
        if v > 0 && (e.min_ts <= 0 || v < e.min_ts) {
            e.min_ts = v;
        }
    }
    if let Some(v) = max_ts {
        if v > e.max_ts {
            e.max_ts = v;
        }
    }
}

/// 加密源文件 mtime 降序（新写的分片优先，通常即热分片）。
pub fn sort_rel_keys_by_mtime(db_dir: &Path, keys: &[String]) -> Vec<String> {
    let mut items: Vec<(u64, String)> = keys
        .iter()
        .map(|k| {
            let p = db_dir.join(k.replace('/', std::path::MAIN_SEPARATOR_STR));
            (source_mtime_ns(&p), k.clone())
        })
        .collect();
    items.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    items.into_iter().map(|(_, k)| k).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_bounds_do_not_poison_other_talkers() {
        let mut meta = ShardMetaFile::default();
        let path = PathBuf::from("/tmp/nonexistent-for-meta-test");
        record_open(
            &mut meta,
            "message/message_0.db",
            &path,
            "Msg_aaa",
            Some(1_700_000_000),
            Some(1_700_000_100),
            None,
        );
        let e = meta.shards.get("message/message_0.db");
        // other table unknown → must open
        assert!(may_overlap(
            e,
            0,
            0,
            "Msg_bbb",
            Some(1_600_000_000),
            Some(1_600_000_100)
        ));
        // known table outside window → skip
        assert!(!may_overlap(
            e,
            0,
            0,
            "Msg_aaa",
            Some(1_600_000_000),
            Some(1_600_000_100)
        ));
        // known table inside window → open
        assert!(may_overlap(
            e,
            0,
            0,
            "Msg_aaa",
            Some(1_700_000_000),
            Some(1_700_000_050)
        ));
    }

    /// 回归测试：消息只进 WAL、主库 mtime 未变时，不能用滞后的 per-table 界跳过分片。
    /// 症状是窄时间窗 history 误报「找不到 xxx 的消息记录」。
    #[test]
    fn wal_growth_invalidates_stale_table_bounds() {
        let mut meta = ShardMetaFile::default();
        let path = PathBuf::from("/tmp/nonexistent-for-meta-test");
        record_open(
            &mut meta,
            "message/message_0.db",
            &path,
            "Msg_aaa",
            Some(1_700_000_000),
            Some(1_700_000_100),
            None,
        );
        // record_open 对不存在的文件记录 mtime=0；模拟「主库 mtime 未变」：
        let e = meta.shards.get_mut("message/message_0.db").unwrap();
        e.source_mtime_ns = 1_700_000_500;
        e.wal_mtime_ns = 1_700_000_500;
        let e: &ShardMetaEntry = e;

        let since = Some(1_700_000_900);
        let until = Some(1_700_001_000);
        // 主库 mtime 没变、WAL 也没变 → 缓存可信，可跳过
        assert!(!may_overlap(
            Some(e),
            1_700_000_500,
            1_700_000_500,
            "Msg_aaa",
            since,
            until
        ));
        // WAL 变新（有新消息）→ 必须重新打开
        assert!(may_overlap(
            Some(e),
            1_700_000_500,
            1_700_000_950,
            "Msg_aaa",
            since,
            until
        ));
        // 主库 mtime 变新 → 必须重新打开
        assert!(may_overlap(
            Some(e),
            1_700_000_950,
            1_700_000_500,
            "Msg_aaa",
            since,
            until
        ));
    }
}
