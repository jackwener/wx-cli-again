//! `wx watch` — 轮询 session 变更并打印新消息事件

use super::output::{print_value, OutputOpts};
use super::transport;
use crate::ipc::Request;
use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn state_file() -> PathBuf {
    crate::config::cli_dir().join("watch_state.json")
}

fn load_state() -> HashMap<String, i64> {
    let Ok(text) = std::fs::read_to_string(state_file()) else {
        return HashMap::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return HashMap::new();
    };
    v.get("sessions")
        .and_then(|s| s.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_i64().map(|t| (k.clone(), t)))
                .collect()
        })
        .unwrap_or_default()
}

fn save_state(map: &HashMap<String, i64>) {
    let path = state_file();
    if let Some(p) = path.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    let _ = crate::private_fs::write_private(
        &path,
        serde_json::to_string_pretty(&serde_json::json!({ "sessions": map })).unwrap_or_default(),
    );
}

fn file_mtime_ns(p: &std::path::Path) -> u64 {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        })
        .unwrap_or(0)
}

/// 取 session.db / -wal / -shm 的最大 mtime。
/// WeChat 常只 append WAL，主文件 mtime 可能长时间不变。
fn session_source_mtime() -> u64 {
    let Ok(cfg) = crate::config::load_config() else {
        return 0;
    };
    let base = cfg.db_dir.join("session/session.db");
    let wal = cfg.db_dir.join("session/session.db-wal");
    let shm = cfg.db_dir.join("session/session.db-shm");
    file_mtime_ns(&base)
        .max(file_mtime_ns(&wal))
        .max(file_mtime_ns(&shm))
}

pub fn cmd_watch(interval_ms: u64, limit: usize, opts: OutputOpts) -> Result<()> {
    let interval = Duration::from_millis(interval_ms.max(200));
    let mut state = load_state();
    let mut last_mtime = session_source_mtime();
    eprintln!(
        "watching session.db(+wal) (poll {}ms). Ctrl+C 退出…",
        interval.as_millis()
    );

    // 首次：若无 state，只同步快照不刷屏
    if state.is_empty() {
        let resp = transport::send(Request::NewMessages {
            state: None,
            limit,
            with_meta: false,
            debug_source: false,
        })?;
        if let Some(obj) = resp.data.get("new_state").and_then(|v| v.as_object()) {
            state = obj
                .iter()
                .filter_map(|(k, v)| v.as_i64().map(|t| (k.clone(), t)))
                .collect();
            save_state(&state);
            eprintln!("已建立 baseline（{} 会话），等待新消息…", state.len());
        }
    }

    loop {
        thread::sleep(interval);
        let mt = session_source_mtime();
        if mt != 0 && mt == last_mtime {
            continue;
        }
        last_mtime = mt;

        let resp = transport::send(Request::NewMessages {
            state: Some(state.clone()),
            limit,
            with_meta: false,
            debug_source: false,
        })?;
        if !resp.ok {
            eprintln!("watch error: {}", resp.error.unwrap_or_default());
            continue;
        }

        if let Some(obj) = resp.data.get("new_state").and_then(|v| v.as_object()) {
            state = obj
                .iter()
                .filter_map(|(k, v)| v.as_i64().map(|t| (k.clone(), t)))
                .collect();
            save_state(&state);
        }

        let messages = resp
            .data
            .get("messages")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]));
        let n = messages.as_array().map(|a| a.len()).unwrap_or(0);
        if n == 0 {
            continue;
        }

        if opts.json {
            let _ = print_value(&messages, &super::output::resolve(true));
        } else {
            // 逐条打印一行摘要
            if let Some(arr) = messages.as_array() {
                for m in arr {
                    let time = m.get("time").and_then(|v| v.as_str()).unwrap_or("");
                    let chat = m.get("chat").and_then(|v| v.as_str()).unwrap_or("");
                    let sender = m.get("sender").and_then(|v| v.as_str()).unwrap_or("");
                    let content = m.get("content").and_then(|v| v.as_str()).unwrap_or("");
                    let one_line: String = content.chars().take(80).collect();
                    if sender.is_empty() {
                        println!("{time} [{chat}] {one_line}");
                    } else {
                        println!("{time} [{chat}] {sender}: {one_line}");
                    }
                }
            }
        }
    }
}
