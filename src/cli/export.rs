use super::history::{parse_time, parse_time_end};
use super::output::{emit_warnings, warning_block_markdown, warning_block_text, OutputOpts};
use super::transport;
use crate::ipc::Request;
use anyhow::Result;

pub fn cmd_export(
    chat: String,
    since: Option<String>,
    until: Option<String>,
    limit: usize,
    format: String,
    output: Option<String>,
    opts: OutputOpts,
) -> Result<()> {
    let since_ts = since.as_deref().map(parse_time).transpose()?;
    let until_ts = until.as_deref().map(parse_time_end).transpose()?;
    let (with_meta, debug_source) = opts.request_flags();

    let req = Request::History {
        chat,
        limit,
        offset: 0,
        since: since_ts,
        until: until_ts,
        after_ts: None,
        before_ts: None,
        msg_type: None,
        with_meta,
        debug_source,
    };

    let resp = transport::send(req)?;
    emit_warnings(&resp.data);
    let messages = resp.data["messages"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let chat_name = resp.data["chat"].as_str().unwrap_or("").to_string();
    let is_group = resp.data["is_group"].as_bool().unwrap_or(false);
    let count = messages.len();

    let text = match format.as_str() {
        "json" => serde_json::to_string_pretty(&resp.data)?,
        "yaml" => serde_yaml::to_string(&resp.data)?,
        "txt" => {
            let group_str = if is_group { "[群]" } else { "" };
            let mut lines = vec![format!(
                "=== {}{} ({} 条) ===\n",
                chat_name, group_str, count
            )];
            if let Some(warn) = warning_block_text(&resp.data) {
                lines.push(warn);
                lines.push(String::new());
            }
            for m in &messages {
                let time = m["time"].as_str().unwrap_or("");
                let sender = m["sender"].as_str().unwrap_or("");
                let content = m["content"].as_str().unwrap_or("");
                let sender_str = if !sender.is_empty() {
                    format!("{}: ", sender)
                } else {
                    String::new()
                };
                lines.push(format!("[{}] {}{}", time, sender_str, content));
            }
            lines.join("\n")
        }
        _ => {
            // markdown (default)
            let group_str = if is_group { "（群聊）" } else { "" };
            let mut lines = vec![
                format!("# {}{}", chat_name, group_str),
                format!("\n> 导出 {} 条消息\n", count),
            ];
            if let Some(warn) = warning_block_markdown(&resp.data) {
                lines.push(warn);
            }
            for m in &messages {
                let time = m["time"].as_str().unwrap_or("");
                let sender = m["sender"].as_str().unwrap_or("");
                let content = m["content"].as_str().unwrap_or("").replace('\n', "\n> ");
                let sender_md = if !sender.is_empty() {
                    format!("**{}**: ", sender)
                } else {
                    String::new()
                };
                lines.push(format!("### {}\n\n{}{}\n", time, sender_md, content));
            }
            lines.join("\n")
        }
    };

    match output {
        Some(path) => {
            crate::private_fs::write_private(std::path::Path::new(&path), &text)?;
            println!("已导出 {} 条消息到 {}", count, path);
        }
        None => println!("{}", text),
    }

    Ok(())
}
