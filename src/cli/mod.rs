pub mod attachments;
pub mod biz_articles;
pub mod contacts;
pub mod daemon_cmd;
pub mod doctor;
pub mod export;
pub mod extract;
pub mod favorites;
pub mod history;
pub(crate) mod init;
pub mod key_cmd;
pub mod media;
pub mod members;
pub mod new_messages;
pub mod output;
pub mod search;
pub mod sessions;
pub mod sns_feed;
pub mod sns_notifications;
pub mod sns_search;
pub mod stats;
pub mod timeline;
pub mod transport;
pub mod unread;
pub mod watch;

use self::output::OutputOpts;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Clap `value_parser` for `--type`: must accept every slug/`type_id` and numeric codes
/// that `history::parse_msg_type` knows — closed string lists reject agent round-trips.
fn clap_parse_msg_type(s: &str) -> std::result::Result<String, String> {
    history::parse_msg_type_required(s)
        .map(|_| s.to_string())
        .map_err(|e| e.to_string())
}

const MSG_TYPE_HELP: &str = "消息类型过滤 [text|image|voice|video|card|sticker|location|link|file|appmsg|call|system|revoke|数字code]";

/// wx — 微信本地数据 CLI
#[derive(Parser)]
#[command(name = "wx", version = env!("CARGO_PKG_VERSION"), about = "wx — 微信本地数据 CLI")]
pub struct Cli {
    /// 返回更重的 freshness/source 元数据（如 per-shard latest、cache modes）
    #[arg(long, global = true)]
    with_meta: bool,
    /// 在 meta 里暴露真实 shard 路径（调试用）
    #[arg(long, global = true, hide = true)]
    debug_source: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 初始化：检测数据目录并扫描加密密钥
    Init {
        /// 强制重新扫描（与已有有效密钥合并，不会因部分失败而清空）
        #[arg(long)]
        force: bool,
        /// macOS: LLDB hook 等待秒数（0=禁用）。内存扫描配不齐冷分片时，
        /// 在等待期间打开微信会话可捕获 per-DB AES key。
        #[arg(long)]
        hook_seconds: Option<u64>,
    },
    /// 列出最近会话
    Sessions {
        /// 会话数量
        #[arg(short = 'n', long, default_value = "20")]
        limit: usize,
        /// 输出 JSON（默认 YAML）
        #[arg(long)]
        json: bool,
    },
    /// 查看聊天记录
    History {
        /// 聊天对象名称（支持模糊匹配）
        chat: String,
        /// 消息数量
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        /// 分页偏移（深 offset 慢；优先用 --after 游标）
        #[arg(long, default_value = "0")]
        offset: usize,
        /// 起始时间 YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// 结束时间 YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// 游标：只返回比该时间更旧的消息（Unix 秒或日期；通常传上一页最旧 timestamp）
        #[arg(long)]
        after: Option<String>,
        /// 游标：只返回比该时间更新的消息
        #[arg(long)]
        before: Option<String>,
        #[arg(long = "type", value_name = "TYPE", help = MSG_TYPE_HELP, value_parser = clap_parse_msg_type)]
        msg_type: Option<String>,
        /// 输出 JSON（默认 YAML）
        #[arg(long)]
        json: bool,
    },
    /// 搜索消息
    Search {
        /// 搜索关键词
        keyword: String,
        /// 限定聊天（可多次指定）
        #[arg(long = "in", value_name = "CHAT")]
        chats: Vec<String>,
        /// 结果数量
        #[arg(short = 'n', long, default_value = "20")]
        limit: usize,
        /// 起始时间 YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// 结束时间 YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        #[arg(long = "type", value_name = "TYPE", help = MSG_TYPE_HELP, value_parser = clap_parse_msg_type)]
        msg_type: Option<String>,
        /// 输出 JSON（默认 YAML）
        #[arg(long)]
        json: bool,
    },
    /// 查看联系人
    Contacts {
        /// 按名字过滤
        #[arg(short = 'q', long)]
        query: Option<String>,
        /// 显示数量
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        /// 输出 JSON（默认 YAML）
        #[arg(long)]
        json: bool,
    },
    /// 导出聊天记录到文件
    Export {
        /// 聊天对象名称
        chat: String,
        /// 起始时间 YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// 结束时间 YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// 最多导出条数
        #[arg(short = 'n', long, default_value = "500")]
        limit: usize,
        /// 输出格式 [markdown|txt|json|yaml]
        #[arg(short = 'f', long, default_value = "markdown", value_parser = ["markdown", "txt", "json", "yaml"])]
        format: String,
        /// 输出文件（默认 stdout）
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    /// 显示有未读消息的会话
    Unread {
        /// 显示数量
        #[arg(short = 'n', long, default_value = "20")]
        limit: usize,
        /// 按会话类型过滤，逗号分隔。示例：--filter private,group 只看真人的未读
        #[arg(long, value_name = "TYPES", value_delimiter = ',',
              value_parser = ["all", "private", "group", "official", "folded"])]
        filter: Vec<String>,
        /// 输出 JSON（默认 YAML）
        #[arg(long)]
        json: bool,
    },
    /// 查看群成员
    Members {
        /// 群聊名称（支持模糊匹配）
        chat: String,
        /// 输出 JSON（默认 YAML）
        #[arg(long)]
        json: bool,
    },
    /// 获取自上次检查以来的新消息
    NewMessages {
        /// 显示数量上限
        #[arg(short = 'n', long, default_value = "200")]
        limit: usize,
        /// 输出 JSON（默认 YAML）
        #[arg(long)]
        json: bool,
    },
    /// 聊天统计分析
    Stats {
        /// 聊天对象名称（支持模糊匹配）
        chat: String,
        /// 起始时间 YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// 结束时间 YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// 输出 JSON（默认 YAML）
        #[arg(long)]
        json: bool,
    },
    /// 查看微信收藏内容
    Favorites {
        /// 显示数量
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        /// 类型过滤 [text|image|article|card|video]
        #[arg(long = "type", value_name = "TYPE",
              value_parser = ["text","image","article","card","video"])]
        fav_type: Option<String>,
        /// 内容关键词搜索
        #[arg(short = 'q', long)]
        query: Option<String>,
        /// 输出 JSON（默认 YAML）
        #[arg(long)]
        json: bool,
    },
    /// 朋友圈互动通知：别人对我的朋友圈点赞/评论 + 我评过的帖子下的跟帖
    SnsNotifications {
        /// 显示数量
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        /// 起始时间 YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// 结束时间 YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// 包含已读通知（默认仅未读）
        #[arg(long)]
        include_read: bool,
        /// 输出 JSON（默认 YAML）
        #[arg(long)]
        json: bool,
    },
    /// 朋友圈时间线：按时间/作者筛选本地缓存的朋友圈
    SnsFeed {
        /// 显示数量
        #[arg(short = 'n', long, default_value = "20")]
        limit: usize,
        /// 起始时间 YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// 结束时间 YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// 只看指定作者（昵称 / 备注名 / 微信 ID，模糊匹配）
        #[arg(long)]
        user: Option<String>,
        /// 输出 JSON（默认 YAML）
        #[arg(long)]
        json: bool,
    },
    /// 查询公众号文章推送（本地缓存）
    BizArticles {
        /// 显示数量
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        /// 限定公众号（名称模糊匹配）
        #[arg(long)]
        account: Option<String>,
        /// 起始时间 YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// 结束时间 YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// 只看有未读的公众号，每个公众号取最新 1 篇
        #[arg(long)]
        unread: bool,
        /// 输出 JSON（默认 YAML）
        #[arg(long)]
        json: bool,
    },
    /// 朋友圈全文搜索：匹配正文关键词
    SnsSearch {
        /// 关键词
        keyword: String,
        /// 结果数量
        #[arg(short = 'n', long, default_value = "20")]
        limit: usize,
        /// 起始时间 YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// 结束时间 YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// 限定作者（昵称 / 备注名 / 微信 ID）
        #[arg(long)]
        user: Option<String>,
        /// 输出 JSON（默认 YAML）
        #[arg(long)]
        json: bool,
    },
    /// 列出某会话的图片附件，返回不透明 attachment_id
    Attachments {
        /// 会话名称（联系人显示名 / wxid / @chatroom username 都可以）
        chat: String,
        /// 类型（当前仅支持 image）
        #[arg(long = "kind", value_name = "KIND",
              value_parser = ["image", "img"])]
        kinds: Vec<String>,
        /// 显示数量
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        /// 分页偏移
        #[arg(long, default_value = "0")]
        offset: usize,
        /// 起始时间 YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// 结束时间 YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// 输出 JSON（默认 YAML）
        #[arg(long)]
        json: bool,
    },
    /// 把单个 attachment_id 对应的资源解密写到指定文件路径
    Extract {
        /// 由 `wx attachments` 输出的不透明 ID（base64url 字符串）
        attachment_id: String,
        /// 输出文件路径（绝对或相对当前工作目录均可；扩展名建议保留为 .jpg 等）
        #[arg(short = 'o', long)]
        output: String,
        /// 目标已存在时覆盖
        #[arg(long)]
        overwrite: bool,
        /// 输出 JSON（默认 YAML）
        #[arg(long)]
        json: bool,
    },
    /// 管理 wx-daemon
    Daemon {
        #[command(subcommand)]
        cmd: DaemonCommands,
    },
    /// 环境 / 密钥 / 分片健康检查
    Doctor {
        /// 输出 JSON
        #[arg(long)]
        json: bool,
        /// 打印修复建议命令
        #[arg(long)]
        fix: bool,
    },
    /// 密钥管理
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// 跨会话时间线（按时间合并多 chat 消息）
    Timeline {
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        #[arg(long, default_value = "0")]
        offset: usize,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        /// 游标：只返回比该时间更旧的消息
        #[arg(long)]
        after: Option<String>,
        #[arg(long = "type", value_name = "TYPE", help = MSG_TYPE_HELP, value_parser = clap_parse_msg_type)]
        msg_type: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// 实时监听新消息（轮询 session.db）
    Watch {
        /// 轮询间隔毫秒
        #[arg(long, default_value = "1500")]
        interval: u64,
        /// 每轮最多拉取条数
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// 媒体工具（语音等）
    Media {
        #[command(subcommand)]
        action: MediaAction,
    },
}

#[derive(Subcommand)]
enum KeyAction {
    /// 扫描进程内存 / LLDB hook 提取密钥（建议 sudo）
    Extract {
        #[arg(long)]
        hook_seconds: Option<u64>,
    },
    /// 列出 all_keys.json 中的密钥
    List {
        #[arg(long)]
        json: bool,
        /// 输出完整 enc_key（默认仅 preview，防误粘贴泄露）
        #[arg(long)]
        show_secrets: bool,
    },
    /// 手动写入某个 DB 的密钥
    Set {
        /// 相对路径，如 message/message_1.db
        db: String,
        /// 64 位 hex
        enc_key: String,
    },
}

#[derive(Subcommand)]
enum MediaAction {
    /// 按 svr_id 从 message/media_0.db 导出语音 silk 原始数据
    Voice {
        /// 消息 server id / svr_id
        svr_id: i64,
        /// 可选 chat username（加速定位）
        #[arg(long)]
        chat: Option<String>,
        /// 输出路径（.silk）
        #[arg(short = 'o', long)]
        output: String,
    },
}

#[derive(Subcommand)]
pub enum DaemonCommands {
    /// 查看 daemon 运行状态
    Status,
    /// 停止 daemon
    Stop,
    /// 查看 daemon 日志
    Logs {
        /// 持续输出（tail -f）
        #[arg(short = 'f', long)]
        follow: bool,
        /// 显示最近 N 行
        #[arg(short = 'n', long, default_value = "50")]
        lines: usize,
    },
}

pub fn run() {
    let cli = Cli::parse();
    if let Err(e) = dispatch(cli) {
        eprintln!("错误: {}", e);
        std::process::exit(1);
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    if !matches!(&cli.command, Commands::Init { .. } | Commands::Key { action: KeyAction::Extract { .. } }) {
        crate::private_fs::require_unprivileged()?;
    }
    let base_with_meta = cli.with_meta;
    let base_debug_source = cli.debug_source;
    match cli.command {
        Commands::Init {
            force,
            hook_seconds,
        } => init::cmd_init(force, hook_seconds),
        Commands::Sessions { limit, json } => sessions::cmd_sessions(
            limit,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::History {
            chat,
            limit,
            offset,
            since,
            until,
            after,
            before,
            msg_type,
            json,
        } => history::cmd_history(
            chat,
            limit,
            offset,
            since,
            until,
            after,
            before,
            msg_type,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::Search {
            keyword,
            chats,
            limit,
            since,
            until,
            msg_type,
            json,
        } => search::cmd_search(
            keyword,
            chats,
            limit,
            since,
            until,
            msg_type,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::Contacts { query, limit, json } => contacts::cmd_contacts(query, limit, json),
        Commands::Export {
            chat,
            since,
            until,
            limit,
            format,
            output,
        } => {
            let export_json = format == "json";
            export::cmd_export(
                chat,
                since,
                until,
                limit,
                format,
                output,
                OutputOpts {
                    json: export_json,
                    with_meta: base_with_meta,
                    debug_source: base_debug_source,
                },
            )
        }
        Commands::Unread {
            limit,
            filter,
            json,
        } => unread::cmd_unread(
            limit,
            filter,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::Members { chat, json } => members::cmd_members(chat, json),
        Commands::NewMessages { limit, json } => new_messages::cmd_new_messages(
            limit,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::Stats {
            chat,
            since,
            until,
            json,
        } => stats::cmd_stats(
            chat,
            since,
            until,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::Favorites {
            limit,
            fav_type,
            query,
            json,
        } => favorites::cmd_favorites(limit, fav_type, query, json),
        Commands::SnsNotifications {
            limit,
            since,
            until,
            include_read,
            json,
        } => sns_notifications::cmd_sns_notifications(limit, since, until, include_read, json),
        Commands::SnsFeed {
            limit,
            since,
            until,
            user,
            json,
        } => sns_feed::cmd_sns_feed(limit, since, until, user, json),
        Commands::SnsSearch {
            keyword,
            limit,
            since,
            until,
            user,
            json,
        } => sns_search::cmd_sns_search(keyword, limit, since, until, user, json),
        Commands::BizArticles {
            limit,
            account,
            since,
            until,
            unread,
            json,
        } => biz_articles::cmd_biz_articles(limit, account, since, until, unread, json),
        Commands::Attachments {
            chat,
            kinds,
            limit,
            offset,
            since,
            until,
            json,
        } => attachments::cmd_attachments(
            chat,
            kinds,
            limit,
            offset,
            since,
            until,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::Extract {
            attachment_id,
            output,
            overwrite,
            json,
        } => extract::cmd_extract(attachment_id, output, overwrite, json),
        Commands::Daemon { cmd } => daemon_cmd::cmd_daemon(cmd),
        Commands::Doctor { json, fix } => doctor::cmd_doctor(json, fix),
        Commands::Key { action } => match action {
            KeyAction::Extract { hook_seconds } => key_cmd::cmd_key_extract(hook_seconds),
            KeyAction::List { json, show_secrets } => key_cmd::cmd_key_list(json, show_secrets),
            KeyAction::Set { db, enc_key } => key_cmd::cmd_key_set(&db, &enc_key),
        },
        Commands::Timeline {
            limit,
            offset,
            since,
            until,
            after,
            msg_type,
            json,
        } => timeline::cmd_timeline(
            limit,
            offset,
            since,
            until,
            after,
            msg_type,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::Watch {
            interval,
            limit,
            json,
        } => watch::cmd_watch(
            interval,
            limit,
            OutputOpts {
                json,
                with_meta: false,
                debug_source: false,
            },
        ),
        Commands::Media { action } => match action {
            MediaAction::Voice {
                svr_id,
                chat,
                output,
            } => media::cmd_voice_export(svr_id, chat, output),
        },
    }
}

#[cfg(test)]
mod clap_msg_type_wiring_tests {
    use super::Cli;
    use clap::Parser;

    /// Real CLI parse path (not just parse_msg_type helper): clap value_parser must accept
    /// agent type_id round-trips and numeric codes.
    #[test]
    fn history_accepts_appmsg_card_revoke_and_digit_type() {
        for ty in ["appmsg", "card", "revoke", "49", "link", "text"] {
            let cli = Cli::try_parse_from(["wx", "history", "someone", "--type", ty])
                .unwrap_or_else(|e| panic!("--type {ty} must parse: {e}"));
            match cli.command {
                super::Commands::History { msg_type, .. } => {
                    assert_eq!(msg_type.as_deref(), Some(ty));
                }
                _ => panic!("expected History for --type {ty}"),
            }
        }
    }

    #[test]
    fn search_and_timeline_accept_appmsg() {
        let s = Cli::try_parse_from(["wx", "search", "kw", "--type", "appmsg"])
            .expect("search --type appmsg");
        match s.command {
            super::Commands::Search { msg_type, .. } => {
                assert_eq!(msg_type.as_deref(), Some("appmsg"));
            }
            _ => panic!("expected Search"),
        }
        let t = Cli::try_parse_from(["wx", "timeline", "--type", "57"]).expect("timeline --type 57");
        match t.command {
            super::Commands::Timeline { msg_type, .. } => {
                assert_eq!(msg_type.as_deref(), Some("57"));
            }
            _ => panic!("expected Timeline"),
        }
    }

    #[test]
    fn clap_rejects_unknown_type_before_dispatch() {
        let err = match Cli::try_parse_from(["wx", "history", "x", "--type", "nope"]) {
            Ok(_) => panic!("unknown --type must fail at clap parse"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("未知消息类型") || msg.contains("nope"),
            "unexpected error: {msg}"
        );
    }
}
