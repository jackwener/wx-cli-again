/// macOS WeChat 进程内存密钥扫描器
///
/// 两阶段提取（**都不依赖关闭 SIP**；SIP 保护的是系统组件，不是读微信内存的开关）：
/// 1. **内存扫描**（需要 `task_for_pid`：通常 = 本机 GUI Terminal + sudo + 开发者工具 TCC）
///    - 搜索 `x'<64hex_key><32hex_salt>'` 传统 WCDB 缓存格式
///    - 按每个 DB 的 16-byte salt 在堆中找相邻 32-byte raw key
/// 2. **LLDB hook**（补齐冷分片密钥：用户滚动/打开会话时触发 DB 打开）
///    - attach 到 WeChat，hook CommonCrypto `CCCryptorCreate` 等
///    - 捕获 32-byte AES key，用 SQLCipher 4 HMAC 与磁盘 DB 匹配
///    - Hardened Runtime 官方包建议 sudo；部分官网包本身 ad-hoc，用户态 LLDB 即可
///
/// 官方 Hardened Runtime 包在本机 GUI Terminal + sudo 下通常可 `task_for_pid`；
/// 部分官网包本身就是 ad-hoc，无需也不应再重签。
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use super::{
    collect_db_salts, collect_salt_adjacent_keys, decode_salt_hex, match_key_hexes, unique_key_hexes,
    scan_key_patterns, KeyEntry, MAX_PATTERN_BYTES,
};

// Mach 相关常量
const KERN_SUCCESS: i32 = 0;
const VM_PROT_READ: i32 = 1;
const VM_PROT_WRITE: i32 = 2;
const VM_REGION_BASIC_INFO_64: i32 = 9;
const CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2MB

// vm_region_basic_info_64 结构体
#[repr(C)]
struct VmRegionBasicInfo64 {
    protection: i32,
    max_protection: i32,
    inheritance: u32,
    shared: u32,
    reserved: u32,
    _offset: u64,
    behavior: i32,
    user_wired_count: u16,
}

// Mach FFI 声明
#[allow(non_camel_case_types)]
type kern_return_t = i32;
#[allow(non_camel_case_types)]
type mach_port_t = u32;
#[allow(non_camel_case_types)]
type mach_vm_address_t = u64;
#[allow(non_camel_case_types)]
type mach_vm_size_t = u64;
#[allow(non_camel_case_types)]
type mach_msg_type_number_t = u32;
#[allow(non_camel_case_types)]
type vm_offset_t = usize;
#[allow(non_camel_case_types, dead_code)]
type vm_prot_t = i32;

#[derive(Clone, Copy)]
enum SignatureKind {
    AdHoc,
    HardenedRuntime,
    Unknown,
}

extern "C" {
    fn mach_task_self() -> mach_port_t;
    fn task_for_pid(host: mach_port_t, pid: libc::pid_t, task: *mut mach_port_t) -> kern_return_t;
    fn mach_vm_region(
        task: mach_port_t,
        address: *mut mach_vm_address_t,
        size: *mut mach_vm_size_t,
        flavor: i32,
        info: *mut VmRegionBasicInfo64,
        info_count: *mut mach_msg_type_number_t,
        obj_name: *mut mach_port_t,
    ) -> kern_return_t;
    fn mach_vm_read(
        task: mach_port_t,
        addr: mach_vm_address_t,
        size: mach_vm_size_t,
        data: *mut vm_offset_t,
        data_cnt: *mut mach_msg_type_number_t,
    ) -> kern_return_t;
    fn mach_vm_deallocate(
        task: mach_port_t,
        addr: mach_vm_address_t,
        size: mach_vm_size_t,
    ) -> kern_return_t;
}

/// 查找 WeChat 进程的 PID
fn find_wechat_pid() -> Option<libc::pid_t> {
    // 使用 pgrep -x WeChat 查找（与 C 版本一致）
    let output = std::process::Command::new("pgrep")
        .args(["-x", "WeChat"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout);
    s.trim().parse().ok()
}

/// 默认 LLDB hook 等待秒数（给用户时间在微信里滚动历史、打开会话）。
pub const DEFAULT_HOOK_SECONDS: u64 = 45;

#[allow(dead_code)]
pub fn scan_keys(db_dir: &Path) -> Result<Vec<KeyEntry>> {
    scan_keys_with_options(db_dir, DEFAULT_HOOK_SECONDS, true, &[])
}

/// `hook_seconds == 0` 时跳过 LLDB hook；`auto_hook` 为 false 时即使匹配不全也不 hook。
/// `known` 为已有仍有效的密钥，用于判断是否还需要 hook 补齐。
pub fn scan_keys_with_options(
    db_dir: &Path,
    hook_seconds: u64,
    auto_hook: bool,
    known: &[KeyEntry],
) -> Result<Vec<KeyEntry>> {
    let is_root = unsafe { libc::geteuid() } == 0;

    // 1. 查找 WeChat PID
    let pid = find_wechat_pid().context("找不到 WeChat 进程，请确认 WeChat 正在运行")?;
    eprintln!("WeChat PID: {}", pid);
    let signature = detect_signature(pid);
    match signature {
        SignatureKind::AdHoc => eprintln!("WeChat 签名: ad-hoc（无需再次签名；用户态 LLDB 通常可附加）"),
        SignatureKind::HardenedRuntime => {
            eprintln!("WeChat 签名: 官方 Hardened Runtime（内存扫描需要 sudo；hook 也建议 sudo）")
        }
        SignatureKind::Unknown => eprintln!("WeChat 签名: 未能识别（继续尝试）"),
    }

    eprintln!("扫描数据库文件...");
    let db_salts = collect_db_salts(db_dir);
    eprintln!("找到 {} 个加密数据库", db_salts.len());
    if db_salts.is_empty() {
        bail!("数据目录中没有加密的 .db 文件: {}", db_dir.display());
    }

    let salt_bytes: Vec<[u8; 16]> = db_salts
        .iter()
        .filter_map(|(s, _)| decode_salt_hex(s))
        .collect();

    let mut raw_keys: Vec<(String, String)> = Vec::new();
    let mut extra_keys: Vec<String> = Vec::new();
    let mut seen_extra: HashSet<String> = HashSet::new();

    // ── Phase 1: 进程内存扫描（需要 task_for_pid） ─────────────────────
    if is_root {
        let task = obtain_task_port(pid, signature)?;
        eprintln!("Got task port: {}", task);
        eprintln!("扫描进程内存寻找密钥（x'hex' + salt 邻接）...");
        let scanned = scan_memory(task, &salt_bytes, &mut raw_keys, &mut extra_keys, &mut seen_extra)?;
        eprintln!(
            "内存扫描完成：x'hex' 候选 {} 个，salt 邻接候选 {} 个（读取约 {:.1} MB）",
            raw_keys.len(),
            extra_keys.len(),
            scanned as f64 / (1024.0 * 1024.0)
        );
    } else {
        eprintln!(
            "当前非 root：跳过 Mach 内存扫描。若 WeChat 为 ad-hoc 签名，将仅依赖 LLDB hook。"
        );
        if !matches!(signature, SignatureKind::AdHoc) && hook_seconds == 0 {
            bail!(
                "读取 WeChat 进程内存需要 root 权限，请从本机 Terminal 运行：\n\
                 {}\n\
                 若使用官网 ad-hoc 包，也可不加 sudo：\n\
                 wx key extract --hook-seconds 60",
                crate::config::RECOMMENDED_KEY_EXTRACT
            );
        }
    }

    // 合并候选并匹配
    let mut all_key_hexes = unique_key_hexes(&raw_keys);
    for k in &extra_keys {
        if !all_key_hexes.iter().any(|x| x == k) {
            all_key_hexes.push(k.clone());
        }
    }

    let mut entries = if raw_keys.is_empty() && all_key_hexes.is_empty() {
        Vec::new()
    } else {
        match_key_hexes(db_dir, &all_key_hexes, &raw_keys, &db_salts)
    };

    // 把已有有效密钥并入，避免已配齐时还去 hook
    if !known.is_empty() {
        let mut by_name: std::collections::BTreeMap<String, KeyEntry> = known
            .iter()
            .cloned()
            .map(|e| (e.db_name.clone(), e))
            .collect();
        for e in entries {
            by_name.insert(e.db_name.clone(), e);
        }
        entries = by_name.into_values().collect();
    }

    eprintln!(
        "内存阶段匹配到 {}/{} 个数据库密钥（候选 key {} 个，含已有密钥）",
        entries.len(),
        db_salts.len(),
        all_key_hexes.len()
    );

    // ── Phase 2: LLDB CommonCrypto hook 补齐冷分片 ───────────────────
    let covered: HashSet<&str> = entries.iter().map(|e| e.db_name.as_str()).collect();
    let still_missing: Vec<&(String, String)> = db_salts
        .iter()
        .filter(|(_, name)| !covered.contains(name.as_str()))
        .collect();
    if auto_hook && hook_seconds > 0 && !still_missing.is_empty() {
        eprintln!(
            "仍有 {} 个数据库未匹配密钥，启动 LLDB hook {}s…\n\
             请在此期间切换到微信：滚动聊天列表、打开几个会话/历史记录，\n\
             以触发冷分片 DB 的解密（message_N.db 等）。",
            still_missing.len(),
            hook_seconds
        );
        match hook_keys_via_lldb(
            pid,
            hook_seconds,
            is_root || matches!(signature, SignatureKind::AdHoc),
        ) {
            Ok(hooked) => {
                eprintln!("LLDB hook 捕获到 {} 个 32-byte key", hooked.len());
                // 只对仍缺的 DB 做匹配，加快速度
                let missing_salts: Vec<(String, String)> = still_missing
                    .iter()
                    .map(|(s, n)| ((*s).clone(), (*n).clone()))
                    .collect();
                let hooked_entries = match_key_hexes(db_dir, &hooked, &[], &missing_salts);
                let mut by_name: std::collections::BTreeMap<String, KeyEntry> = entries
                    .into_iter()
                    .map(|e| (e.db_name.clone(), e))
                    .collect();
                for e in hooked_entries {
                    by_name.insert(e.db_name.clone(), e);
                }
                entries = by_name.into_values().collect();
            }
            Err(e) => {
                eprintln!("LLDB hook 未成功: {:#}", e);
                eprintln!(
                    "提示: 确认已安装 Xcode CLT（xcode-select --install），\n\
                     Hardened Runtime 包请使用 sudo；ad-hoc 包可直接用户态 lldb。"
                );
            }
        }
    }

    eprintln!(
        "最终匹配到 {}/{} 个数据库密钥",
        entries.len(),
        db_salts.len()
    );

    // 兼容旧返回路径：若完全失败且非 root，给出清晰错误
    if entries.is_empty() && !is_root && !matches!(signature, SignatureKind::AdHoc) {
        bail!(
            "未能提取任何密钥。请从本机 Terminal 运行：\n\
             {}\n\
             等待期间在微信中打开/滚动相关聊天以触发冷分片加载。\n\
             SIP 无需关闭；不要预先 ad-hoc 重签官方包。",
            crate::config::RECOMMENDED_KEY_EXTRACT_HINT
        );
    }

    Ok(entries)
}

fn obtain_task_port(pid: libc::pid_t, signature: SignatureKind) -> Result<mach_port_t> {
    // SAFETY: task_for_pid 是标准 Mach API，参数合法
    let mut task: mach_port_t = 0;
    let kr = unsafe { task_for_pid(mach_task_self(), pid, &mut task) };
    if kr == KERN_SUCCESS {
        return Ok(task);
    }
    let advice = match signature {
        SignatureKind::AdHoc => {
            "当前 WeChat 已是 ad-hoc，重复签名没有帮助。请确认命令来自本机 GUI \
             Terminal，并在系统提示时允许「开发者工具」权限。"
        }
        SignatureKind::HardenedRuntime => {
            "当前 WeChat 是官方 Hardened Runtime 签名。请从本机 GUI Terminal \
             重试，并在「隐私与安全性 → 开发者工具」中允许该 Terminal。只有 SSH \
             等无 GUI 场景仍被拒绝时，才考虑有副作用的 ad-hoc 重签。"
        }
        SignatureKind::Unknown => {
            "请从本机 GUI Terminal 重试，并检查「隐私与安全性 → 开发者工具」权限。"
        }
    };
    bail!(
        "task_for_pid 失败 (kr={})。\n{}\n\
         SIP 无需关闭；wx-cli 不会自动修改 WeChat.app。",
        kr,
        advice
    )
}

fn detect_signature(pid: libc::pid_t) -> SignatureKind {
    let process = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output();
    let Ok(process) = process else {
        return SignatureKind::Unknown;
    };
    let executable = String::from_utf8_lossy(&process.stdout);
    let executable = executable.trim();
    if executable.is_empty() {
        return SignatureKind::Unknown;
    }

    let output = std::process::Command::new("codesign")
        .args(["-dvv", executable])
        .output();
    let Ok(output) = output else {
        return SignatureKind::Unknown;
    };
    let details = String::from_utf8_lossy(&output.stderr);
    parse_signature_details(&details)
}

fn parse_signature_details(details: &str) -> SignatureKind {
    if details.contains("Signature=adhoc") || details.contains("(adhoc)") {
        SignatureKind::AdHoc
    } else if details.contains("(runtime)") || details.contains("flags=0x10000") {
        SignatureKind::HardenedRuntime
    } else {
        SignatureKind::Unknown
    }
}

/// 扫描进程内存。
///
/// - `raw_keys`: `x'<key><salt>'` 字符串模式
/// - `extra_keys`: salt 邻接的 binary 32-byte key
/// - 返回值：成功读取的总字节数
fn scan_memory(
    task: mach_port_t,
    salts: &[[u8; 16]],
    raw_keys: &mut Vec<(String, String)>,
    extra_keys: &mut Vec<String>,
    seen_extra: &mut HashSet<String>,
) -> Result<u64> {
    let mut addr: mach_vm_address_t = 0;
    let mut bytes_read: u64 = 0;

    // VM_REGION_BASIC_INFO_COUNT_64 = 9（来自 <mach/vm_region.h>，固定值，不能用 sizeof 计算）
    let info_count_expected: mach_msg_type_number_t = 9;

    loop {
        let mut size: mach_vm_size_t = 0;
        let mut info = VmRegionBasicInfo64 {
            protection: 0,
            max_protection: 0,
            inheritance: 0,
            shared: 0,
            reserved: 0,
            _offset: 0,
            behavior: 0,
            user_wired_count: 0,
        };
        let mut info_count: mach_msg_type_number_t = info_count_expected;
        let mut obj_name: mach_port_t = 0;

        // SAFETY: mach_vm_region 枚举虚拟内存区域，所有参数合法
        let kr = unsafe {
            mach_vm_region(
                task,
                &mut addr,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                &mut info,
                &mut info_count,
                &mut obj_name,
            )
        };

        if kr != KERN_SUCCESS {
            break;
        }
        if size == 0 {
            addr = addr.saturating_add(1);
            continue;
        }

        // 堆上密钥：优先 RW；也扫只读区域中较小的块（部分缓存）
        let readable = (info.protection & VM_PROT_READ) != 0;
        let writable = (info.protection & VM_PROT_WRITE) != 0;
        let scan_it = readable
            && (writable || size <= 64 * 1024 * 1024)
            && size > 0
            && size < 512 * 1024 * 1024;
        if scan_it {
            bytes_read += scan_region(task, addr, size, salts, raw_keys, extra_keys, seen_extra);
        }

        addr = addr.saturating_add(size);
    }

    Ok(bytes_read)
}

/// 扫描单个内存区域，按 CHUNK_SIZE 分块读取
fn scan_region(
    task: mach_port_t,
    addr: mach_vm_address_t,
    size: mach_vm_size_t,
    salts: &[[u8; 16]],
    raw_keys: &mut Vec<(String, String)>,
    extra_keys: &mut Vec<String>,
    seen_extra: &mut HashSet<String>,
) -> u64 {
    let end = addr + size;
    let mut ca = addr;
    let mut bytes_read: u64 = 0;

    while ca < end {
        let cs = std::cmp::min(end - ca, CHUNK_SIZE as u64);

        let mut data: vm_offset_t = 0;
        let mut dc: mach_msg_type_number_t = 0;

        // SAFETY: mach_vm_read 读取目标进程内存到内核缓冲区，
        // 返回的 data 指针指向通过 vm_allocate 分配的内存，
        // 必须用 mach_vm_deallocate 释放
        let kr = unsafe { mach_vm_read(task, ca, cs, &mut data, &mut dc) };

        if kr == KERN_SUCCESS {
            // SAFETY: data 是 mach_vm_read 返回的有效指针，dc 是字节数
            let buf: &[u8] = unsafe { std::slice::from_raw_parts(data as *const u8, dc as usize) };

            search_pattern(buf, raw_keys);
            collect_salt_adjacent_keys(buf, salts, extra_keys, seen_extra);
            bytes_read += dc as u64;

            // SAFETY: 释放 mach_vm_read 分配的内核内存
            unsafe {
                mach_vm_deallocate(mach_task_self(), data as u64, dc as u64);
            }
        }

        // 保留最大 pattern 长度以处理跨块边界
        let overlap = MAX_PATTERN_BYTES;
        if cs as usize > overlap {
            ca += cs - overlap as u64;
        } else {
            ca += cs;
        }
    }
    bytes_read
}

/// 通过 LLDB 在用户/root 态 hook CommonCrypto，捕获 AES-256 key。
///
/// 微信 4.x（尤其是 Tencent 官网 ad-hoc 包）在打开加密 DB 时会调用
/// `CCCryptorCreate` / `CCCryptorCreateWithMode`；此时 keyLength==32。
///
/// 脚本在 `seconds` 后自动 `process detach`，避免强杀 lldb 把微信留在 SIGSTOP。
fn hook_keys_via_lldb(pid: libc::pid_t, seconds: u64, allow_user: bool) -> Result<Vec<String>> {
    let lldb = find_lldb()
        .context("找不到 lldb。请安装 Xcode Command Line Tools：xcode-select --install")?;

    let hook_dir = tempfile::Builder::new().prefix("wx-cli-hook-").tempdir()?;
    let tmp_dir = hook_dir.path();
    let script_path = tmp_dir.join("wx_hook.py");
    let keys_path = tmp_dir.join("keys.txt");
    let done_path = tmp_dir.join("done");
    crate::private_fs::create_new(&keys_path)?;
    std::fs::write(
        &script_path,
        lldb_hook_script(
            keys_path.to_string_lossy().as_ref(),
            done_path.to_string_lossy().as_ref(),
            seconds,
        ),
    )?;

    if !allow_user && unsafe { libc::geteuid() } != 0 {
        bail!("LLDB hook 需要 root 或 ad-hoc 签名的 WeChat");
    }

    let mut cmd = Command::new(&lldb);
    cmd.args([
        "-p",
        &pid.to_string(),
        "--batch",
        "-o",
        &format!("command script import {}", script_path.display()),
        "-o",
        "process continue",
    ]);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());

    eprintln!("LLDB: {} -p {} （等待 {}s，到期自动 detach）", lldb.display(), pid, seconds);
    let mut child = cmd.spawn().context("启动 lldb 失败")?;

    // 多等几秒给 detach/quit 收尾
    let wait_budget = Duration::from_secs(seconds + 15);
    let started = std::time::Instant::now();
    loop {
        if done_path.exists() {
            // 给 quit 一点时间
            std::thread::sleep(Duration::from_millis(500));
            let _ = child.try_wait();
            break;
        }
        if let Some(status) = child.try_wait()? {
            if !status.success() && !keys_path.exists() {
                let mut stderr = String::new();
                if let Some(mut s) = child.stderr.take() {
                    use std::io::Read;
                    let _ = s.read_to_string(&mut stderr);
                }
                bail!(
                    "lldb 退出异常: {} {}",
                    status,
                    stderr.chars().take(400).collect::<String>()
                );
            }
            break;
        }
        if started.elapsed() > wait_budget {
            eprintln!("LLDB 超时，尝试终止…");
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    // 确保子进程回收
    let _ = child.wait();

    let content = std::fs::read_to_string(&keys_path).unwrap_or_default();
    let mut keys = Vec::new();
    let mut seen = HashSet::new();
    for line in content.lines() {
        let line = line.trim().to_lowercase();
        if line.len() == 64
            && line.chars().all(|c| c.is_ascii_hexdigit())
            && seen.insert(line.clone())
        {
            keys.push(line);
        }
    }
    Ok(keys)
}

fn find_lldb() -> Option<PathBuf> {
    let candidates = [
        "lldb",
        "/usr/bin/lldb",
        "/Library/Developer/CommandLineTools/usr/bin/lldb",
        "/Applications/Xcode.app/Contents/Developer/usr/bin/lldb",
        "/opt/homebrew/opt/llvm/bin/lldb",
    ];
    for c in candidates {
        let p = PathBuf::from(c);
        if c == "lldb" {
            if Command::new("which")
                .arg("lldb")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return Some(PathBuf::from("lldb"));
            }
        } else if p.exists() {
            return Some(p);
        }
    }
    None
}

fn lldb_hook_script(keys_path: &str, done_path: &str, seconds: u64) -> String {
    // arm64 ABI:
    //   CCCryptorCreate(op, alg, options, key, keyLength, iv, cryptorRef)
    //     x3=key, x4=keyLength
    //   CCCryptorCreateWithMode(op, mode, alg, padding, iv, key, keyLength, ...)
    //     x5=key, x6=keyLength
    format!(
        r#"# auto-generated by wx-cli
import lldb
import threading
import time

OUT = r"{keys_path}"
DONE = r"{done_path}"
SECONDS = {seconds}
captured = set()
_debugger = None

def _save(hx):
    try:
        with open(OUT, "a") as f:
            f.write(hx + "\n")
    except Exception:
        pass

def _try_read(process, key_ptr, key_len):
    if key_len != 32 or not key_ptr:
        return
    err = lldb.SBError()
    data = process.ReadMemory(key_ptr, 32, err)
    if not err.Success() or not data or len(data) != 32:
        return
    hx = bytes(data).hex()
    if hx in captured:
        return
    captured.add(hx)
    print("[wx-cli hook] key " + hx, flush=True)
    _save(hx)

def on_cc(frame, bp_loc, _dict):
    try:
        process = frame.GetThread().GetProcess()
        arch = process.GetTarget().GetTriple()
        if "arm64" in arch or "aarch64" in arch:
            x3 = frame.FindRegister("x3").GetValueAsUnsigned()
            x4 = frame.FindRegister("x4").GetValueAsUnsigned()
            x5 = frame.FindRegister("x5").GetValueAsUnsigned()
            x6 = frame.FindRegister("x6").GetValueAsUnsigned()
            _try_read(process, x3, x4)
            _try_read(process, x5, x6)
        else:
            rcx = frame.FindRegister("rcx").GetValueAsUnsigned()
            r8 = frame.FindRegister("r8").GetValueAsUnsigned()
            r9 = frame.FindRegister("r9").GetValueAsUnsigned()
            _try_read(process, rcx, r8)
            _try_read(process, r9, 32)
    except Exception as e:
        print("[wx-cli hook] err " + str(e), flush=True)
    return False

def _finish():
    time.sleep(SECONDS)
    try:
        if _debugger is not None:
            _debugger.HandleCommand("process detach")
            _debugger.HandleCommand("quit")
    except Exception as e:
        print("[wx-cli hook] detach err " + str(e), flush=True)
    try:
        open(DONE, "w").write("ok\n")
    except Exception:
        pass

def __lldb_init_module(debugger, _internal_dict):
    global _debugger
    _debugger = debugger
    target = debugger.GetSelectedTarget()
    names = [
        "CCCryptorCreate",
        "CCCrypt",
        "CCCryptorCreateWithMode",
        "CCCryptorCreateFromData",
    ]
    for name in names:
        bp = target.BreakpointCreateByName(name)
        n = bp.GetNumLocations()
        if n == 0:
            print("[wx-cli hook] skip " + name, flush=True)
            continue
        bp.SetScriptCallbackFunction(__name__ + ".on_cc")
        bp.SetAutoContinue(True)
        print("[wx-cli hook] " + name + " locs=" + str(n), flush=True)
    open(OUT, "w").close()
    print("[wx-cli hook] ready for %ds → %s" % (SECONDS, OUT), flush=True)
    t = threading.Thread(target=_finish, daemon=True)
    t.start()
"#
    )
}

pub(crate) fn search_pattern(buf: &[u8], results: &mut Vec<(String, String)>) {
    scan_key_patterns(buf, results);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一条合法的 x'<key><salt>' 模式字节串
    fn make_pattern(key: &[u8; 64], salt: &[u8; 32]) -> Vec<u8> {
        let mut v = vec![b'x', b'\''];
        v.extend_from_slice(key);
        v.extend_from_slice(salt);
        v.push(b'\'');
        v
    }

    #[test]
    fn test_search_pattern_basic() {
        let key = [b'a'; 64];
        let salt = [b'b'; 32];
        let buf = make_pattern(&key, &salt);
        let mut results = Vec::new();
        search_pattern(&buf, &mut results);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "a".repeat(64));
        assert_eq!(results[0].1, "b".repeat(32));
    }

    #[test]
    fn test_search_pattern_uppercase_lowercased() {
        // 大写十六进制字符应被统一转为小写
        let key = [b'A'; 64];
        let salt = [b'B'; 32];
        let buf = make_pattern(&key, &salt);
        let mut results = Vec::new();
        search_pattern(&buf, &mut results);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "a".repeat(64));
        assert_eq!(results[0].1, "b".repeat(32));
    }

    #[test]
    fn test_search_pattern_not_all_hex() {
        // 96 个十六进制字符中有一个非法字符 → 不匹配
        let mut buf = vec![b'x', b'\''];
        buf.extend_from_slice(&[b'a'; 95]);
        buf.push(b'g'); // 'g' 不是合法十六进制字符
        buf.push(b'\'');
        let mut results = Vec::new();
        search_pattern(&buf, &mut results);
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_pattern_wrong_closing_quote() {
        // 结尾引号错误 → 不匹配
        let mut buf = vec![b'x', b'\''];
        buf.extend_from_slice(&[b'a'; 96]);
        buf.push(b'"'); // 应为 b'\''
        let mut results = Vec::new();
        search_pattern(&buf, &mut results);
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_pattern_dedup() {
        // 相同模式出现两次 → 只保留一条
        let key = [b'1'; 64];
        let salt = [b'2'; 32];
        let pattern = make_pattern(&key, &salt);
        let mut buf = pattern.clone();
        buf.extend_from_slice(&pattern);
        let mut results = Vec::new();
        search_pattern(&buf, &mut results);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_pattern_multiple_distinct() {
        // 两个不同的合法模式 → 各自独立捕获
        let key1 = [b'a'; 64];
        let salt1 = [b'b'; 32];
        let key2 = [b'c'; 64];
        let salt2 = [b'd'; 32];
        let mut buf = make_pattern(&key1, &salt1);
        buf.extend_from_slice(&make_pattern(&key2, &salt2));
        let mut results = Vec::new();
        search_pattern(&buf, &mut results);
        assert_eq!(results.len(), 2);
        let keys: Vec<&str> = results.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"a".repeat(64).as_str()));
        assert!(keys.contains(&"c".repeat(64).as_str()));
    }

    #[test]
    fn test_search_pattern_embedded_in_garbage() {
        // 模式夹在垃圾字节中间，仍应找到
        let mut buf = vec![0xFFu8; 50];
        let key = [b'e'; 64];
        let salt = [b'f'; 32];
        buf.extend_from_slice(&make_pattern(&key, &salt));
        buf.extend_from_slice(&[0x00u8; 50]);
        let mut results = Vec::new();
        search_pattern(&buf, &mut results);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_pattern_too_short() {
        // 缓冲区太小，无法容纳完整模式
        let buf = [b'x', b'\'', b'a', b'b'];
        let mut results = Vec::new();
        search_pattern(&buf, &mut results);
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_pattern_empty_buf() {
        let mut results = Vec::new();
        search_pattern(&[], &mut results);
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_pattern_real_hex_mix() {
        // 合法的混合大小写十六进制（0-9, a-f, A-F）
        let mut key = [b'0'; 64];
        for (i, c) in b"0123456789abcdefABCDEF0123456789abcdef0123456789abcdef01234567"
            .iter()
            .enumerate()
        {
            if i < 64 {
                key[i] = *c;
            }
        }
        let salt = [b'9'; 32];
        let buf = make_pattern(&key, &salt);
        let mut results = Vec::new();
        search_pattern(&buf, &mut results);
        assert_eq!(results.len(), 1);
        // 结果应全小写
        assert!(results[0]
            .0
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn test_parse_signature_details() {
        assert!(matches!(
            parse_signature_details("flags=0x2(adhoc) Signature=adhoc"),
            SignatureKind::AdHoc
        ));
        assert!(matches!(
            parse_signature_details("flags=0x10000(runtime) Signature size=9174"),
            SignatureKind::HardenedRuntime
        ));
        assert!(matches!(
            parse_signature_details("Identifier=com.tencent.xinWeChat"),
            SignatureKind::Unknown
        ));
    }
}
