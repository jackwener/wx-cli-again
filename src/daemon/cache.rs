use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config;
use crate::crypto;
use crate::crypto::sqlcipher;
use crate::crypto::wal;
use rusqlite::Connection;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MtimeEntry {
    db_mt: u64,
    wal_mt: u64,
    path: String,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    db_mtime: u64,
    wal_mtime: u64,
    decrypted_path: PathBuf,
}

/// `DbCache::get_with_mode()` / `open_query_conn` 本次解析 rel_key 时实际走了哪条路径。
///
/// latency tier:
/// - `Online`：SQLCipher 在线打开加密源（首选，无全量解密）
/// - `CacheHit`：~0ms，只返回已有解密产物
/// - `WalIncremental`：典型 <10s，只在 cached DB 上增量 apply WAL
/// - `FullDecrypt`：最慢路径，大库上可能到 ~120s
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    /// SQLCipher 直接读加密源文件（`sqlite3_key`）。
    Online,
    /// Path 1：主 `.db` 和 WAL 都没变，直接命中缓存。
    CacheHit,
    /// Path 2：主 `.db` 没变、只有 WAL 变了，在 cached DB 上增量 apply。
    WalIncremental,
    /// Path 3：主 `.db` 变了或缓存 miss，重新 full decrypt。
    FullDecrypt,
}

impl CacheMode {
    /// 手工固定为 snake_case 字符串，避免未来给 enum 直接 derive `Serialize`
    /// 时静默改变 wire 形态。
    pub fn as_str(self) -> &'static str {
        match self {
            CacheMode::Online => "online",
            CacheMode::CacheHit => "cache_hit",
            CacheMode::WalIncremental => "wal_incremental",
            CacheMode::FullDecrypt => "full_decrypt",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheResolve {
    pub path: PathBuf,
    pub mode: CacheMode,
}

/// 解密后数据库的 mtime-aware 缓存
///
/// 当数据库文件（.db）或 WAL 文件（.db-wal）的 mtime 发生变化时，
/// 自动重新解密并更新缓存。跨进程重启可通过持久化 mtime 文件复用已解密的 DB。
///
/// **并发**：
/// - Path 2 / Path 3 对同一 `rel_key` 串行（`rel_key_locks`）
/// - 写缓存一律 **temp + atomic rename**，不原地改已打开的解密文件，避免读者撕页
/// - `key_epoch`：`replace_keys` 递增；Path2/3 安装前若 epoch 变了则丢弃产物（防旧 key 写回）
/// - Online open（`open_query_conn` 首选）不持 per-key 锁
pub struct DbCache {
    db_dir: PathBuf,
    cache_dir: PathBuf,
    mtime_file: PathBuf,
    /// rel_key -> enc_key(hex)。`RwLock` 以便 `ReloadConfig` 热更新密钥。
    all_keys: std::sync::RwLock<HashMap<String, String>>,
    /// 密钥世代：`replace_keys` 后 in-flight 解密结果不得再安装。
    key_epoch: AtomicU64,
    inner: Arc<Mutex<HashMap<String, CacheEntry>>>,
    /// per-`rel_key` 写锁：Path2/Path3 持有；不同 DB 仍可并行。
    rel_key_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// 序列化 mtime 持久化，避免并发 save 互相覆盖丢条目。
    save_lock: Mutex<()>,
}

impl DbCache {
    pub async fn new(db_dir: PathBuf, all_keys: HashMap<String, String>) -> Result<Self> {
        Self::with_dirs(db_dir, config::cache_dir(), config::mtime_file(), all_keys).await
    }

    /// 注入 `cache_dir` / `mtime_file`（测试用 + 生产 `new()` 复用）
    pub(crate) async fn with_dirs(
        db_dir: PathBuf,
        cache_dir: PathBuf,
        mtime_file: PathBuf,
        all_keys: HashMap<String, String>,
    ) -> Result<Self> {
        crate::private_fs::ensure_private_dir(&cache_dir)?;

        let cache = DbCache {
            db_dir,
            cache_dir,
            mtime_file,
            all_keys: std::sync::RwLock::new(all_keys),
            key_epoch: AtomicU64::new(0),
            inner: Arc::new(Mutex::new(HashMap::new())),
            rel_key_locks: Mutex::new(HashMap::new()),
            save_lock: Mutex::new(()),
        };

        cache.load_persistent().await;
        Ok(cache)
    }

    fn current_key_epoch(&self) -> u64 {
        self.key_epoch.load(Ordering::Acquire)
    }

    /// Path2/3 安装前：若 `replace_keys` 已推进 epoch，丢弃本次产物。
    fn epoch_still_current(&self, started: u64) -> bool {
        self.current_key_epoch() == started
    }

    /// 取得同一 `rel_key` 共享的 async mutex（Path2/Path3 singleflight）。
    async fn lock_for_rel_key(&self, rel_key: &str) -> Arc<Mutex<()>> {
        let mut map = self.rel_key_locks.lock().await;
        map.entry(rel_key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn cache_tmp_path(final_path: &Path) -> PathBuf {
        let mut name = final_path
            .file_name()
            .map(|s| s.to_os_string())
            .unwrap_or_else(|| "cache.db".into());
        name.push(".tmp");
        final_path.with_file_name(name)
    }

    /// 打开解密产物做 cheap 校验（sqlite_master），防止错 key 粘住 CacheHit。
    fn probe_decrypted_db(path: &Path) -> Result<()> {
        crate::private_fs::secure_existing(path)?;
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .with_context(|| format!("探测打开解密缓存失败: {}", path.display()))?;
        let n: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
            .context("解密缓存 sqlite_master 探测失败（密钥可能错误）")?;
        let _ = n;
        Ok(())
    }

    /// temp → final。Unix 上 rename 替换后旧 fd 仍指向旧 inode；Windows 先删目标。
    fn atomic_install_cache(tmp: &Path, final_path: &Path) -> Result<()> {
        #[cfg(windows)]
        {
            if final_path.exists() {
                let _ = std::fs::remove_file(final_path);
            }
        }
        std::fs::rename(tmp, final_path).with_context(|| {
            format!(
                "原子替换缓存失败: {} → {}",
                tmp.display(),
                final_path.display()
            )
        })?;
        Ok(())
    }

    /// 数据库根目录（即 `<wxchat_base>/db_storage`）。
    /// 上层（attachment resolver）需要 `db_dir.parent()` 来定位 `msg/attach/...` 解密图片。
    pub fn db_dir(&self) -> &Path {
        &self.db_dir
    }

    /// 加密源路径（`db_storage/...`）。
    pub fn source_path(&self, rel_key: &str) -> PathBuf {
        self.db_dir.join(
            rel_key
                .replace('\\', std::path::MAIN_SEPARATOR_STR)
                .replace('/', std::path::MAIN_SEPARATOR_STR),
        )
    }

    pub fn key_hex(&self, rel_key: &str) -> Option<String> {
        self.all_keys
            .read()
            .ok()
            .and_then(|g| g.get(rel_key).cloned())
    }

    /// 热替换密钥映射（`ReloadConfig` / `wx key set`）。
    ///
    /// **顺序（第一性原理）**：必须先写新 keys，再 bump epoch。
    /// 若先 bump epoch 再换 keys，`get_with_mode` 可能 snapshot 到
    /// `(epoch=NEW, key=OLD)`，解密旧 key 后仍能通过 epoch 检查并粘住坏缓存。
    ///
    /// 随后在 `inner` 下 clear，并删除确定性 cache 路径（含 rename 未 insert 孤儿）。
    pub async fn replace_keys(&self, new_keys: HashMap<String, String>) {
        let old_rels: Vec<String> = self
            .all_keys
            .read()
            .ok()
            .map(|g| g.keys().cloned().collect())
            .unwrap_or_default();

        // 1) keys first — readers never see new epoch with old keys
        if let Ok(mut g) = self.all_keys.write() {
            *g = new_keys.clone();
        }
        // 2) then publish epoch — invalidates in-flight snapshots of old generation
        self.key_epoch.fetch_add(1, Ordering::Release);

        let mut stale_paths: Vec<PathBuf> = {
            let mut inner = self.inner.lock().await;
            let paths = inner.values().map(|e| e.decrypted_path.clone()).collect();
            inner.clear();
            paths
        };
        for rel in old_rels.into_iter().chain(new_keys.keys().cloned()) {
            stale_paths.push(self.cache_file_path(&rel));
        }
        stale_paths.sort();
        stale_paths.dedup();
        for p in stale_paths {
            let _ = tokio::fs::remove_file(&p).await;
            let tmp = Self::cache_tmp_path(&p);
            let _ = tokio::fs::remove_file(&tmp).await;
        }
        self.save_persistent().await;
    }

    /// 原子 snapshot `(epoch, key_hex)`：双检 epoch，避免读到换代中间态。
    fn snapshot_key_for_decrypt(&self, rel_key: &str) -> Option<(u64, String)> {
        for _ in 0..16 {
            let e1 = self.current_key_epoch();
            let key = self.key_hex(rel_key)?;
            let e2 = self.current_key_epoch();
            if e1 == e2 {
                return Some((e1, key));
            }
        }
        None
    }

    /// 持 `inner` 时安装：epoch 与 used_key 必须仍匹配当前表。
    /// 通过后 rename tmp→final 并 insert；否则删产物返回 None。
    fn commit_cache_product(
        &self,
        epoch_start: u64,
        used_key_hex: &str,
        rel_key: &str,
        tmp: &Path,
        final_path: &Path,
        db_mt: u64,
        wal_mt: u64,
        mode: CacheMode,
        inner: &mut HashMap<String, CacheEntry>,
    ) -> Result<Option<CacheResolve>> {
        // 锁序：不在持有 all_keys write 时等 inner；此处仅 read keys（replace 不持 write 等 inner）
        let key_ok = self
            .key_hex(rel_key)
            .as_deref()
            .map(|k| k == used_key_hex)
            .unwrap_or(false);
        if !self.epoch_still_current(epoch_start) || !key_ok {
            let _ = std::fs::remove_file(tmp);
            let _ = std::fs::remove_file(final_path);
            return Ok(None);
        }
        if tmp.exists() {
            Self::atomic_install_cache(tmp, final_path)?;
        } else if !final_path.exists() {
            anyhow::bail!("缓存产物缺失: {}", final_path.display());
        }
        // rename 后再确认一次（replace 可能刚结束）
        let key_ok = self
            .key_hex(rel_key)
            .as_deref()
            .map(|k| k == used_key_hex)
            .unwrap_or(false);
        if !self.epoch_still_current(epoch_start) || !key_ok {
            let _ = std::fs::remove_file(final_path);
            return Ok(None);
        }
        inner.insert(
            rel_key.to_string(),
            CacheEntry {
                db_mtime: db_mt,
                wal_mtime: wal_mt,
                decrypted_path: final_path.to_path_buf(),
            },
        );
        Ok(Some(CacheResolve {
            path: final_path.to_path_buf(),
            mode,
        }))
    }

    /// 查询用连接：优先 SQLCipher 在线打开加密源，失败再退回解密缓存。
    ///
    /// 大库（message_0/1）上 online 路径避免 10s+ 全量解密。
    pub async fn open_query_conn(&self, rel_key: &str) -> Result<Option<(Connection, CacheMode)>> {
        let Some(key_hex) = self.key_hex(rel_key) else {
            return Ok(None);
        };
        let src = self.source_path(rel_key);
        if !src.exists() {
            return Ok(None);
        }

        let src2 = src.clone();
        let key2 = key_hex.clone();
        let online = tokio::task::spawn_blocking(move || sqlcipher::open_encrypted_readonly(&src2, &key2))
            .await
            .context("online open task join failed")?;

        match online {
            Ok(conn) => {
                // 不刷屏：仅在 debug 或首次可考虑日志；这里用安静路径
                return Ok(Some((conn, CacheMode::Online)));
            }
            Err(e) => {
                eprintln!(
                    "[cache] online 打开失败 {}，回退解密缓存: {:#}",
                    rel_key, e
                );
            }
        }

        let resolved = self.get_with_mode(rel_key).await?;
        let Some(r) = resolved else {
            return Ok(None);
        };
        let path = r.path.clone();
        let mode = r.mode;
        let conn = tokio::task::spawn_blocking(move || Connection::open(&path))
            .await
            .context("open cached db task join failed")??;
        Ok(Some((conn, mode)))
    }

    fn cache_file_path(&self, rel_key: &str) -> PathBuf {
        let hash = format!("{:x}", md5::compute(rel_key.as_bytes()));
        self.cache_dir.join(format!("{}.db", hash))
    }

    /// 从持久化文件加载 mtime 记录，复用未过期的解密文件
    async fn load_persistent(&self) {
        let mtime_file = &self.mtime_file;
        let content = match tokio::fs::read_to_string(&mtime_file).await {
            Ok(c) => c,
            Err(_) => return,
        };
        let saved: HashMap<String, MtimeEntry> = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return,
        };

        let mut inner = self.inner.lock().await;
        let mut reused = 0usize;
        for (rel_key, entry) in &saved {
            let dec_path = PathBuf::from(&entry.path);
            // An edited mtime index must never make us open or delete arbitrary paths.
            if dec_path != self.cache_file_path(rel_key) || !dec_path.exists() {
                continue;
            }
            // 跳过无法打开的旧坏缓存（错 key 时代写入的 SQLITE_HDR 垃圾）
            if Self::probe_decrypted_db(&dec_path).is_err() {
                let _ = std::fs::remove_file(&dec_path);
                continue;
            }
            let db_path = self.db_dir.join(
                rel_key
                    .replace('\\', std::path::MAIN_SEPARATOR_STR)
                    .replace('/', std::path::MAIN_SEPARATOR_STR),
            );
            let wal_path = wal_path_for(&db_path);

            let db_mt = mtime_nanos(&db_path);
            let _wal_mt = if wal_path.exists() {
                mtime_nanos(&wal_path)
            } else {
                0
            };

            // 只要主 .db 没变，就把 cached 产物载回来。
            // 如果 WAL mtime 变了，后续 `get()` 会自动走 Path 2：在已有 cached DB 上增量 apply_wal，
            // 而不是 daemon 重启后第一条请求又退回全量解密。
            if db_mt == entry.db_mt {
                inner.insert(
                    rel_key.clone(),
                    CacheEntry {
                        db_mtime: db_mt,
                        // 保留"cached 产物构建时看到的 wal_mtime"，让 `get()` 去比较当前 WAL
                        // 是否发生了变化，从而决定 exact-hit 还是 WAL 增量。
                        wal_mtime: entry.wal_mt,
                        decrypted_path: dec_path,
                    },
                );
                reused += 1;
            }
        }
        if reused > 0 {
            eprintln!("[cache] 复用 {} 个已解密 DB", reused);
        }
    }

    /// 持久化 mtime 记录
    async fn save_persistent(&self) {
        let _save = self.save_lock.lock().await;
        let mtime_file = &self.mtime_file;
        let data: HashMap<String, MtimeEntry> = {
            let inner = self.inner.lock().await;
            inner
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        MtimeEntry {
                            db_mt: v.db_mtime,
                            wal_mt: v.wal_mtime,
                            path: v.decrypted_path.to_string_lossy().into_owned(),
                        },
                    )
                })
                .collect()
        };

        if let Ok(json) = serde_json::to_string_pretty(&data) {
            let _ = crate::private_fs::write_private(mtime_file, json);
        }
    }

    /// 获取解密后的数据库路径
    ///
    /// 三种命中路径：
    /// 1. 主 `.db` 和 WAL mtime 都未变 → 直接返回缓存路径
    /// 2. 主 `.db` 未变、WAL mtime 变了 → 在已有 cached 产物上**增量** `apply_wal`
    ///    （apply_wal 是幂等的：旧帧 redo 同样的 page 写入，新帧追加生效；不重新 full_decrypt）
    /// 3. 主 `.db` mtime 变了 → 重新 `full_decrypt` + `apply_wal`
    ///
    /// WeChat 在写消息时只 append WAL（除非触发 checkpoint），因此 path 2 是常态；
    /// 这条路径把"每次请求都全量解密 ~1.8GB DB（~120s）"压到"只解 WAL 帧（典型 < 10s）"。
    pub async fn get(&self, rel_key: &str) -> Result<Option<PathBuf>> {
        Ok(self.get_with_mode(rel_key).await?.map(|r| r.path))
    }

    pub async fn get_with_mode(&self, rel_key: &str) -> Result<Option<CacheResolve>> {
        let Some((epoch_start, enc_key_hex)) = self.snapshot_key_for_decrypt(rel_key) else {
            return Ok(None);
        };

        let db_path = self.db_dir.join(
            rel_key
                .replace('\\', std::path::MAIN_SEPARATOR_STR)
                .replace('/', std::path::MAIN_SEPARATOR_STR),
        );
        if !db_path.exists() {
            return Ok(None);
        }

        let wal_path = wal_path_for(&db_path);
        let db_mt = mtime_nanos(&db_path);
        let wal_mt = if wal_path.exists() {
            mtime_nanos(&wal_path)
        } else {
            0
        };

        // Path 1 fast path：不持 per-key 锁（只读，无写缓存文件）
        {
            let cached = {
                let inner = self.inner.lock().await;
                inner.get(rel_key).cloned()
            };
            if let Some(entry) = cached {
                if entry.db_mtime == db_mt
                    && entry.wal_mtime == wal_mt
                    && entry.decrypted_path.exists()
                {
                    return Ok(Some(CacheResolve {
                        path: entry.decrypted_path,
                        mode: CacheMode::CacheHit,
                    }));
                }
            }
        }

        // Path 2 / Path 3：写缓存文件。同一 rel_key 串行，避免并发撕页。
        let key_lock = self.lock_for_rel_key(rel_key).await;
        let _guard = key_lock.lock().await;

        // 锁后：密钥可能已被 replace_keys 换掉
        if !self.epoch_still_current(epoch_start) {
            return Ok(None);
        }

        // 锁后再读 mtime / entry（前一任务可能已写完）
        let db_mt = mtime_nanos(&db_path);
        let wal_mt = if wal_path.exists() {
            mtime_nanos(&wal_path)
        } else {
            0
        };
        let cached = {
            let inner = self.inner.lock().await;
            inner.get(rel_key).cloned()
        };

        let enc_key_bytes =
            hex_to_32bytes(&enc_key_hex).with_context(|| format!("密钥格式错误: {}", rel_key))?;

        if let Some(entry) = cached.as_ref() {
            if entry.db_mtime == db_mt && entry.decrypted_path.exists() {
                if entry.wal_mtime == wal_mt {
                    return Ok(Some(CacheResolve {
                        path: entry.decrypted_path.clone(),
                        mode: CacheMode::CacheHit,
                    }));
                }

                // Path 2: 只写 temp；epoch+inner 锁下才 rename 安装
                let out_path = entry.decrypted_path.clone();
                let t0 = std::time::Instant::now();
                let tmp = Self::cache_tmp_path(&out_path);
                let out_src = out_path.clone();
                let tmp2 = tmp.clone();
                let wal_path2 = wal_path.clone();
                let key_copy = enc_key_bytes;
                tokio::task::spawn_blocking(move || {
                    if tmp2.exists() {
                        let _ = std::fs::remove_file(&tmp2);
                    }
                    crate::private_fs::copy_private(&out_src, &tmp2).with_context(|| {
                        format!("复制缓存到 temp 失败: {}", out_src.display())
                    })?;
                    if wal_path2.exists() {
                        wal::apply_wal(&wal_path2, &tmp2, &key_copy)?;
                    }
                    Self::probe_decrypted_db(&tmp2)?;
                    Ok::<_, anyhow::Error>(())
                })
                .await??;
                eprintln!(
                    "[cache] WAL 增量 {} ({}ms)",
                    rel_key,
                    t0.elapsed().as_millis()
                );

                let committed = {
                    let mut inner = self.inner.lock().await;
                    self.commit_cache_product(
                        epoch_start,
                        &enc_key_hex,
                        rel_key,
                        &tmp,
                        &out_path,
                        db_mt,
                        wal_mt,
                        CacheMode::WalIncremental,
                        &mut inner,
                    )?
                };
                if committed.is_some() {
                    self.save_persistent().await;
                }
                return Ok(committed);
            }
        }

        // Path 3: 全量解密只落 temp；持 inner 校验 epoch+key 后才 rename+insert
        let out_path = self.cache_file_path(rel_key);
        let t0 = std::time::Instant::now();
        let db_path2 = db_path.clone();
        let tmp = Self::cache_tmp_path(&out_path);
        let tmp2 = tmp.clone();
        let wal_path3 = wal_path.clone();
        let key_copy = enc_key_bytes;
        tokio::task::spawn_blocking(move || {
            if !crypto::validate_raw_key_for_db(&db_path2, &key_copy) {
                anyhow::bail!(
                    "密钥无法通过源库 HMAC/页头校验: {}（请 {} 或 wx key set）",
                    db_path2.display(),
                    crate::config::RECOMMENDED_KEY_EXTRACT
                );
            }
            if tmp2.exists() {
                let _ = std::fs::remove_file(&tmp2);
            }
            crypto::full_decrypt(&db_path2, &tmp2, &key_copy)?;
            if wal_path3.exists() {
                wal::apply_wal(&wal_path3, &tmp2, &key_copy)?;
            }
            Self::probe_decrypted_db(&tmp2)?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;

        eprintln!(
            "[cache] 全量解密 {} ({}ms)",
            rel_key,
            t0.elapsed().as_millis()
        );

        let committed = {
            let mut inner = self.inner.lock().await;
            self.commit_cache_product(
                epoch_start,
                &enc_key_hex,
                rel_key,
                &tmp,
                &out_path,
                db_mt,
                wal_mt,
                CacheMode::FullDecrypt,
                &mut inner,
            )?
        };
        if committed.is_some() {
            self.save_persistent().await;
        }
        Ok(committed)
    }
}

pub(super) fn mtime_nanos(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        })
        .unwrap_or(0)
}

/// `foo/bar.db` → `foo/bar.db-wal`（用 OsString 拼接，避免 display() 的 UTF-8 问题）
fn wal_path_for(db_path: &Path) -> PathBuf {
    let mut name = db_path.file_name().unwrap_or_default().to_os_string();
    name.push("-wal");
    db_path.with_file_name(name)
}

fn hex_to_32bytes(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        anyhow::bail!("密钥 hex 长度应为 64，实际为 {}", s.len());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("非法 hex 字符 at {}", i * 2))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 64 字符 hex（测试用假 key；Path3 会在 HMAC 校验处拒绝）
    const FAKE_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn unique_tmpdir(tag: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("wx-cli-cache-test-{}-{}-{}", tag, pid, nanos));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// 写入最小合法 SQLite 文件（Path2 probe / CacheHit 内容校验用）
    fn write_minimal_sqlite(path: &Path, marker: &str) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch("CREATE TABLE t(x TEXT);")
            .unwrap();
        conn.execute("INSERT INTO t(x) VALUES (?1)", [marker])
            .unwrap();
    }

    fn sqlite_marker(path: &Path) -> String {
        let conn = Connection::open(path).unwrap();
        conn.query_row("SELECT x FROM t LIMIT 1", [], |r| r.get(0))
            .unwrap()
    }

    /// 准备一份 "DbCache 已经 reuse 了 cached 解密产物" 的初始状态。
    /// 返回 (cache, db_path, decrypted_path, mtime_file, rel_key)。
    async fn setup_seeded_cache(tag: &str) -> (DbCache, PathBuf, PathBuf, PathBuf, String) {
        let root = unique_tmpdir(tag);
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        // 非完整页的假加密源：Path3 会 key 校验失败（预期）
        std::fs::write(&db_path, b"fake encrypted db").unwrap();

        let cached_hash = format!("{:x}", md5::compute(rel_key.as_bytes()));
        let decrypted_path = cache_dir.join(format!("{}.db", cached_hash));
        write_minimal_sqlite(&decrypted_path, "seed-v1");

        let db_mt = mtime_nanos(&db_path);
        let mtime_file = cache_dir.join("_mtimes.json");
        let payload = serde_json::to_string(&serde_json::json!({
            &rel_key: {
                "db_mt": db_mt,
                "wal_mt": 0u64,
                "path": decrypted_path.display().to_string(),
            }
        }))
        .unwrap();
        std::fs::write(&mtime_file, payload).unwrap();

        let mut all_keys = HashMap::new();
        all_keys.insert(rel_key.clone(), FAKE_KEY_HEX.to_string());
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file.clone(), all_keys)
            .await
            .unwrap();

        (cache, db_path, decrypted_path, mtime_file, rel_key)
    }

    #[tokio::test]
    async fn lock_for_rel_key_returns_same_arc_for_same_key() {
        let (cache, _db_path, _dec, _mt, rel_key) = setup_seeded_cache("lockshare").await;
        let a = cache.lock_for_rel_key(&rel_key).await;
        let b = cache.lock_for_rel_key(&rel_key).await;
        assert!(
            Arc::ptr_eq(&a, &b),
            "same rel_key must share one mutex for singleflight"
        );
        let other = cache.lock_for_rel_key("message/other.db").await;
        assert!(
            !Arc::ptr_eq(&a, &other),
            "different rel_key must not share mutex"
        );
    }

    #[tokio::test]
    async fn exact_mtime_hit_skips_decrypt() {
        let (cache, _db_path, decrypted_path, _mtime_file, rel_key) =
            setup_seeded_cache("exact").await;

        let p = cache
            .get(&rel_key)
            .await
            .unwrap()
            .expect("cache should hit");
        assert_eq!(p, decrypted_path);
        assert_eq!(sqlite_marker(&decrypted_path), "seed-v1");
    }

    #[tokio::test]
    async fn wal_only_change_uses_incremental_path() {
        let root = unique_tmpdir("walonly");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        std::fs::write(&db_path, b"fake encrypted db").unwrap();

        let wal_path = wal_path_for(&db_path);
        std::fs::write(&wal_path, [0u8; 31]).unwrap(); // ≤ WAL_HDR_SZ=32 → apply_wal noop

        let cached_hash = format!("{:x}", md5::compute(rel_key.as_bytes()));
        let decrypted_path = cache_dir.join(format!("{}.db", cached_hash));
        write_minimal_sqlite(&decrypted_path, "wal-seed");

        let db_mt = mtime_nanos(&db_path);
        let wal_mt0 = mtime_nanos(&wal_path);
        let mtime_file = cache_dir.join("_mtimes.json");
        let payload = serde_json::to_string(&serde_json::json!({
            &rel_key: {
                "db_mt": db_mt,
                "wal_mt": wal_mt0,
                "path": decrypted_path.display().to_string(),
            }
        }))
        .unwrap();
        std::fs::write(&mtime_file, payload).unwrap();

        let mut all_keys = HashMap::new();
        all_keys.insert(rel_key.clone(), FAKE_KEY_HEX.to_string());
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();

        let p1 = cache.get(&rel_key).await.unwrap().expect("first get hits");
        assert_eq!(p1, decrypted_path);
        assert_eq!(sqlite_marker(&decrypted_path), "wal-seed");

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&wal_path, [0xffu8; 31]).unwrap();
        let wal_mt1 = mtime_nanos(&wal_path);
        assert_ne!(wal_mt0, wal_mt1, "rewriting WAL should bump mtime");

        // WAL noop + temp/rename + probe：标记行应仍可读
        let r = cache.get_with_mode(&rel_key).await.unwrap().expect("wal path");
        assert_eq!(r.path, decrypted_path);
        assert_eq!(r.mode, CacheMode::WalIncremental);
        assert_eq!(sqlite_marker(&decrypted_path), "wal-seed");
    }

    #[tokio::test]
    async fn invalid_key_full_decrypt_does_not_stick_bad_cache() {
        let (cache, db_path, decrypted_path, _mtime_file, rel_key) =
            setup_seeded_cache("badkey").await;

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&db_path, b"different fake encrypted bytes").unwrap();

        // Path3：HMAC/页头校验失败 → 不安装坏缓存
        let err = cache.get(&rel_key).await;
        assert!(err.is_err(), "expected key validation error, got {err:?}");
        // 旧 seed 文件仍在（rename 未发生）
        assert_eq!(sqlite_marker(&decrypted_path), "seed-v1");
    }

    #[tokio::test]
    async fn replace_keys_clears_decrypt_cache_entries() {
        let (cache, _db_path, decrypted_path, _mtime_file, rel_key) =
            setup_seeded_cache("reload").await;
        assert!(cache.inner.lock().await.contains_key(&rel_key));
        assert!(decrypted_path.exists());

        let epoch0 = cache.current_key_epoch();
        let mut new_keys = HashMap::new();
        new_keys.insert(rel_key.clone(), FAKE_KEY_HEX.to_string());
        cache.replace_keys(new_keys).await;

        assert!(
            cache.inner.lock().await.is_empty(),
            "inner cache map must be cleared"
        );
        assert!(
            !decrypted_path.exists(),
            "stale decrypt file must be deleted"
        );
        assert!(
            cache.current_key_epoch() > epoch0,
            "replace_keys must advance key_epoch so in-flight installs are discarded"
        );
        assert!(!cache.epoch_still_current(epoch0));
    }

    /// 真实驱动 C3：tmp 已写好，中途 replace_keys 后 commit 不得安装。
    #[tokio::test]
    async fn commit_after_replace_keys_does_not_install_stale_product() {
        let (cache, _db_path, decrypted_path, _mtime_file, rel_key) =
            setup_seeded_cache("epoch-race").await;

        let (epoch_start, used_key) = cache.snapshot_key_for_decrypt(&rel_key).unwrap();
        let final_path = decrypted_path.clone();
        let tmp = DbCache::cache_tmp_path(&final_path);
        write_minimal_sqlite(&tmp, "stale-product");

        let mut new_keys = HashMap::new();
        new_keys.insert(rel_key.clone(), FAKE_KEY_HEX.to_string());
        cache.replace_keys(new_keys).await;
        assert!(!cache.epoch_still_current(epoch_start));

        if !tmp.exists() {
            write_minimal_sqlite(&tmp, "stale-product-recreated");
        }

        let committed = {
            let mut inner = cache.inner.lock().await;
            cache
                .commit_cache_product(
                    epoch_start,
                    &used_key,
                    &rel_key,
                    &tmp,
                    &final_path,
                    1,
                    2,
                    CacheMode::FullDecrypt,
                    &mut inner,
                )
                .unwrap()
        };

        assert!(committed.is_none(), "stale epoch must not commit CacheResolve");
        assert!(!cache.inner.lock().await.contains_key(&rel_key));
        assert!(!final_path.exists(), "stale product must not remain as final");
        assert!(!tmp.exists(), "stale tmp must be cleaned on reject");
    }

    /// Skeptic C3 residual：若 epoch 已是 NEW 但仍用 OLD key 解密，commit 必须拒绝。
    /// （旧 bug：先 bump epoch 再换 keys → snapshot 到 NEW+OLD 仍可通过 epoch-only 检查）
    #[tokio::test]
    async fn commit_rejects_new_epoch_with_old_key_hex() {
        let (cache, _db_path, decrypted_path, _mtime_file, rel_key) =
            setup_seeded_cache("new-epoch-old-key").await;

        let old_key = FAKE_KEY_HEX.to_string();
        // 模拟错误顺序窗口：keys 已换成 OTHER，epoch 已 NEW，但 in-flight used_key 仍是 OLD
        const OTHER_KEY: &str =
            "1111111111111111111111111111111111111111111111111111111111111111";
        {
            let mut g = cache.all_keys.write().unwrap();
            g.insert(rel_key.clone(), OTHER_KEY.to_string());
        }
        cache.key_epoch.fetch_add(1, Ordering::Release);
        let epoch_new = cache.current_key_epoch();

        // 去掉 seed entry，只验证本次 commit 行为
        cache.inner.lock().await.clear();
        let final_path = decrypted_path.clone();
        let _ = std::fs::remove_file(&final_path);
        let tmp = DbCache::cache_tmp_path(&final_path);
        let _ = std::fs::remove_file(&tmp);
        write_minimal_sqlite(&tmp, "wrong-key-product");

        let committed = {
            let mut inner = cache.inner.lock().await;
            cache
                .commit_cache_product(
                    epoch_new,
                    &old_key,
                    &rel_key,
                    &tmp,
                    &final_path,
                    9,
                    9,
                    CacheMode::FullDecrypt,
                    &mut inner,
                )
                .unwrap()
        };

        assert!(
            committed.is_none(),
            "NEW epoch + OLD used_key must not install (key revalidation)"
        );
        assert!(
            !cache.inner.lock().await.contains_key(&rel_key),
            "must not insert CacheEntry for wrong used_key"
        );
        assert!(
            !final_path.exists(),
            "wrong-key product must not be installed as final"
        );
        assert!(!tmp.exists(), "tmp cleaned on key mismatch reject");
    }

    #[test]
    fn snapshot_key_is_consistent_after_keys_then_epoch_order() {
        // pure ordering contract: after keys write + epoch bump, snapshot matches
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (cache, _, _, _, rel_key) = setup_seeded_cache("snap-order").await;
            let mut new_keys = HashMap::new();
            const K2: &str =
                "2222222222222222222222222222222222222222222222222222222222222222";
            new_keys.insert(rel_key.clone(), K2.to_string());
            cache.replace_keys(new_keys).await;
            let (e, k) = cache.snapshot_key_for_decrypt(&rel_key).unwrap();
            assert_eq!(k, K2);
            assert_eq!(e, cache.current_key_epoch());
            // 再 snapshot 稳定
            let (e2, k2) = cache.snapshot_key_for_decrypt(&rel_key).unwrap();
            assert_eq!((e, k), (e2, k2));
        });
    }

    /// replace_keys 必须删掉「确定性 cache 路径」上的文件，即使它不在 inner 里
    /// （in-flight Path3 rename 后、insert 前的窗口）。
    #[tokio::test]
    async fn replace_keys_deletes_orphan_cache_file_not_in_inner() {
        let (cache, _db_path, _dec, _mt, rel_key) = setup_seeded_cache("orphan").await;
        // 清空 inner 但留下 orphan 文件，模拟「只 rename 未 insert」
        let orphan = {
            let seed = cache
                .inner
                .lock()
                .await
                .get(&rel_key)
                .unwrap()
                .decrypted_path
                .clone();
            cache.inner.lock().await.clear();
            seed
        };
        let _ = std::fs::remove_file(&orphan);
        write_minimal_sqlite(&orphan, "orphan");
        assert!(orphan.exists());

        let mut new_keys = HashMap::new();
        new_keys.insert(rel_key.clone(), FAKE_KEY_HEX.to_string());
        cache.replace_keys(new_keys).await;

        assert!(
            !orphan.exists(),
            "replace_keys must delete deterministic cache paths even if not in inner"
        );
    }

    #[tokio::test]
    async fn get_with_mode_reports_hit_and_wal() {
        let root = unique_tmpdir("getwithmode");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        std::fs::write(&db_path, b"fake encrypted db").unwrap();
        let wal_path = wal_path_for(&db_path);
        std::fs::write(&wal_path, [0u8; 31]).unwrap();

        let cached_hash = format!("{:x}", md5::compute(rel_key.as_bytes()));
        let decrypted_path = cache_dir.join(format!("{}.db", cached_hash));
        write_minimal_sqlite(&decrypted_path, "mode-seed");

        let db_mt = mtime_nanos(&db_path);
        let wal_mt0 = mtime_nanos(&wal_path);
        let mtime_file = cache_dir.join("_mtimes.json");
        let payload = serde_json::to_string(&serde_json::json!({
            &rel_key: {
                "db_mt": db_mt,
                "wal_mt": wal_mt0,
                "path": decrypted_path.display().to_string(),
            }
        }))
        .unwrap();
        std::fs::write(&mtime_file, payload).unwrap();

        let mut all_keys = HashMap::new();
        all_keys.insert(rel_key.clone(), FAKE_KEY_HEX.to_string());
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();

        let hit = cache
            .get_with_mode(&rel_key)
            .await
            .unwrap()
            .expect("cache should hit");
        assert_eq!(hit.path, decrypted_path);
        assert_eq!(hit.mode, CacheMode::CacheHit);

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&wal_path, [0xffu8; 31]).unwrap();
        let wal = cache
            .get_with_mode(&rel_key)
            .await
            .unwrap()
            .expect("WAL-only change should stay incremental");
        assert_eq!(wal.path, decrypted_path);
        assert_eq!(wal.mode, CacheMode::WalIncremental);

        // 坏 key + 源 mtime 变化 → Path3 拒绝，不返回 FullDecrypt 成功
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&db_path, b"different bytes").unwrap();
        assert!(
            cache.get_with_mode(&rel_key).await.is_err(),
            "invalid key must not install FullDecrypt product"
        );
    }

    #[tokio::test]
    async fn restart_with_wal_change_still_reuses_cached_db_then_applies_wal() {
        let root = unique_tmpdir("restart-wal");
        let db_dir = root.join("db_storage");
        let cache_dir = root.join("cache");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let rel_key = "message_0.db".to_string();
        let db_path = db_dir.join(&rel_key);
        std::fs::write(&db_path, b"fake encrypted db").unwrap();

        let wal_path = wal_path_for(&db_path);
        std::fs::write(&wal_path, [0u8; 31]).unwrap(); // WAL 增量仍是 noop

        let cached_hash = format!("{:x}", md5::compute(rel_key.as_bytes()));
        let decrypted_path = cache_dir.join(format!("{}.db", cached_hash));
        write_minimal_sqlite(&decrypted_path, "restart-seed");

        let db_mt = mtime_nanos(&db_path);
        let wal_mt0 = mtime_nanos(&wal_path);
        let mtime_file = cache_dir.join("_mtimes.json");
        let payload = serde_json::to_string(&serde_json::json!({
            &rel_key: {
                "db_mt": db_mt,
                "wal_mt": wal_mt0,
                "path": decrypted_path.display().to_string(),
            }
        }))
        .unwrap();
        std::fs::write(&mtime_file, payload).unwrap();

        // 模拟 daemon 重启前又有新消息写入 WAL
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&wal_path, [0xffu8; 31]).unwrap();
        let wal_mt1 = mtime_nanos(&wal_path);
        assert_ne!(wal_mt0, wal_mt1);

        let mut all_keys = HashMap::new();
        all_keys.insert(rel_key.clone(), FAKE_KEY_HEX.to_string());
        let cache = DbCache::with_dirs(db_dir, cache_dir, mtime_file, all_keys)
            .await
            .unwrap();

        let r = cache
            .get_with_mode(&rel_key)
            .await
            .unwrap()
            .expect("cache should reuse persisted DB");
        assert_eq!(r.path, decrypted_path);
        assert_eq!(r.mode, CacheMode::WalIncremental);
        assert_eq!(
            sqlite_marker(&decrypted_path),
            "restart-seed",
            "restart + WAL-only change should still reuse cached DB and avoid full_decrypt"
        );
    }
}

#[cfg(test)]
mod storage_security_tests {
    use super::*;

    #[tokio::test]
    async fn forged_cache_index_cannot_delete_files_outside_cache() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("unrelated-file");
        std::fs::write(&victim, b"must remain intact").unwrap();
        let cache_dir = dir.path().join("cache");
        let index = dir.path().join("mtimes.json");
        std::fs::write(&index, serde_json::json!({
            "message/message_0.db": {"path": victim, "db_mt": 0, "wal_mt": 0}
        }).to_string()).unwrap();
        let cache = DbCache::with_dirs(dir.path().join("source"), cache_dir, index, HashMap::new())
            .await.unwrap();
        assert!(cache.inner.lock().await.is_empty());
        assert_eq!(std::fs::read(victim).unwrap(), b"must remain intact");
    }
}
