//! Private local storage. Never repair ownership while running as root.
//!
//! Unix files are 0600 and application directories are 0700. Existing files
//! are checked through an O_NOFOLLOW descriptor before changing permissions.
//! Atomic replacement also avoids modifying the target of a hard link.

#[cfg(unix)]
use anyhow::Context;
use anyhow::{bail, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

pub fn restrict_umask() {
    // Called once, before starting threads or invoking the scanner.
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }
}

pub fn require_unprivileged() -> Result<()> {
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        bail!("查询、daemon 和文件写入请用普通用户运行；仅 init / key extract 需要 sudo");
    }
    Ok(())
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn create_parents(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

/// Only use for application-owned directories, never for an export's parent.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    create_parents(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("拒绝不安全的数据目录: {}", path.display()))?;
        if dir.metadata()?.uid() != unsafe { libc::geteuid() } {
            bail!(
                "数据目录不属于当前用户: {}；请先人工检查旧目录的属主，程序不会以 root 自动迁移",
                path.display()
            );
        }
        dir.set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("拒绝不安全的数据目录: {}", path.display());
        }
    }
    Ok(())
}

fn no_follow(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // NONBLOCK prevents a planted FIFO from blocking before fstat.
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
}

fn secure_file(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("敏感数据路径必须是普通文件");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 {
            bail!("拒绝不属于当前用户或有硬链接的敏感数据文件");
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn read_private(path: &Path) -> Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    no_follow(&mut options);
    let mut file = options.open(path)?;
    secure_file(&file)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
}

pub fn secure_existing(path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.read(true);
    no_follow(&mut options);
    secure_file(&options.open(path)?)
}

pub fn create_new(path: &Path) -> Result<File> {
    create_parents(parent_dir(path))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    no_follow(&mut options);
    let file = options.open(path)?;
    secure_file(&file)?;
    Ok(file)
}

pub fn open_existing_for_update(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    no_follow(&mut options);
    let file = options.open(path)?;
    secure_file(&file)?;
    Ok(file)
}

pub fn append_private(path: &Path) -> Result<File> {
    create_parents(parent_dir(path))?;
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    no_follow(&mut options);
    let file = options.open(path)?;
    secure_file(&file)?;
    Ok(file)
}

pub fn write_private(path: &Path, data: impl AsRef<[u8]>) -> Result<()> {
    write_output(path, data, true)
}

/// The final rename is atomic, including the no-overwrite decision. A crash
/// cannot truncate an existing key file. Neither symlinks nor hard links cause
/// writes/chmod to another file's inode.
pub fn write_output(path: &Path, data: impl AsRef<[u8]>, overwrite: bool) -> Result<()> {
    let parent = parent_dir(path);
    create_parents(parent)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            bail!("拒绝写入符号链接或非普通文件: {}", path.display());
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    secure_file(temp.as_file())?;
    temp.write_all(data.as_ref())?;
    temp.as_file().sync_all()?;
    if overwrite {
        temp.persist(path).map_err(|e| e.error)?;
    } else {
        temp.persist_noclobber(path).map_err(|e| e.error)?;
    }
    Ok(())
}

pub fn copy_private(source: &Path, destination: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.read(true);
    no_follow(&mut options);
    let mut input = options.open(source)?;
    secure_file(&input)?;
    let mut output = create_new(destination)?;
    std::io::copy(&mut input, &mut output)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    #[test]
    fn private_storage_ignores_permissive_creation_defaults() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("state");
        ensure_private_dir(&dir).unwrap();
        let path = dir.join("keys.json");
        write_private(&path, b"secret").unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_private(&path).unwrap(), "secret");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn symlink_file_cannot_redirect_keys_or_permissions() {
        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("outside");
        fs::write(&victim, b"unchanged").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        let link = root.path().join("keys.json");
        symlink(&victim, &link).unwrap();
        assert!(write_private(&link, b"secret").is_err());
        assert!(read_private(&link).is_err());
        assert!(append_private(&link).is_err());
        assert!(create_new(&link).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        assert_eq!(fs::metadata(&victim).unwrap().mode() & 0o777, 0o644);
    }

    #[test]
    fn symlink_directory_is_not_chmodded_or_traversed() {
        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("outside");
        fs::create_dir(&victim).unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o755)).unwrap();
        let link = root.path().join("state");
        symlink(&victim, &link).unwrap();
        assert!(ensure_private_dir(&link).is_err());
        assert_eq!(fs::metadata(&victim).unwrap().mode() & 0o777, 0o755);
    }

    #[test]
    fn atomic_replacement_does_not_modify_a_hardlink_target() {
        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("outside");
        fs::write(&victim, b"unchanged").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        let link = root.path().join("keys.json");
        fs::hard_link(&victim, &link).unwrap();
        assert!(secure_existing(&link).is_err());
        write_private(&link, b"new key").unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        assert_eq!(fs::metadata(&victim).unwrap().mode() & 0o777, 0o644);
        assert_eq!(fs::read(&link).unwrap(), b"new key");
    }

    #[test]
    fn no_overwrite_preserves_existing_output() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("export");
        write_output(&path, b"first", false).unwrap();
        assert!(write_output(&path, b"second", false).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"first");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn concurrent_no_overwrite_has_exactly_one_winner() {
        use std::sync::{Arc, Barrier};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("export");
        let barrier = Arc::new(Barrier::new(2));
        let workers: Vec<_> = [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .map(|content| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    write_output(&path, content, false).is_ok()
                })
            })
            .collect();
        let winners = workers
            .into_iter()
            .map(|w| usize::from(w.join().unwrap()))
            .sum::<usize>();
        assert_eq!(winners, 1);
        let result = fs::read(&path).unwrap();
        assert!(result == b"first" || result == b"second");
    }
}
