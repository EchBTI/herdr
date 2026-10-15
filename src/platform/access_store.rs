//! Descriptor-relative, owner-only policy persistence. Never follows symlinks.
use std::io;
use std::path::Path;

#[cfg(unix)]
mod native {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;
    use std::sync::atomic::{AtomicU64, Ordering};

    const MAX_BYTES: u64 = 4 * 1024 * 1024;
    const NAME: &CStr = c"access-policy.json";
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, message)
    }
    fn fd_file(fd: libc::c_int) -> io::Result<File> {
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }
    fn name(bytes: &[u8]) -> io::Result<CString> {
        CString::new(bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in policy path"))
    }
    fn directory(path: &Path, owner: u32, create: bool) -> io::Result<File> {
        if !path.is_absolute() {
            return Err(invalid("policy directory must be absolute"));
        }
        if unsafe { libc::geteuid() } != owner {
            return Err(invalid(
                "policy store requires the session owner's OS identity",
            ));
        }
        let mut current = fd_file(unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        })?;
        let parts: Vec<_> = path
            .components()
            .filter(|part| *part != Component::RootDir)
            .collect();
        if parts.is_empty() {
            return Err(invalid("root cannot be a policy directory"));
        }
        for (index, component) in parts.iter().enumerate() {
            let Component::Normal(part) = component else {
                return Err(invalid("invalid policy path component"));
            };
            let component = name(part.as_bytes())?;
            let last = index + 1 == parts.len();
            if last && create {
                let result =
                    unsafe { libc::mkdirat(current.as_raw_fd(), component.as_ptr(), 0o700) };
                if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                    return Err(io::Error::last_os_error());
                }
                if result == 0 {
                    current.sync_all()?;
                }
            }
            current = fd_file(unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            })?;
        }
        let metadata = current.metadata()?;
        if metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
            return Err(invalid(
                "policy directory must belong to owner with mode 0700",
            ));
        }
        Ok(current)
    }
    fn existing(dir: &File, owner: u32) -> io::Result<Option<File>> {
        let file = match fd_file(unsafe {
            libc::openat(
                dir.as_raw_fd(),
                NAME.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        }) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != owner
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() > MAX_BYTES
        {
            return Err(invalid("policy must be a private owner-owned regular file, without hard links, at most 4 MiB"));
        }
        Ok(Some(file))
    }
    pub(super) fn read(path: &Path, owner: u32) -> io::Result<Option<Vec<u8>>> {
        let dir = match directory(path, owner, false) {
            Ok(dir) => dir,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let Some(file) = existing(&dir, owner)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(invalid("policy exceeds maximum size"));
        }
        Ok(Some(bytes))
    }
    pub(super) fn prepare_directory(path: &Path, owner: u32) -> io::Result<()> {
        directory(path, owner, true).map(|_| ())
    }

    pub(super) fn lock(path: &Path, owner: u32, exclusive: bool) -> io::Result<File> {
        const LOCK_NAME: &CStr = c"access-policy.lock";
        let dir = directory(path, owner, true)?;
        let flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        // SAFETY: fixed name, pinned owner-only directory, exclusive creation.
        let descriptor = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                LOCK_NAME.as_ptr(),
                flags | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
        };
        let (file, created) = if descriptor >= 0 {
            (fd_file(descriptor)?, true)
        } else {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
            // SAFETY: same fixed filename; reject symlinks and do not block on FIFOs.
            (
                fd_file(unsafe { libc::openat(dir.as_raw_fd(), LOCK_NAME.as_ptr(), flags) })?,
                false,
            )
        };
        if created && unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != owner
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(invalid(
                "policy lock must be a private owner-owned regular file without hard links",
            ));
        }
        // SAFETY: locking the validated descriptor serializes policy saves and
        // execution barriers across processes. Dropping File releases the lock.
        if unsafe {
            libc::flock(
                file.as_raw_fd(),
                if exclusive {
                    libc::LOCK_EX
                } else {
                    libc::LOCK_SH
                },
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(file)
    }

    pub(super) fn append_audit(path: &Path, owner: u32, record: &[u8]) -> io::Result<()> {
        const AUDIT_NAME: &CStr = c"access-audit.jsonl";
        const MAX_AUDIT_BYTES: u64 = 1024 * 1024;
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        if record.is_empty() || record.len() > 2047 || record.contains(&b'\n') {
            return Err(invalid("audit record must be one line at most 2 KiB"));
        }
        let dir = directory(path, owner, true)?;
        let flags =
            libc::O_WRONLY | libc::O_APPEND | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        // SAFETY: name is fixed, directory pinned, descriptor is newly owned.
        let created_fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                AUDIT_NAME.as_ptr(),
                flags | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
        };
        let (mut file, created) = if created_fd >= 0 {
            (fd_file(created_fd)?, true)
        } else {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
            // SAFETY: fixed path, O_NOFOLLOW rejects symlinks, NONBLOCK rejects FIFO hangs.
            (
                fd_file(unsafe { libc::openat(dir.as_raw_fd(), AUDIT_NAME.as_ptr(), flags) })?,
                false,
            )
        };
        if created && unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: advisory exclusive lock serializes this log's writer processes.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != owner
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(invalid(
                "audit log must be a private owner-owned regular file without hard links",
            ));
        }
        if metadata.len().saturating_add(record.len() as u64 + 1) > MAX_AUDIT_BYTES {
            // Truncate only the already verified open file, never by path.
            file.set_len(0)?;
        }
        let mut line = Vec::with_capacity(record.len() + 1);
        line.extend_from_slice(record);
        line.push(b'\n');
        file.write_all(&line)?;
        file.sync_data()?;
        if created {
            dir.sync_all()?;
        }
        Ok(())
    }

    pub(super) fn write(path: &Path, owner: u32, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() as u64 > MAX_BYTES {
            return Err(invalid("policy exceeds maximum size"));
        }
        let dir = directory(path, owner, true)?;
        existing(&dir, owner)?;
        let temporary = name(
            format!(
                ".access-policy-{}-{}",
                std::process::id(),
                TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
            )
            .as_bytes(),
        )?;
        let mut file = fd_file(unsafe {
            libc::openat(
                dir.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        })?;
        let result = (|| {
            // A restrictive umask can remove requested bits. Set exact private mode.
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } < 0 {
                return Err(io::Error::last_os_error());
            }
            file.write_all(bytes)?;
            file.sync_all()?;
            if unsafe {
                libc::renameat(
                    dir.as_raw_fd(),
                    temporary.as_ptr(),
                    dir.as_raw_fd(),
                    NAME.as_ptr(),
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            dir.sync_all()
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(dir.as_raw_fd(), temporary.as_ptr(), 0);
            }
        }
        result
    }
}

pub(crate) fn read(path: &Path, owner: u32) -> io::Result<Option<Vec<u8>>> {
    #[cfg(unix)]
    {
        native::read(path, owner)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, owner);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "shared policy requires Unix",
        ))
    }
}
pub(crate) fn write(path: &Path, owner: u32, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        native::write(path, owner, bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, owner, bytes);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "shared policy requires Unix",
        ))
    }
}

pub(crate) fn prepare_directory(path: &Path, owner: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        native::prepare_directory(path, owner)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, owner);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "shared policy requires Unix",
        ))
    }
}

pub(crate) fn lock(path: &Path, owner: u32, exclusive: bool) -> io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        native::lock(path, owner, exclusive)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, owner, exclusive);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "shared policy locks require Unix",
        ))
    }
}

pub(crate) fn append_audit(path: &Path, owner: u32, record: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        native::append_audit(path, owner, record)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, owner, record);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "shared audit requires Unix",
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "herdr-policy-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            Self(root)
        }
        fn owner(&self) -> u32 {
            unsafe { libc::geteuid() }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn atomic_private_round_trip_and_modes() {
        let f = Fixture::new();
        assert!(read(&f.0, f.owner()).unwrap().is_none());
        write(&f.0, f.owner(), b"first").unwrap();
        write(&f.0, f.owner(), b"second").unwrap();
        assert_eq!(read(&f.0, f.owner()).unwrap().unwrap(), b"second");
        assert_eq!(std::fs::metadata(&f.0).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            std::fs::metadata(f.0.join("access-policy.json"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
    }
    #[test]
    fn audit_is_private_bounded_and_rejects_path_substitution() {
        let f = Fixture::new();
        append_audit(&f.0, f.owner(), b"{\"outcome\":\"denied\"}").unwrap();
        let path = f.0.join("access-audit.jsonl");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        assert!(std::fs::read(&path).unwrap().ends_with(b"\n"));
        assert!(append_audit(&f.0, f.owner(), &vec![b'a'; 2048]).is_err());
        assert!(append_audit(&f.0, f.owner(), b"line\nspoof").is_err());
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(1024 * 1024)
            .unwrap();
        append_audit(&f.0, f.owner(), b"{}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{}\n");
        std::fs::remove_file(&path).unwrap();
        let target = f.0.join("target");
        std::fs::write(&target, b"keep").unwrap();
        symlink(&target, &path).unwrap();
        assert!(append_audit(&f.0, f.owner(), b"{}").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }
    #[test]
    fn exclusive_policy_lock_excludes_execution_guards() {
        use std::os::fd::AsRawFd;
        let f = Fixture::new();
        let exclusive = lock(&f.0, f.owner(), true).unwrap();
        let candidate = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(f.0.join("access-policy.lock"))
            .unwrap();
        // SAFETY: nonblocking probe on our valid independent descriptor.
        assert_eq!(
            unsafe { libc::flock(candidate.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
            -1
        );
        assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
        drop(exclusive);
        // SAFETY: the exclusive guard was dropped, so shared acquisition succeeds.
        assert_eq!(
            unsafe { libc::flock(candidate.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
            0
        );
        drop(candidate);
        let _shared = lock(&f.0, f.owner(), false).unwrap();
        assert_eq!(
            std::fs::metadata(f.0.join("access-policy.lock"))
                .unwrap()
                .mode()
                & 0o7777,
            0o600
        );
    }
    #[test]
    fn rejects_public_directory_and_symlink_and_hardlink_files() {
        let f = Fixture::new();
        write(&f.0, f.owner(), b"secret").unwrap();
        std::fs::set_permissions(&f.0, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(read(&f.0, f.owner()).is_err());
        std::fs::set_permissions(&f.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = f.0.join("access-policy.json");
        let target = f.0.join("target");
        std::fs::rename(&path, &target).unwrap();
        symlink(&target, &path).unwrap();
        assert!(read(&f.0, f.owner()).is_err());
        assert!(write(&f.0, f.owner(), b"overwrite").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"secret");
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&target, &path).unwrap();
        assert!(read(&f.0, f.owner()).is_err());
    }
    #[test]
    fn durable_store_rejects_stale_revision_corruption_and_foreign_host() {
        use crate::access::{Caller, Grant, PolicyStore, Role};
        let f = Fixture::new();
        let store = PolicyStore::new(&f.0, f.owner(), "host-a".into());
        let owner = Caller::verified(f.owner(), Some("owner".into()));
        let initial = store.load().unwrap();
        let candidate = initial
            .replace_grants(
                &owner,
                0,
                vec![Grant {
                    uid: f.owner().checked_add(1).unwrap(),
                    account_name: "participant".into(),
                    workspace_id: "space".into(),
                    role: Role::View,
                }],
                false,
            )
            .unwrap();
        store.save(&candidate).unwrap();
        assert_eq!(store.load().unwrap().revision(), 1);
        assert!(store.save(&candidate).is_err());
        assert!(PolicyStore::new(&f.0, f.owner(), "host-b".into())
            .load()
            .is_err());
        std::fs::write(f.0.join("access-policy.json"), b"{truncated").unwrap();
        assert!(store.load().is_err());
        assert!(store.save(&candidate).is_err());
    }
    #[test]
    fn rejects_symlink_in_directory_components() {
        let f = Fixture::new();
        std::fs::create_dir(&f.0).unwrap();
        let target = f.0.join("actual");
        std::fs::create_dir(&target).unwrap();
        let linked = f.0.join("linked");
        symlink(&target, &linked).unwrap();
        assert!(write(&linked.join("policy"), f.owner(), b"bad").is_err());
        assert!(!target.join("policy").exists());
    }
}
