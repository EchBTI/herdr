use super::*;
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Component, PathBuf},
};

pub(crate) struct Listener(UnixListener);
pub(crate) struct Stream(UnixStream);

fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn fd_file(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: open/openat returned this new, uniquely owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn c_name(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| denied("NUL in shared socket path"))
}

/// Hold every lookup through a directory descriptor. Only the session owner
/// can write the final directory; group members may traverse it, never replace files.
fn socket_directory(path: &Path, group: Option<u32>) -> io::Result<(File, CString)> {
    if !path.is_absolute() {
        return Err(denied("shared socket path must be absolute"));
    }
    let owner = crate::platform::effective_uid()?;
    let filename = c_name(
        path.file_name()
            .ok_or_else(|| denied("socket filename missing"))?
            .as_bytes(),
    )?;
    let parent = path
        .parent()
        .ok_or_else(|| denied("socket parent missing"))?;
    let parts: Vec<_> = parent
        .components()
        .filter(|part| *part != Component::RootDir)
        .collect();
    if parts.is_empty() {
        return Err(denied("shared socket requires a dedicated directory"));
    }
    // SAFETY: literal is NUL-terminated; descriptor ownership is transferred to File.
    let mut directory = fd_file(unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    })?;
    for (index, part) in parts.iter().enumerate() {
        let Component::Normal(part) = part else {
            return Err(denied("invalid shared socket path component"));
        };
        let name = c_name(part.as_bytes())?;
        let last = index + 1 == parts.len();
        let mut created = false;
        if last && group.is_some() {
            // SAFETY: descriptor and name are valid; mkdirat never follows final symlinks.
            if unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o750) } == 0 {
                created = true;
            } else if io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: open anchored to the verified parent, rejecting final symlinks.
        let next = fd_file(unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        if created {
            let gid = group.expect("creation requires a group");
            // SAFETY: descriptor refers to the newly created owned directory.
            if unsafe { libc::fchown(next.as_raw_fd(), owner, gid) } != 0
                || unsafe { libc::fchmod(next.as_raw_fd(), 0o750) } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let metadata = next.metadata()?;
        if last {
            if metadata.uid() != owner
                || metadata.mode() & 0o7777 != 0o750
                || group.is_some_and(|gid| metadata.gid() != gid)
            {
                return Err(denied("shared socket directory must be owned by the session owner, mode 0750, and use the sharing group"));
            }
        } else if metadata.uid() != 0 && metadata.uid() != owner {
            return Err(denied(
                "shared socket ancestors must belong to root or session owner",
            ));
        } else if metadata.mode() & 0o022 != 0
            && !(metadata.uid() == 0 && metadata.mode() & libc::S_ISVTX != 0)
        {
            return Err(denied(
                "shared socket ancestors cannot be writable by other users",
            ));
        }
        directory = next;
    }
    Ok((directory, filename))
}

fn anchored_path(directory: &File, name: &CString) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
        .join(std::ffi::OsStr::from_bytes(name.as_bytes()))
}

pub(crate) fn bind_listener(path: &Path, gid: u32) -> io::Result<Listener> {
    let (directory, name) = socket_directory(path, Some(gid))?;
    let anchored = anchored_path(&directory, &name);
    // UnixListener::bind refuses all existing paths, including stale sockets and symlinks.
    let listener = UnixListener::bind(&anchored)?;
    // SAFETY: directory is owner-writable only and held open throughout setup;
    // newly bound socket belongs to this process, and symlink targets are forbidden.
    if unsafe {
        libc::fchownat(
            directory.as_raw_fd(),
            name.as_ptr(),
            crate::platform::effective_uid()?,
            gid,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
        || unsafe { libc::fchmodat(directory.as_raw_fd(), name.as_ptr(), 0o660, 0) } != 0
    {
        let error = io::Error::last_os_error();
        // SAFETY: remove only the just-created entry in our pinned directory.
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0);
        }
        return Err(error);
    }
    Ok(Listener(listener))
}

pub(crate) fn remove_socket(path: &Path) -> io::Result<()> {
    let (directory, name) = socket_directory(path, None)?;
    let metadata = match std::fs::symlink_metadata(anchored_path(&directory, &name)) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() || metadata.uid() != crate::platform::effective_uid()? {
        return Err(denied(
            "refusing to remove non-socket or unowned shared endpoint",
        ));
    }
    // SAFETY: only session owner may replace entries in this pinned directory.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn peer_identity(stream: &Stream) -> io::Result<crate::platform::PeerIdentity> {
    crate::platform::linux::identity::socket_peer_identity(stream.0.as_raw_fd())
}
impl Listener {
    pub(crate) fn accept(&self) -> io::Result<Stream> {
        self.0.accept().map(|(stream, _)| Stream(stream))
    }
}
impl Stream {
    pub(crate) fn connect(path: &Path) -> io::Result<Self> {
        UnixStream::connect(path).map(Self)
    }
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(timeout)
    }
    pub(crate) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(timeout)
    }
}
impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read(buffer)
    }
}
impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = PathBuf::from(format!(
                "/tmp/herdr-shared-transport-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn gid() -> u32 {
        // SAFETY: getegid has no preconditions.
        unsafe { libc::getegid() }
    }

    #[test]
    fn shared_endpoint_has_group_modes_and_authenticated_peers() {
        let temp = Temp::new();
        let path = temp.0.join("shared/session.sock");
        let listener = bind_listener(&path, gid()).unwrap();
        assert_eq!(
            std::fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o7777,
            0o750
        );
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o660);
        assert_eq!(metadata.gid(), gid());
        let _client = Stream::connect(&path).unwrap();
        let accepted = listener.accept().unwrap();
        assert_eq!(
            peer_identity(&accepted).unwrap().uid,
            crate::platform::effective_uid().unwrap()
        );
        assert!(bind_listener(&path, gid()).is_err());
        remove_socket(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn rejects_symlinks_and_insecure_existing_directories() {
        let temp = Temp::new();
        let shared = temp.0.join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(bind_listener(&shared.join("session.sock"), gid()).is_err());
        let linked = temp.0.join("linked");
        symlink(&shared, &linked).unwrap();
        assert!(bind_listener(&linked.join("session.sock"), gid()).is_err());
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o750)).unwrap();
        let target = temp.0.join("private");
        std::fs::write(&target, "keep me").unwrap();
        symlink(&target, shared.join("session.sock")).unwrap();
        assert!(bind_listener(&shared.join("session.sock"), gid()).is_err());
        assert!(remove_socket(&shared.join("session.sock")).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "keep me");
    }
}
