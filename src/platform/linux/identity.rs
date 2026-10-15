//! Kernel credentials and NSS account resolution for shared local sessions.
//! Call account resolution on administration/connection paths, never frame paths.

use super::super::{OsAccount, OsGroup, PeerIdentity};
use std::{
    ffi::{CStr, CString, OsString},
    io,
    os::{
        fd::{AsFd, AsRawFd, RawFd},
        unix::ffi::OsStringExt,
    },
    path::PathBuf,
    sync::Mutex,
};

const MAX_NSS_BUFFER: usize = 1024 * 1024;
const MAX_ENUMERATED_ACCOUNTS: usize = 65_536;
static ACCOUNT_ENUMERATION: Mutex<()> = Mutex::new(());

pub(crate) fn effective_uid() -> io::Result<u32> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    Ok(unsafe { libc::geteuid() })
}

pub(crate) fn current_process_identity() -> io::Result<String> {
    process_identity(std::process::id())
}

/// Runtime binding includes boot ID so a PID/start-tick tuple cannot revive a
/// previous daemon's space IDs after a host restart.
pub(crate) fn process_identity(pid: u32) -> io::Result<String> {
    if pid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid process ID",
        ));
    }
    let start = super::process_start_token(pid)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "process identity unavailable"))?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let boot = boot.trim();
    if boot.len() != 36
        || !boot.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Linux boot identity",
        ));
    }
    Ok(format!("{}:{pid}:{start}", boot.to_ascii_lowercase()))
}

/// Stable host binding for policy files; never fall back to a mutable hostname.
pub(crate) fn host_identity() -> io::Result<String> {
    use std::io::Read as _;
    let mut value = String::new();
    std::fs::File::open("/etc/machine-id")?
        .take(129)
        .read_to_string(&mut value)?;
    let identity = value.trim();
    if identity.len() != 32
        || !identity.bytes().all(|byte| byte.is_ascii_hexdigit())
        || identity.bytes().all(|byte| byte == b'0')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing or invalid /etc/machine-id",
        ));
    }
    Ok(identity.to_ascii_lowercase())
}

pub(crate) fn local_stream_peer_identity(
    stream: &crate::ipc::LocalStream,
) -> io::Result<PeerIdentity> {
    let crate::ipc::LocalStream::UdSocket(socket) = stream;
    socket_peer_identity(socket.as_fd().as_raw_fd())
}

pub(crate) fn socket_peer_identity(fd: RawFd) -> io::Result<PeerIdentity> {
    // SAFETY: zero is a valid initial value; getsockopt fills exactly this buffer.
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let expected = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let mut length = expected;
    // SAFETY: credentials and length point to writable, correctly sized storage.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length != expected
        || credentials.pid <= 0
        || credentials.uid == u32::MAX
        || credentials.gid == u32::MAX
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unavailable socket peer credentials",
        ));
    }
    Ok(PeerIdentity {
        uid: credentials.uid,
        gid: credentials.gid,
        pid: Some(credentials.pid as u32),
    })
}

fn account_name(name: &str) -> io::Result<CString> {
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "account name is empty",
        ));
    }
    CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "account name contains NUL"))
}

fn grow_buffer(buffer: &mut Vec<u8>) -> io::Result<()> {
    if buffer.len() >= MAX_NSS_BUFFER {
        return Err(io::Error::other("NSS account record exceeds size limit"));
    }
    buffer.resize((buffer.len() * 2).min(MAX_NSS_BUFFER), 0);
    Ok(())
}

// SAFETY: callers pass strings from a successful NSS result while its backing
// buffer remains alive. Null optional fields are represented by empty strings.
unsafe fn field_bytes<'a>(value: *const libc::c_char) -> &'a [u8] {
    if value.is_null() {
        &[]
    } else {
        unsafe { CStr::from_ptr(value) }.to_bytes()
    }
}

fn copy_account(record: &libc::passwd) -> io::Result<OsAccount> {
    // Identity names must be exact; lossy conversion could alias distinct names.
    let name = unsafe { CStr::from_ptr(record.pw_name) }
        .to_str()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "account name is not UTF-8"))?
        .to_owned();
    // SAFETY: successful NSS lookups own valid fields until buffer is dropped.
    unsafe {
        Ok(OsAccount {
            uid: record.pw_uid,
            gid: record.pw_gid,
            name,
            description: String::from_utf8_lossy(field_bytes(record.pw_gecos)).into_owned(),
            home: PathBuf::from(OsString::from_vec(field_bytes(record.pw_dir).to_vec())),
            shell: PathBuf::from(OsString::from_vec(field_bytes(record.pw_shell).to_vec())),
        })
    }
}

fn lookup_account(
    mut lookup: impl FnMut(*mut libc::passwd, *mut libc::c_char, usize, *mut *mut libc::passwd) -> i32,
) -> io::Result<Option<OsAccount>> {
    let mut buffer = vec![0_u8; 4096];
    loop {
        // SAFETY: passwd is output-only until lookup succeeds.
        let mut record: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let code = lookup(
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        );
        if code == libc::ERANGE {
            grow_buffer(&mut buffer)?;
            continue;
        }
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code));
        }
        if result.is_null() {
            return Ok(None);
        }
        if record.pw_name.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NSS returned no account name",
            ));
        }
        return copy_account(&record).map(Some);
    }
}

pub(crate) fn os_account_by_uid(uid: u32) -> io::Result<Option<OsAccount>> {
    lookup_account(|record, buffer, size, result| {
        // SAFETY: lookup_account supplies valid output pointers and buffer bounds.
        unsafe { libc::getpwuid_r(uid, record, buffer, size, result) }
    })
}

pub(crate) fn os_account_by_name(name: &str) -> io::Result<Option<OsAccount>> {
    let name = account_name(name)?;
    lookup_account(|record, buffer, size, result| {
        // SAFETY: name is NUL-terminated and output storage is valid.
        unsafe { libc::getpwnam_r(name.as_ptr(), record, buffer, size, result) }
    })
}

pub(crate) fn os_accounts() -> io::Result<Vec<OsAccount>> {
    let _lock = ACCOUNT_ENUMERATION
        .lock()
        .map_err(|_| io::Error::other("account enumeration lock poisoned"))?;
    struct Enumeration;
    impl Drop for Enumeration {
        fn drop(&mut self) {
            // SAFETY: closes the NSS enumeration opened below, including error paths.
            unsafe {
                libc::endpwent();
            }
        }
    }
    // SAFETY: serialize this module's process-global enumeration cursor.
    unsafe {
        libc::setpwent();
    }
    let _enumeration = Enumeration;
    let mut accounts = Vec::new();
    loop {
        let next = lookup_account(|record, buffer, size, result| {
            // SAFETY: lookup_account provides valid output storage.
            let code = unsafe { libc::getpwent_r(record, buffer, size, result) };
            // Linux uses ENOENT at end of enumeration, not necessarily success/null.
            if code == libc::ENOENT {
                0
            } else {
                code
            }
        })?;
        let Some(account) = next else {
            break;
        };
        if accounts.len() == MAX_ENUMERATED_ACCOUNTS {
            return Err(io::Error::other(
                "NSS enumeration exceeds account limit; use explicit lookup",
            ));
        }
        accounts.push(account);
    }
    accounts.sort_by(|a, b| a.name.cmp(&b.name).then(a.uid.cmp(&b.uid)));
    accounts.dedup_by(|a, b| a.uid == b.uid && a.name == b.name);
    Ok(accounts)
}

pub(crate) fn os_group_by_name(name: &str) -> io::Result<Option<OsGroup>> {
    let name = account_name(name)?;
    let mut buffer = vec![0_u8; 4096];
    loop {
        // SAFETY: zeroed output record is read only following successful lookup.
        let mut record: libc::group = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        // SAFETY: name and writable record/buffer pointers are valid for this call.
        let code = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                &mut record,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if code == libc::ERANGE {
            grow_buffer(&mut buffer)?;
            continue;
        }
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code));
        }
        if result.is_null() {
            return Ok(None);
        }
        if record.gr_name.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NSS returned no group name",
            ));
        }
        // SAFETY: gr_name belongs to the still-live buffer.
        let name = unsafe { CStr::from_ptr(record.gr_name) }
            .to_str()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "group name is not UTF-8"))?
            .to_owned();
        return Ok(Some(OsGroup {
            gid: record.gr_gid,
            name,
        }));
    }
}

pub(crate) fn os_account_in_group(account: &OsAccount, gid: u32) -> io::Result<bool> {
    if account.gid == gid {
        return Ok(true);
    }
    let name = account_name(&account.name)?;
    let mut groups = vec![0 as libc::gid_t; 32];
    loop {
        let mut count = groups.len() as libc::c_int;
        // SAFETY: groups has capacity for the supplied count; name is a C string.
        let result = unsafe {
            libc::getgrouplist(name.as_ptr(), account.gid, groups.as_mut_ptr(), &mut count)
        };
        if result >= 0 {
            if count < 0 || count as usize > groups.len() {
                return Err(io::Error::other("invalid NSS group count"));
            }
            return Ok(groups[..count as usize].contains(&gid));
        }
        if count <= groups.len() as i32 || count as usize > MAX_ENUMERATED_ACCOUNTS {
            return Err(io::Error::other("cannot resolve account group membership"));
        }
        groups.resize(count as usize, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_credentials_are_kernel_supplied() {
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let identity = socket_peer_identity(stream.as_raw_fd()).unwrap();
        assert_eq!(identity.uid, effective_uid().unwrap());
        // SAFETY: getegid has no preconditions.
        assert_eq!(identity.gid, unsafe { libc::getegid() });
        assert_eq!(identity.pid, Some(std::process::id()));
        assert!(socket_peer_identity(-1).is_err());
    }

    #[test]
    fn process_identity_binds_boot_pid_and_start_time() {
        let identity = current_process_identity().unwrap();
        assert_eq!(identity, process_identity(std::process::id()).unwrap());
        let parts: Vec<_> = identity.split(':').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 36);
        assert_eq!(parts[1], std::process::id().to_string());
        assert!(parts[2].parse::<u64>().is_ok());
        assert!(process_identity(0).is_err());
        assert!(process_identity(u32::MAX).is_err());
    }

    #[test]
    fn credential_child_process() {
        let Some(path) = std::env::var_os("HERDR_TEST_CREDENTIAL_SOCKET") else {
            return;
        };
        let _stream = std::os::unix::net::UnixStream::connect(path).unwrap();
    }

    /// Runs in the disposable Linux qualification container as root. Ordinary
    /// developer test runs skip it; it never creates or changes host accounts.
    #[test]
    fn kernel_attributes_a_different_os_uid_to_the_connecting_process() {
        use std::os::unix::{fs::PermissionsExt, process::CommandExt};
        use std::time::{Duration, Instant};
        if effective_uid().unwrap() != 0 {
            return;
        }
        let directory = PathBuf::from(format!("/tmp/herdr-peer-uid-test-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = directory.join("peer.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("platform::linux::identity::tests::credential_child_process")
            .env("HERDR_TEST_CREDENTIAL_SOCKET", &path)
            .uid(65534)
            .gid(65534)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("cross-UID child did not connect: {error}");
                }
            }
        };
        let identity = socket_peer_identity(stream.as_raw_fd()).unwrap();
        assert_eq!(identity.uid, 65534);
        assert_eq!(identity.gid, 65534);
        assert_eq!(identity.pid, Some(child.id()));
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn current_account_resolves_by_uid_and_exact_name() {
        let account = os_account_by_uid(effective_uid().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            os_account_by_name(&account.name).unwrap(),
            Some(account.clone())
        );
        assert!(os_account_in_group(&account, account.gid).unwrap());
        assert!(os_account_by_name("bad\0name").is_err());
        assert!(os_account_by_name("").is_err());
        assert!(os_group_by_name("bad\0group").is_err());
        assert!(os_group_by_name("herdr-nonexistent-test-group-948273")
            .unwrap()
            .is_none());
    }

    #[test]
    fn nss_buffers_are_bounded() {
        let mut buffer = vec![0; MAX_NSS_BUFFER / 2];
        grow_buffer(&mut buffer).unwrap();
        assert_eq!(buffer.len(), MAX_NSS_BUFFER);
        assert!(grow_buffer(&mut buffer).is_err());
    }

    #[test]
    fn nss_lookup_retries_short_buffers_and_copies_identity_exactly() {
        let name = CString::new("directory-user").unwrap();
        let mut calls = 0;
        let account = lookup_account(|record, _buffer, size, result| {
            calls += 1;
            if size == 4096 {
                return libc::ERANGE;
            }
            // SAFETY: lookup_account supplied these writable pointers; name stays
            // alive throughout the lookup and the resulting string is copied.
            unsafe {
                (*record).pw_name = name.as_ptr().cast_mut();
                (*record).pw_uid = 12345;
                (*record).pw_gid = 45678;
                *result = record;
            }
            0
        })
        .unwrap()
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(account.name, "directory-user");
        assert_eq!(account.uid, 12345);
        assert_eq!(account.gid, 45678);
    }

    #[test]
    fn nss_lookup_distinguishes_absent_accounts_from_provider_failure() {
        assert!(lookup_account(|_, _, _, _| 0).unwrap().is_none());
        assert_eq!(
            lookup_account(|_, _, _, _| libc::EIO)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EIO)
        );
        assert!(lookup_account(|record, _, _, result| {
            // SAFETY: valid output pointers from lookup_account. A malformed
            // successful provider result must still fail closed.
            unsafe {
                *result = record;
            }
            0
        })
        .is_err());
    }
}
