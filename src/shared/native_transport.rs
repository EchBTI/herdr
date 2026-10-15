//! Kernel-authenticated identity retained for the lifetime of a native shared client.
use std::io;
use std::path::{Path, PathBuf};

use crate::access::{Caller, PolicyStore};

#[derive(Clone, Debug)]
pub(crate) struct NativePrincipal {
    pub(crate) caller: Caller,
    pub(crate) policy_directory: PathBuf,
    pub(crate) policy_revision: u64,
    pub(crate) policy_host_id: String,
}

impl NativePrincipal {
    /// Called only on the accepted connection, before any welcome is emitted.
    pub(crate) fn authenticate(
        stream: &crate::ipc::LocalStream,
        directory: &Path,
        host_id: &str,
    ) -> io::Result<Self> {
        let peer = crate::platform::local_stream_peer_identity(stream)?;
        let account = crate::platform::os_account_by_uid(peer.uid)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "unknown OS account"))?;
        let owner = crate::platform::effective_uid()?;
        let policy = PolicyStore::new(directory, owner, host_id.to_owned())
            .load()
            .map_err(io::Error::other)?;
        Ok(Self {
            caller: Caller::verified(peer.uid, Some(account.name)),
            policy_directory: directory.to_owned(),
            policy_revision: policy.revision(),
            policy_host_id: host_id.to_owned(),
        })
    }
}
