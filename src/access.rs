//! Default-deny shared-session authorization. The caller is supplied only by a
//! transport that has verified kernel credentials, never by deserializing input.
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Caller {
    uid: u32,
    account_name: Option<String>,
}
impl Caller {
    /// `account_name` must come from a current host account lookup for this UID.
    pub(crate) fn verified(uid: u32, account_name: Option<String>) -> Self {
        Self { uid, account_name }
    }
    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }
    pub(crate) fn account_name(&self) -> Option<&str> {
        self.account_name.as_deref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Role {
    View,
    Control,
}

/// Call sites resolve objects to authoritative workspace IDs before evaluation.
/// Unclassified methods, global effects, and mixed-workspace operations cannot
/// acquire authority merely by supplying a granted workspace ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Read,
    Control,
    OwnerOnly,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Grant {
    pub uid: u32,
    pub account_name: String,
    pub workspace_id: String,
    #[serde(default)]
    pub workspace_incarnation: String,
    pub role: Role,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessPolicy {
    schema_version: u32,
    owner_uid: u32,
    host_id: String,
    revision: u64,
    grants: Vec<Grant>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PolicyError {
    Denied,
    InvalidPolicy,
    WrongHostOrOwner,
    StaleRevision,
    RevisionExhausted,
    ControlAcknowledgementRequired,
}
impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PolicyError {}

impl AccessPolicy {
    pub(crate) fn new(owner_uid: u32, host_id: String) -> Result<Self, PolicyError> {
        let policy = Self {
            schema_version: SCHEMA_VERSION,
            owner_uid,
            host_id,
            revision: 0,
            grants: Vec::new(),
        };
        policy.validate()?;
        Ok(policy)
    }
    pub(crate) fn owner_uid(&self) -> u32 {
        self.owner_uid
    }
    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }
    pub(crate) fn grants(&self) -> &[Grant] {
        &self.grants
    }
    pub(crate) fn is_owner(&self, caller: &Caller) -> bool {
        caller.uid == self.owner_uid
    }

    pub(crate) fn authorize(
        &self,
        caller: &Caller,
        action: Action,
        workspace: Option<(&str, &str)>,
    ) -> bool {
        if self.is_owner(caller) {
            return true;
        }
        if matches!(action, Action::OwnerOnly | Action::Unknown) {
            return false;
        }
        let Some((workspace, incarnation)) = workspace else {
            return false;
        };
        self.grants.iter().any(|grant| {
            grant.uid == caller.uid
                && caller.account_name() == Some(grant.account_name.as_str())
                && grant.workspace_id == workspace
                && crate::workspace::valid_workspace_incarnation(incarnation)
                && grant.workspace_incarnation == incarnation
                && (action == Action::Read || grant.role == Role::Control)
        })
    }

    /// Produces a candidate without mutating live authority. Persist it before
    /// publishing it and invalidating old client queues under the server lock.
    pub(crate) fn replace_grants(
        &self,
        caller: &Caller,
        expected_revision: u64,
        grants: Vec<Grant>,
        acknowledge_owner_execution: bool,
    ) -> Result<Self, PolicyError> {
        self.check_edit(caller, expected_revision)?;
        if !acknowledge_owner_execution
            && grants
                .iter()
                .any(|grant| grant.role == Role::Control && !self.grants.contains(grant))
        {
            return Err(PolicyError::ControlAcknowledgementRequired);
        }
        let mut next = self.clone();
        next.grants = grants;
        next.revision = self.next_revision()?;
        next.validate()?;
        Ok(next)
    }

    /// Delete grants when the authoritative workspace is deleted. Renaming a
    /// workspace never changes its stable ID; recreated names get new IDs.
    #[cfg(test)]
    pub(crate) fn delete_workspace(
        &self,
        caller: &Caller,
        expected_revision: u64,
        workspace_id: &str,
    ) -> Result<Self, PolicyError> {
        self.check_edit(caller, expected_revision)?;
        let mut next = self.clone();
        next.grants
            .retain(|grant| grant.workspace_id != workspace_id);
        next.revision = self.next_revision()?;
        Ok(next)
    }

    /// Drop deleted, replaced and ambiguous workspace grants before publishing
    /// a topology update. The caller persists a candidate and revokes queues.
    pub(crate) fn retain_workspaces(
        &self,
        caller: &Caller,
        expected_revision: u64,
        workspaces: &std::collections::HashMap<String, String>,
    ) -> Result<Option<Self>, PolicyError> {
        self.check_edit(caller, expected_revision)?;
        let mut next = self.clone();
        next.grants.retain(|grant| {
            workspaces
                .get(&grant.workspace_id)
                .is_some_and(|incarnation| {
                    incarnation == &grant.workspace_incarnation
                        && crate::workspace::valid_workspace_incarnation(incarnation)
                })
        });
        if next.grants == self.grants {
            return Ok(None);
        }
        next.revision = self.next_revision()?;
        Ok(Some(next))
    }

    fn check_edit(&self, caller: &Caller, expected_revision: u64) -> Result<(), PolicyError> {
        if !self.is_owner(caller) {
            return Err(PolicyError::Denied);
        }
        if self.revision != expected_revision {
            return Err(PolicyError::StaleRevision);
        }
        Ok(())
    }
    fn next_revision(&self) -> Result<u64, PolicyError> {
        self.revision
            .checked_add(1)
            .ok_or(PolicyError::RevisionExhausted)
    }
    fn validate(&self) -> Result<(), PolicyError> {
        if self.schema_version != SCHEMA_VERSION || self.host_id.trim().is_empty() {
            return Err(PolicyError::InvalidPolicy);
        }
        let mut keys = HashSet::new();
        let mut names = std::collections::HashMap::new();
        for grant in &self.grants {
            if grant.uid == self.owner_uid
                || grant.account_name.trim().is_empty()
                || grant.workspace_id.trim().is_empty()
                || !crate::workspace::valid_workspace_incarnation(&grant.workspace_incarnation)
                || !keys.insert((grant.uid, grant.workspace_id.as_str()))
            {
                return Err(PolicyError::InvalidPolicy);
            }
            if let Some(previous) = names.insert(grant.uid, grant.account_name.as_str()) {
                if previous != grant.account_name {
                    return Err(PolicyError::InvalidPolicy);
                }
            }
        }
        Ok(())
    }
}

/// Stable host + current owner account binding. A copied policy, renamed owner,
/// or reused owner UID cannot silently inherit the previous owner's grants.
pub(crate) fn policy_host_identity() -> std::io::Result<String> {
    let uid = crate::platform::effective_uid()?;
    let account = crate::platform::os_account_by_uid(uid)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "owner account unavailable",
        )
    })?;
    Ok(format!(
        "{}:{}:{}",
        crate::platform::host_identity()?,
        uid,
        account.name
    ))
}

/// The directory belongs to the owner and must be outside the shared endpoint
/// directory. A missing store means no grants; malformed stores are errors.
pub(crate) struct PolicyStore {
    directory: PathBuf,
    owner_uid: u32,
    host_id: String,
}
impl PolicyStore {
    pub(crate) fn new(directory: impl AsRef<Path>, owner_uid: u32, host_id: String) -> Self {
        Self {
            directory: directory.as_ref().to_owned(),
            owner_uid,
            host_id,
        }
    }
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }
    pub(crate) fn load(&self) -> Result<AccessPolicy, Box<dyn std::error::Error + Send + Sync>> {
        let Some(bytes) = crate::platform::access_store::read(&self.directory, self.owner_uid)?
        else {
            return Ok(AccessPolicy::new(self.owner_uid, self.host_id.clone())?);
        };
        let policy: AccessPolicy = serde_json::from_slice(&bytes)?;
        policy.validate()?;
        self.check_binding(&policy)?;
        Ok(policy)
    }
    /// The server serializes edits; expected revisions protect stale admin
    /// screens. Do not call concurrently from independent daemon processes.
    pub(crate) fn save(
        &self,
        policy: &AccessPolicy,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _lock = crate::platform::access_store::lock(&self.directory, self.owner_uid, true)?;
        policy.validate()?;
        self.check_binding(policy)?;
        let existing = self.load()?;
        if policy.revision != existing.next_revision()? {
            return Err(PolicyError::StaleRevision.into());
        }
        let bytes = serde_json::to_vec_pretty(policy)?;
        crate::platform::access_store::write(&self.directory, self.owner_uid, &bytes)?;
        Ok(())
    }
    fn check_binding(&self, policy: &AccessPolicy) -> Result<(), PolicyError> {
        if policy.owner_uid != self.owner_uid || policy.host_id != self.host_id {
            return Err(PolicyError::WrongHostOrOwner);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "access/tests.rs"]
mod tests;
