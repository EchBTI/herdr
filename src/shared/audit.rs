//! Bounded, rate-limited audit delivery. The event loop never performs disk I/O.
use std::path::Path;
use std::sync::mpsc::{self, SyncSender};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const QUEUE: usize = 64;
const PER_SECOND: u32 = 64;

#[derive(Debug, serde::Serialize)]
pub(crate) struct Record {
    unix_seconds: u64,
    process_id: u32,
    uid: u32,
    revision: u64,
    operation: &'static str,
    outcome: &'static str,
    scope: Option<String>,
    suppressed: u64,
}
struct Window {
    started: Instant,
    accepted: u32,
    suppressed: u64,
}
/// Metadata only: never pass terminal input, command arguments, paths, or labels.
pub(crate) struct Audit {
    critical_sender: SyncSender<Record>,
    sender: SyncSender<Record>,
    window: Mutex<Window>,
    critical_window: Mutex<Window>,
}
impl Audit {
    pub(crate) fn new(directory: &Path, owner: u32) -> std::io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Record>(QUEUE);
        let (critical_sender, critical_receiver) = mpsc::sync_channel::<Record>(16);
        let directory = directory.to_owned();
        crate::thread_spawn::spawn_named("herdr-access-audit", move || {
            // Separate bounded priority capacity keeps denial floods from hiding
            // owner policy/lifecycle changes. All disk work stays on this worker.
            let append = |record: Record| {
                if let Ok(bytes) = serde_json::to_vec(&record) {
                    if let Err(error) =
                        crate::platform::access_store::append_audit(&directory, owner, &bytes)
                    {
                        tracing::warn!(%error, "shared access audit unavailable");
                    }
                }
            };
            loop {
                if let Ok(record) = critical_receiver.try_recv() {
                    append(record);
                    continue;
                }
                match receiver.recv_timeout(Duration::from_millis(50)) {
                    Ok(record) => append(record),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        for record in critical_receiver.try_iter() {
                            append(record);
                        }
                        break;
                    }
                }
            }
        })?;
        Ok(Self::with_senders(sender, critical_sender))
    }
    #[cfg(test)]
    pub(crate) fn test_noop() -> Self {
        let (sender, _receiver) = mpsc::sync_channel(1);
        Self::with_sender(sender)
    }
    #[cfg(test)]
    pub(crate) fn test_channel() -> (Self, mpsc::Receiver<Record>) {
        let (sender, receiver) = mpsc::sync_channel(QUEUE);
        (Self::with_sender(sender), receiver)
    }
    #[cfg(test)]
    fn with_sender(sender: SyncSender<Record>) -> Self {
        Self::with_senders(sender.clone(), sender)
    }
    fn with_senders(sender: SyncSender<Record>, critical_sender: SyncSender<Record>) -> Self {
        Self {
            critical_sender,
            sender,
            window: Mutex::new(Window {
                started: Instant::now(),
                accepted: 0,
                suppressed: 0,
            }),
            critical_window: Mutex::new(Window {
                started: Instant::now(),
                accepted: 0,
                suppressed: 0,
            }),
        }
    }
    pub(crate) fn record(
        &self,
        uid: u32,
        revision: u64,
        operation: &'static str,
        outcome: &'static str,
        scope: Option<&str>,
    ) {
        let critical = operation.starts_with("policy.")
            || operation.starts_with("sharing.")
            || operation.starts_with("account.")
            || matches!(
                operation,
                "grant" | "revoke" | "grants.set" | "disable" | "topology.refresh"
            );
        // Independent locks preserve reserved policy capacity even while a
        // concurrent handshake producer holds the ordinary denial window.
        let window = if critical {
            &self.critical_window
        } else {
            &self.window
        };
        let Ok(mut window) = window.try_lock() else {
            return;
        };
        if window.started.elapsed() >= Duration::from_secs(1) {
            window.started = Instant::now();
            window.accepted = 0;
        }
        if window.accepted >= if critical { 16 } else { PER_SECOND } {
            window.suppressed = window.suppressed.saturating_add(1);
            return;
        }
        // Public IDs are short. Reject unexpectedly large scope metadata, rather
        // than allocating from untrusted input or logging arbitrary text.
        let scope = scope.filter(|scope| scope.len() <= 128).map(str::to_owned);
        let record = Record {
            unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|time| time.as_secs())
                .unwrap_or(0),
            process_id: std::process::id(),
            uid,
            revision,
            operation,
            outcome,
            scope,
            suppressed: window.suppressed,
        };
        let sender = if critical {
            &self.critical_sender
        } else {
            &self.sender
        };
        if sender.try_send(record).is_ok() {
            window.accepted += 1;
            window.suppressed = 0;
        } else {
            window.suppressed = window.suppressed.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denial_burst_is_bounded_without_waiting_for_a_disk_worker() {
        let (sender, receiver) = mpsc::sync_channel(QUEUE);
        let audit = Audit::with_sender(sender);
        for _ in 0..100_000 {
            audit.record(1001, 7, "terminal.input", "denied", Some("w1"));
        }
        let records = receiver.try_iter().collect::<Vec<_>>();
        assert_eq!(records.len(), QUEUE);
        assert!(records
            .iter()
            .all(|record| record.uid == 1001 && record.revision == 7));
        assert!(audit.window.lock().unwrap().suppressed > 90_000);
        // Next window emits the exact suppressed count alongside ordinary metadata.
        audit.window.lock().unwrap().started = Instant::now() - Duration::from_secs(2);
        audit.record(1001, 8, "terminal.input", "denied", None);
        assert!(receiver.try_recv().unwrap().suppressed > 90_000);
    }
    #[test]
    fn denial_flood_cannot_fill_reserved_policy_audit_capacity() {
        let (sender, receiver) = mpsc::sync_channel(QUEUE);
        let (critical_sender, critical_receiver) = mpsc::sync_channel(16);
        let audit = Audit::with_senders(sender, critical_sender);
        for _ in 0..100_000 {
            audit.record(1001, 7, "terminal.input", "denied", None);
        }
        audit.record(1000, 8, "policy.refresh", "allowed", None);
        assert_eq!(receiver.try_iter().count(), QUEUE);
        assert_eq!(critical_receiver.try_recv().unwrap().revision, 8);
    }
    #[test]
    fn normal_producer_contention_cannot_drop_critical_policy_audit() {
        let (sender, _receiver) = mpsc::sync_channel(QUEUE);
        let (critical_sender, critical_receiver) = mpsc::sync_channel(16);
        let audit = Audit::with_senders(sender, critical_sender);
        let _normal_window = audit.window.lock().unwrap();
        audit.record(1000, 9, "policy.refresh", "allowed", None);
        let record = critical_receiver
            .try_recv()
            .expect("critical lane remains independent");
        assert_eq!(record.uid, 1000);
        assert_eq!(record.revision, 9);
    }
    #[test]
    fn queue_backpressure_never_allocates_an_unbounded_backlog() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let audit = Audit::with_sender(sender);
        for _ in 0..1000 {
            audit.record(1, 2, "attach", "allowed", Some(&"x".repeat(4096)));
        }
        let record = receiver.try_recv().unwrap();
        assert!(record.scope.is_none());
        assert!(receiver.try_recv().is_err());
    }
}
