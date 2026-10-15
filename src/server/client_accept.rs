use std::io;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use interprocess::local_socket::traits::{Listener as _, Stream as _};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::ipc::LocalListener;
use crate::server::client_transport::{self, ServerEvent};

/// Accepts pending thin-client connections and starts their handshake readers.
pub(crate) fn accept_pending_client_connections(
    listener: &LocalListener,
    next_client_id: &mut u64,
    should_quit: &Arc<AtomicBool>,
    server_event_tx: &mpsc::Sender<ServerEvent>,
) -> io::Result<()> {
    loop {
        if should_quit.load(Ordering::Acquire) {
            break;
        }
        match listener.accept() {
            Ok(stream) => {
                let client_id = *next_client_id;
                *next_client_id = next_client_id.saturating_add(1);

                if let Err(err) = stream.set_nonblocking(true) {
                    warn!(err = %err, "failed to set client stream nonblocking");
                    continue;
                }

                let should_quit = should_quit.clone();
                let server_event_tx = server_event_tx.clone();
                let spawned = crate::thread_spawn::spawn_named("herdr-client-conn", move || {
                    if let Err(err) = client_transport::handle_client_handshake(
                        stream,
                        client_id,
                        &server_event_tx,
                        &should_quit,
                    ) {
                        debug!(client_id, err = %err, "client handshake failed");
                    }
                });
                if let Err(err) = spawned {
                    warn!(client_id, err = %err, "failed to spawn client connection thread; dropping connection");
                }
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => {
                error!(err = %err, "client listener accept failed");
                break;
            }
        }
    }

    Ok(())
}

/// Drains pending thin-client connections without starting handshakes.
///
/// During live handoff the old server must not let clients sit in the Unix
/// listener backlog waiting for a welcome frame that will never be sent.
pub(crate) fn reject_pending_client_connections(listener: &LocalListener) -> io::Result<()> {
    loop {
        match listener.accept() {
            Ok(_stream) => {}
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => {
                error!(err = %err, "client listener reject failed");
                break;
            }
        }
    }

    Ok(())
}

/// Accept native shared endpoints, authenticating the kernel identity before welcome.
pub(crate) fn accept_pending_shared_client_connections(
    listener: &LocalListener,
    policy_directory: &std::path::Path,
    policy_host_id: &str,
    next_client_id: &mut u64,
    should_quit: &Arc<AtomicBool>,
    server_event_tx: &mpsc::Sender<ServerEvent>,
) -> io::Result<()> {
    loop {
        if should_quit.load(Ordering::Acquire) {
            break;
        }
        match listener.accept() {
            Ok(stream) => {
                let client_id = *next_client_id;
                *next_client_id = next_client_id.saturating_add(1);
                // Never trust a caller UID or name supplied by endpoint JSON.
                let auth = match crate::shared::native_transport::NativePrincipal::authenticate(
                    &stream,
                    policy_directory,
                    policy_host_id,
                ) {
                    Ok(auth) => auth,
                    Err(error) => {
                        debug!(client_id, %error, "shared client identity rejected");
                        continue;
                    }
                };
                let should_quit = should_quit.clone();
                let server_event_tx = server_event_tx.clone();
                if let Err(error) =
                    crate::thread_spawn::spawn_named("herdr-shared-client", move || {
                        if let Err(error) = client_transport::handle_client_handshake_with_auth(
                            stream,
                            client_id,
                            &server_event_tx,
                            &should_quit,
                            Some(auth),
                        ) {
                            debug!(client_id, %error, "shared client handshake failed");
                        }
                    })
                {
                    warn!(client_id, %error, "failed to spawn shared client handshake");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
