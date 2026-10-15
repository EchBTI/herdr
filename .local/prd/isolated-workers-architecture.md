# Isolated workers: architecture decision (herdr-ocr.1)

Decision recorded 2026-10-15. Select rootless Bubblewrap on Linux, with a fixed
Herdr-generated mount/namespace policy and a separate, workspace-scoped broker.
This is an opt-in execution mode. Ordinary existing terminals retain their
trusted-collaboration execution identity until explicitly migrated.

## Why this boundary

| Approach | Privilege/provisioning | Decision |
| --- | --- | --- |
| Rootless Bubblewrap | Administrator installs trusted `/usr/bin/bwrap`; kernel permits unprivileged user, mount, PID, IPC, UTS, cgroup and network namespaces. Herdr stays an ordinary user. | Selected. Small launcher surface; no delegated host privilege or engine socket. |
| Separate worker accounts plus constrained launcher | Administrator provisions accounts and a privileged service/setuid/sudo launcher, filesystem isolation and its independent policy. Separate UIDs alone still expose world-readable host files and network services. | Rejected for this implementation: introduces a privileged service and privileged path-validation code. |
| Owner-accessible Docker daemon | Docker socket/engine authority can grant host root or arbitrary mounts. | Rejected as the runtime boundary. Docker is only the disposable qualification environment; never mount its socket into Herdr or a worker. |

Upstream documents that Bubblewrap supplies mechanisms, while its caller owns
the security policy. Its no-new-privileges, namespace and session behavior is
documented in the [upstream README](https://github.com/containers/bubblewrap/blob/main/README.md).

## Identities and capabilities

The attaching human remains the kernel-authenticated UID/account principal in
Herdr's access policy. Worker namespace identity is separate: the unprivileged
owner's outer UID is mapped into a new user namespace; this is **not** a separately
provisioned host account. Show “isolated worker” together with the host execution
account, project identity and network policy. Never describe this as another
host UID.

The daemon does not invoke sudo, a setuid helper or a privileged container engine.
The launcher rejects root hosting for this mode, requires a trusted system
Bubblewrap executable, drops all namespace capabilities, creates a new session,
and uses Bubblewrap's no-new-privileges and die-with-parent behavior. Parent
PTYs remain daemon-owned; workers receive their own slave terminal only.

## Filesystem, environment and network policy

Construct an empty mount namespace. Mount trusted system programs/libraries
read-only; expose private procfs for the worker PID namespace and a minimal devfs.
Use private tmpfs `/tmp` and `/run` and a private empty HOME. Bind **only** the
selected project root writable, at its original absolute path so shell cwd
reporting and subsequent pane creation remain compatible. Empty destination
parents do not bind the owner's real home or other host ancestors.

The root and cwd must canonicalize; cwd must remain inside the selected root.
Root-level, system-runtime and overlapping project mounts are rejected. Never
mount owner home/config/cache, SSH agents, display/D-Bus sockets, owner API/client
sockets, Docker sockets, sibling project roots or a host procfs. Symlinks inside
the project resolve against the constructed namespace. Deliberately stored
project credentials are available to everyone controlling that project.

Clear the environment **before launching Bubblewrap**, including loader variables
and agent/provider credentials. Retain only fixed terminal/locale values and
explicit workspace/incarnation/tab/pane identity. Set a private HOME, fixed PATH,
scoped broker address and workspace token. Mount the Herdr executable read-only
as `/run/herdr/herdr`; mount only the selected broker socket at
`/run/herdr/worker.sock`. Do not bind executable parent directories.

Unshare the network namespace. There is no host loopback, abstract Unix socket
namespace or outbound network by default. This mode therefore cannot use remote
AI providers without a separately reviewed, explicitly scoped network/secret
provisioning extension. No broad network or host-secret fallback is permitted.

## Scoped integration broker

Issue independent unpredictable tokens bound to the persisted workspace identity,
incarnation and current workspace broker generation. Tokens travel only to their
worker, never through shared snapshots. The broker verifies the complete binding
and its active generation before resolving any requested pane. Copying a token
to another workspace/incarnation or replaying a retired token must fail.

Allow only project-local reporting and explicitly permitted project control;
reject global administrative operations and IDs outside the bound project.
Preserve authenticated human authorization for controller operations. A worker
is not the Owner principal, even when its host UID matches the daemon. The
existing unrestricted owner API is not reachable through this broker.

## Crash recovery and migration

Every spawn path, including agent commands, split/new-tab, restore and respawn,
passes the same final wrapping boundary. Missing Bubblewrap, unavailable kernel
features, invalid profiles or broker failure deny creation; never retry as an
owner shell. Namespace PID-1/parent-death behavior must terminate descendants
when the pane/server dies. New generations revoke old tokens before enabling
replacement workers.

Migration is owner-initiated and explicit. Persist the chosen project identity,
incarnation and isolated execution profile; reject roots that overlap another
isolated project. Refuse migration while the daemon is running. The owner stops it, explicitly
acknowledges process restart, and configures the persisted workspace profile;
restart then recreates every restored PTY through the launcher. Restore the
profile before restoring its terminals. An unresolvable or invalid profile leaves the workspace unavailable.
Disabling sharing or revoking a human's space grant revokes that connection; it
does not silently convert an isolated worker back into an owner process.

## Evidence and required qualification

Initial executable design probe passed **13/13** checks as UID 65534 in a
disposable Linux container using Bubblewrap 0.12.0: own-project writes succeed;
owner files, sibling credentials, owner socket and symlink escape are absent;
owner environment is absent; host processes are hidden; host loopback and
abstract Unix sockets are inaccessible; no-new-privileges is set; worker is
non-root; the file-mounted executable and scoped socket are available. The probe did not mount host credentials or Docker sockets.

Docker's default procfs masks prevent the nested proc mount even after allowing
namespace syscalls. Qualification uses outer-container
`--security-opt seccomp=unconfined --security-opt systempaths=unconfined`; payloads
remain unprivileged and no SYS_ADMIN capability is granted. These are explicit
test-environment requirements, not privileges requested by Herdr. Production
must independently pass its rootless preflight and fail closed otherwise.

Before stronger release claims, `herdr-ocr.3` must exercise the **actual** runtime
wrapper and broker: files/read/write, sibling roots, symlinks, inherited FDs,
owner/private/abstract sockets, process signals/ptrace/proc, network and owner
environment; forged/cross-space/retired tokens; worker/server crash descendants;
restore and explicit migration; read/control authorization and scoped agent
reports. Root/host administrators, kernel vulnerabilities, resource exhaustion,
and credentials deliberately provisioned into the project remain outside this
boundary. This architecture decision authorizes implementation; it does not
replace that release qualification.


## Completed implementation qualification

The actual Herdr launcher, native pane runtime and scoped broker passed 43 checks
in the disposable Linux environment, including child termination on pane close
and actual server SIGKILL, private PID/signal/ptrace boundaries, token retirement,
project/owner/sibling access, network isolation, restoration and explicit migration.
The repeatable command is `just test-isolated-workers-linux`. See
`os-user-space-access-validation.md` for all measured evidence and limitations.
Isolated snapshots use version 4 before enabling their worker registry; older
version-3 readers reject them. Ordinary sessions remain version 3. A missing
worker profile preserves the required boundary and forbids live handoff.

This qualification supports the limited Linux isolation claims in the operator
guide. It does not establish a separate host UID, online provider provisioning,
protection against the host administrator/kernel, or resource-exhaustion control.
