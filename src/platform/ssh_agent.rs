//! Session-local indirection for SSH agents whose sockets belong to an attachment.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{symlink, FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use interprocess::local_socket::{ConnectOptions, GenericFilePath, ToFsName};
use interprocess::ConnectWaitMode;

use crate::ipc::LocalStream;

const CHECK_INTERVAL: Duration = Duration::from_secs(1);
const UNAVAILABLE_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;

/// Device, inode, mode, and ctime of a usable agent socket file.
type Fingerprint = (u64, u64, u32, i64, i64);

#[derive(Clone)]
pub(crate) struct SshAgentRegistry(Arc<Mutex<State>>);

struct State {
    path: PathBuf,
    fallback: Option<PathBuf>,
    agents: Vec<(u64, PathBuf)>,
    next_id: u64,
    identity: Option<(u64, u64)>,
    observed: Vec<Option<Fingerprint>>,
    selected: bool,
    last_check: Option<Instant>,
    last_probe: Option<Instant>,
}

pub(crate) struct SshAgentLease {
    registry: SshAgentRegistry,
    id: u64,
}

pub(crate) fn socket_path() -> PathBuf {
    agent_path_for(&crate::api::socket_path())
}

fn agent_path_for(api_path: &Path) -> PathBuf {
    let mut path = api_path.as_os_str().to_os_string();
    path.push(".agent");
    path.into()
}

fn usable_socket(path: &Path) -> bool {
    fingerprint(path).is_some()
}

// A listener that dies in place, or an in-place change that keeps all of these fields, is
// noticed only at the next selection; periodic connect probes would cost a forwarded channel.
fn fingerprint(path: &Path) -> Option<Fingerprint> {
    fs::metadata(path)
        .ok()
        .filter(|metadata| {
            // The API is user-private; do not redirect that user's panes to another user's agent.
            metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() }
        })
        .map(|metadata| {
            (
                metadata.dev(),
                metadata.ino(),
                metadata.mode(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        })
}

/// Number of identities the agent offers, or `None` when it does not answer in time.
// A forwarded agent whose SSH session went away (a suspended laptop) can keep accepting
// connections while never answering, so only a real request proves the agent works.
fn agent_identities(path: &Path) -> Option<u32> {
    if !usable_socket(path) {
        return None;
    }
    let name = path.to_fs_name::<GenericFilePath>().ok()?;
    // Never wait for a full accept queue or retain a forwarded SSH channel after probing.
    let Ok(LocalStream::UdSocket(stream)) = ConnectOptions::new()
        .name(name)
        .wait_mode(ConnectWaitMode::Timeout(Duration::ZERO))
        .nonblocking_stream(true)
        .connect_sync()
    else {
        return None;
    };
    let mut stream = stream.inner();
    // Linux can report an unconnected socket writable after connect returns EAGAIN.
    stream.peer_addr().ok()?;
    stream.set_nonblocking(false).ok()?;
    stream.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT)).ok()?;
    stream
        .write_all(&[0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES])
        .ok()?;
    // Length, message type, and identity count; the identities themselves are not needed.
    let mut answer = [0; 9];
    stream.read_exact(&mut answer).ok()?;
    (answer[4] == SSH_AGENT_IDENTITIES_ANSWER)
        .then(|| u32::from_be_bytes([answer[5], answer[6], answer[7], answer[8]]))
}

impl SshAgentRegistry {
    pub(crate) fn new(path: PathBuf, inherited: Option<PathBuf>) -> io::Result<Self> {
        let inherited = inherited.filter(|path| !path.as_os_str().is_empty());
        let managed = inherited.is_some()
            || fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink());
        // A handoff keeps existing pane environments, including this stable pathname.
        let fallback = fs::read_link(&path)
            .ok()
            .filter(|target| target != &path && usable_socket(target))
            .or_else(|| inherited.filter(|target| target != &path && usable_socket(target)));
        let mut state = State {
            path,
            fallback,
            agents: Vec::new(),
            next_id: 0,
            identity: None,
            observed: Vec::new(),
            selected: false,
            last_check: None,
            last_probe: None,
        };
        if managed {
            state.publish(Instant::now())?;
        }
        Ok(Self(Arc::new(Mutex::new(state))))
    }

    pub(crate) fn register(&self, path: PathBuf) -> io::Result<SshAgentLease> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("SSH agent registry poisoned"))?;
        if !path.is_absolute() || path == state.path || !usable_socket(&path) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SSH agent must be an absolute, user-owned socket",
            ));
        }
        // Canonicalizing /var to /private/var can exceed macOS's Unix socket path limit.
        let id = state.next_id;
        state.next_id += 1;
        state.agents.push((id, path));
        if let Err(error) = state.publish(Instant::now()) {
            state.agents.retain(|(candidate, _)| *candidate != id);
            return Err(error);
        }
        Ok(SshAgentLease {
            registry: self.clone(),
            id,
        })
    }
}

impl State {
    fn ensure_owned(&self) -> io::Result<()> {
        if let Some(identity) = self.identity {
            let metadata = fs::symlink_metadata(&self.path)?;
            if identity != (metadata.dev(), metadata.ino()) {
                return Err(io::Error::other(
                    "SSH agent address belongs to a replacement server",
                ));
            }
        }
        Ok(())
    }

    fn observe(&self) -> Vec<Option<Fingerprint>> {
        self.fallback
            .iter()
            .chain(self.agents.iter().map(|(_, path)| path))
            .map(|path| fingerprint(path))
            .collect()
    }

    fn publish(&mut self, now: Instant) -> io::Result<()> {
        self.ensure_owned()?;
        // Keep a working agent rather than letting probes or a second client replace it.
        let unavailable = self.path.with_extension("unavailable");
        let observed = self.observe();
        self.last_probe = Some(now);
        // An agent without identities is kept only when no other agent offers any.
        let mut empty = None;
        let target = self
            .fallback
            .iter()
            .chain(self.agents.iter().map(|(_, path)| path))
            .find(|path| match agent_identities(path) {
                Some(0) => {
                    empty.get_or_insert(*path);
                    false
                }
                Some(_) => true,
                None => false,
            })
            .or(empty)
            .unwrap_or(&unavailable)
            .to_path_buf();
        if self.identity.is_none()
            || fs::read_link(&self.path).ok().as_deref() != Some(target.as_path())
        {
            let temporary = self
                .path
                .with_extension(format!("{}.new", std::process::id()));
            symlink(&target, &temporary)?;
            if let Err(error) = fs::rename(&temporary, &self.path) {
                let _ = fs::remove_file(&temporary);
                return Err(error);
            }
            let metadata = fs::symlink_metadata(&self.path)?;
            self.identity = Some((metadata.dev(), metadata.ino()));
        }
        // Record the selection only once it is published, so a failed publish is retried.
        self.observed = observed;
        self.selected = target != unavailable;
        Ok(())
    }
}

impl Drop for State {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| self.identity == Some((metadata.dev(), metadata.ino())))
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl SshAgentLease {
    pub(crate) fn refresh(&self) -> io::Result<()> {
        self.refresh_at(Instant::now())
    }

    fn refresh_at(&self, now: Instant) -> io::Result<()> {
        let mut state = self
            .registry
            .0
            .lock()
            .map_err(|_| io::Error::other("SSH agent registry poisoned"))?;
        if state
            .last_check
            .is_some_and(|last| now.saturating_duration_since(last) < CHECK_INTERVAL)
        {
            return Ok(());
        }
        state.last_check = Some(now);
        state.ensure_owned()?;
        // Each probe opens a forwarded SSH channel, so a selected agent is probed again only when a
        // socket file changes. Without one, retry slowly in case a probe failed transiently.
        let observed = state.observe();
        let retry = !state.selected
            && observed.iter().any(Option::is_some)
            && state.last_probe.is_none_or(|last| {
                now.saturating_duration_since(last) >= UNAVAILABLE_RETRY_INTERVAL
            });
        if retry || observed != state.observed {
            state.publish(now)?;
        }
        Ok(())
    }
}

impl Drop for SshAgentLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.registry.0.lock() {
            state.agents.retain(|(id, _)| *id != self.id);
            if let Err(error) = state.publish(Instant::now()) {
                tracing::warn!(%error, "could not refresh SSH agent after attachment ended");
            }
        }
    }
}

pub(crate) fn apply_pane_env(command: &mut portable_pty::CommandBuilder) {
    let path = socket_path();
    if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        command.env("SSH_AUTH_SOCK", path);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Answers identity requests like an agent holding `identities` keys.
    pub(crate) struct FakeAgent {
        accepted: Arc<AtomicUsize>,
        held: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl FakeAgent {
        pub(crate) fn bind(path: &Path, identities: u32) -> Self {
            Self::serve(UnixListener::bind(path).unwrap(), identities)
        }

        fn serve(listener: UnixListener, identities: u32) -> Self {
            listener.set_nonblocking(true).unwrap();
            let accepted = Arc::new(AtomicUsize::new(0));
            let held = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let thread = std::thread::spawn({
                let (accepted, held, stop) = (accepted.clone(), held.clone(), stop.clone());
                move || {
                    while !stop.load(Ordering::Relaxed) {
                        let Ok((stream, _)) = listener.accept() else {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        };
                        accepted.fetch_add(1, Ordering::Relaxed);
                        if !answer(stream, identities) {
                            held.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
            Self {
                accepted,
                held,
                stop,
                thread: Some(thread),
            }
        }

        /// Connections accepted since the last call.
        fn accepted(&self) -> usize {
            self.accepted.swap(0, Ordering::Relaxed)
        }

        /// Stops listening, leaving the socket file behind like a dead sshd, and returns how
        /// many probes kept their connection open after the answer.
        fn finish(mut self) -> usize {
            self.stop.store(true, Ordering::Relaxed);
            self.thread.take().unwrap().join().unwrap();
            self.held.load(Ordering::Relaxed)
        }
    }

    impl Drop for FakeAgent {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// Returns whether the prober closed the connection after reading the answer.
    fn answer(mut stream: UnixStream, identities: u32) -> bool {
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = [0; 5];
        if stream.read_exact(&mut request).is_err()
            || request != [0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES]
        {
            return true;
        }
        let mut reply = vec![0, 0, 0, 5, SSH_AGENT_IDENTITIES_ANSWER];
        reply.extend_from_slice(&identities.to_be_bytes());
        stream.write_all(&reply).unwrap();
        matches!(stream.read(&mut [0]), Ok(0))
    }

    #[test]
    fn server_without_an_agent_leaves_local_pane_agent_setup_alone() {
        let directory = std::env::temp_dir().join(format!("herdr-no-agent-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let stable = directory.join("agent");
        for inherited in [None, Some(PathBuf::new())] {
            let registry = SshAgentRegistry::new(stable.clone(), inherited).unwrap();
            assert!(
                fs::symlink_metadata(&stable).is_err(),
                "a local server without an agent must not advertise an agent address to panes"
            );
            drop(registry);
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn closed_agent_listener_does_not_block_a_live_replacement() {
        let directory =
            std::env::temp_dir().join(format!("herdr-dead-agent-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let stable = directory.join("agent");
        let a = directory.join("a");
        let b = directory.join("b");
        let agent_a = FakeAgent::bind(&a, 1);
        let _agent_b = FakeAgent::bind(&b, 1);
        let registry = SshAgentRegistry::new(stable.clone(), Some(a.clone())).unwrap();
        let lease_b = registry.register(b.clone()).unwrap();
        assert_eq!(fs::read_link(&stable).unwrap(), a);
        assert_eq!(
            agent_a.finish(),
            0,
            "agent checks must not hold forwarded SSH channels open"
        );
        assert!(fs::metadata(&a).unwrap().file_type().is_socket());
        // Periodic checks do not probe an unchanged socket file.
        lease_b.refresh_at(Instant::now() + CHECK_INTERVAL).unwrap();
        assert_eq!(fs::read_link(&stable).unwrap(), a);
        // The next selection skips the stale socket.
        let lease_c = registry.register(b.clone()).unwrap();
        assert_eq!(fs::read_link(&stable).unwrap(), b);
        drop(lease_c);
        assert_eq!(fs::read_link(&stable).unwrap(), b);
        drop(lease_b);
        drop(registry);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unestablished_agent_connection_does_not_block_a_live_replacement() {
        use std::os::fd::AsRawFd;
        let directory =
            std::env::temp_dir().join(format!("herdr-busy-agent-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let a = directory.join("a");
        let b = directory.join("b");
        let stable = directory.join("agent");
        let listener_a = UnixListener::bind(&a).unwrap();
        // Linux allows one queued connection with a zero backlog.
        assert_eq!(unsafe { libc::listen(listener_a.as_raw_fd(), 0) }, 0);
        let _queued = UnixStream::connect(&a).unwrap();
        let _agent_b = FakeAgent::bind(&b, 1);
        let registry = SshAgentRegistry::new(stable.clone(), Some(a)).unwrap();
        let lease_b = registry.register(b.clone()).unwrap();
        assert_eq!(fs::read_link(&stable).unwrap(), b);
        drop(lease_b);
        drop(registry);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn accepted_connections(listener: &UnixListener) -> usize {
        listener.set_nonblocking(true).unwrap();
        std::iter::from_fn(|| listener.accept().ok()).count()
    }

    #[test]
    fn unresponsive_agent_does_not_block_a_live_replacement() {
        let directory =
            std::env::temp_dir().join(format!("herdr-hung-agent-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let stable = directory.join("agent");
        let a = directory.join("a");
        let b = directory.join("b");
        // Accepts connections but never answers, like an agent forwarded by a suspended client.
        let _hung = UnixListener::bind(&a).unwrap();
        let _agent_b = FakeAgent::bind(&b, 1);
        let registry = SshAgentRegistry::new(stable.clone(), None).unwrap();
        let lease_a = registry.register(a.clone()).unwrap();
        assert_eq!(
            fs::read_link(&stable).unwrap(),
            stable.with_extension("unavailable")
        );
        let lease_b = registry.register(b.clone()).unwrap();
        assert_eq!(fs::read_link(&stable).unwrap(), b);
        drop(lease_b);
        drop(lease_a);
        drop(registry);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn agent_with_identities_is_preferred_over_an_empty_one() {
        let directory =
            std::env::temp_dir().join(format!("herdr-empty-agent-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let stable = directory.join("agent");
        let a = directory.join("a");
        let b = directory.join("b");
        let _agent_a = FakeAgent::bind(&a, 0);
        let _agent_b = FakeAgent::bind(&b, 2);
        let registry = SshAgentRegistry::new(stable.clone(), None).unwrap();
        let lease_a = registry.register(a.clone()).unwrap();
        assert_eq!(
            fs::read_link(&stable).unwrap(),
            a,
            "an empty agent is better than none"
        );
        let lease_b = registry.register(b.clone()).unwrap();
        assert_eq!(fs::read_link(&stable).unwrap(), b);
        drop(lease_b);
        assert_eq!(fs::read_link(&stable).unwrap(), a);
        drop(lease_a);
        drop(registry);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn periodic_refresh_does_not_connect_to_agents() {
        let directory =
            std::env::temp_dir().join(format!("herdr-agent-quiet-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let stable = directory.join("agent");
        let a = directory.join("a");
        let b = directory.join("b");
        let stale = UnixListener::bind(&a).unwrap();
        drop(stale);
        let agent_b = FakeAgent::bind(&b, 1);
        let registry = SshAgentRegistry::new(stable.clone(), Some(a.clone())).unwrap();
        let lease = registry.register(b.clone()).unwrap();
        assert_eq!(
            fs::read_link(&stable).unwrap(),
            b,
            "selection must skip a socket file left by a crashed sshd"
        );
        assert!(agent_b.accepted() > 0);

        let start = Instant::now();
        for second in 1..=100 {
            lease.refresh_at(start + CHECK_INTERVAL * second).unwrap();
        }
        assert_eq!(
            agent_b.accepted(),
            0,
            "periodic refresh must not open forwarded SSH channels"
        );
        assert_eq!(fs::read_link(&stable).unwrap(), b);

        // A replaced socket file is probed again. The old listener keeps its inode alive.
        let before = fingerprint(&b).unwrap();
        fs::remove_file(&b).unwrap();
        let replacement = FakeAgent::bind(&b, 1);
        assert_ne!(fingerprint(&b).unwrap(), before);
        lease.refresh_at(start + CHECK_INTERVAL * 101).unwrap();
        assert_eq!(replacement.accepted(), 1);
        assert_eq!(agent_b.accepted(), 0);
        assert_eq!(fs::read_link(&stable).unwrap(), b);

        drop(lease);
        drop(registry);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failed_publication_is_retried_by_remaining_leases() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let directory =
            std::env::temp_dir().join(format!("herdr-agent-publish-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let stable = directory.join("agent");
        let a = directory.join("a");
        let b = directory.join("b");
        let _agent_a = FakeAgent::bind(&a, 1);
        let _agent_b = FakeAgent::bind(&b, 1);
        let registry = SshAgentRegistry::new(stable.clone(), None).unwrap();
        let lease_a = registry.register(a.clone()).unwrap();
        let lease_b = registry.register(b.clone()).unwrap();
        assert_eq!(fs::read_link(&stable).unwrap(), a);

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
        drop(lease_a);
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(fs::read_link(&stable).unwrap(), a);
        lease_b.refresh_at(Instant::now() + CHECK_INTERVAL).unwrap();
        assert_eq!(fs::read_link(&stable).unwrap(), b);
        drop(lease_b);
        drop(registry);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn transient_probe_failure_recovers_without_a_socket_change() {
        use std::os::fd::AsRawFd;
        let directory =
            std::env::temp_dir().join(format!("herdr-agent-retry-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let stable = directory.join("agent");
        let a = directory.join("a");
        let listener = UnixListener::bind(&a).unwrap();
        // Linux allows one queued connection with a zero backlog.
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let queued = UnixStream::connect(&a).unwrap();
        let registry = SshAgentRegistry::new(stable.clone(), None).unwrap();
        let lease = registry.register(a.clone()).unwrap();
        assert_eq!(
            fs::read_link(&stable).unwrap(),
            stable.with_extension("unavailable")
        );

        drop(queued);
        assert_eq!(accepted_connections(&listener), 1);
        let agent = FakeAgent::serve(listener, 1);
        let fingerprint_before = fingerprint(&a);
        let start = Instant::now();
        lease.refresh_at(start + CHECK_INTERVAL).unwrap();
        assert_eq!(agent.accepted(), 0, "retries back off");
        lease
            .refresh_at(start + UNAVAILABLE_RETRY_INTERVAL)
            .unwrap();
        assert_eq!(fingerprint(&a), fingerprint_before);
        assert_eq!(fs::read_link(&stable).unwrap(), a);
        assert_eq!(agent.accepted(), 1);

        lease
            .refresh_at(start + UNAVAILABLE_RETRY_INTERVAL * 10)
            .unwrap();
        assert_eq!(agent.accepted(), 0, "a selected agent is not probed");
        drop(lease);
        drop(registry);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn registration_preserves_the_supplied_socket_address() {
        let directory =
            std::env::temp_dir().join(format!("herdr-agent-path-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        symlink(".", directory.join("alias")).unwrap();
        let _agent = FakeAgent::bind(&directory.join("upstream"), 1);
        let supplied = directory.join("alias/upstream");
        let stable = directory.join("agent");
        let registry = SshAgentRegistry::new(stable.clone(), None).unwrap();
        let lease = registry.register(supplied.clone()).unwrap();
        assert_eq!(fs::read_link(&stable).unwrap(), supplied);
        drop(lease);
        drop(registry);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn socket_overrides_have_independent_agent_addresses() {
        let directory =
            std::env::temp_dir().join(format!("herdr-agent-overrides-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let a = directory.join("a");
        let b = directory.join("b");
        let _agent_a = FakeAgent::bind(&a, 1);
        let _agent_b = FakeAgent::bind(&b, 1);
        let stable_a = agent_path_for(&directory.join("first.sock"));
        let stable_b = agent_path_for(&directory.join("second.sock"));
        let registry_a = SshAgentRegistry::new(stable_a.clone(), Some(a.clone())).unwrap();
        let registry_b = SshAgentRegistry::new(stable_b.clone(), Some(b.clone())).unwrap();
        assert_eq!(fs::read_link(&stable_a).unwrap(), a);
        assert_eq!(fs::read_link(&stable_b).unwrap(), b);
        drop(registry_a);
        assert_eq!(fs::read_link(&stable_b).unwrap(), b);
        drop(registry_b);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reconnect_and_overlapping_attachments_keep_a_stable_agent_address() {
        let directory =
            std::env::temp_dir().join(format!("herdr-ssh-agent-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let stable = directory.join("agent");
        let a = directory.join("a");
        let b = directory.join("b");
        let probe = directory.join("probe");
        let _agent_a = FakeAgent::bind(&a, 1);
        let _agent_b = FakeAgent::bind(&b, 1);
        let _agent_probe = FakeAgent::bind(&probe, 1);
        let registry = SshAgentRegistry::new(stable.clone(), Some(a.clone())).unwrap();
        let temporary = registry.register(a.clone()).unwrap();
        drop(temporary);
        assert_eq!(fs::read_link(&stable).unwrap(), a);
        let lease_a = registry.register(a.clone()).unwrap();
        let lease_probe = registry.register(probe).unwrap();
        assert_eq!(fs::read_link(&stable).unwrap(), a);
        drop(lease_probe);
        let lease_b = registry.register(b.clone()).unwrap();
        assert_eq!(fs::read_link(&stable).unwrap(), a);
        fs::remove_file(&a).unwrap();
        lease_b.refresh_at(Instant::now() + CHECK_INTERVAL).unwrap();
        assert_eq!(fs::read_link(&stable).unwrap(), b);
        drop(lease_a);
        assert_eq!(fs::read_link(&stable).unwrap(), b);
        drop(lease_b);
        assert!(!stable.exists());
        assert!(fs::symlink_metadata(&stable).is_ok());
        let _lease_b = registry.register(b.clone()).unwrap();
        assert_eq!(fs::read_link(&stable).unwrap(), b);
        assert!(registry.register(stable).is_err());
        drop(_lease_b);
        drop(registry);
        fs::remove_dir_all(directory).unwrap();
    }
}
