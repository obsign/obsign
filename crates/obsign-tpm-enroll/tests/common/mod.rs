//! Shared swtpm process management for the integration tests: temp state
//! dir, ephemeral ports, cleanup on drop. Nothing here is test-logic. The
//! tests own what they prove against the instance.

#![allow(dead_code)] // each integration test binary uses its own subset

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use obsign_tpm_enroll::ctrl::SwtpmCtrl;

pub fn swtpm_on_path() -> bool {
    Command::new("swtpm")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

pub fn go_on_path() -> bool {
    Command::new("go")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// A running swtpm and its cleanup. Kills the process and removes the state
/// directory even when an assertion fails mid-test.
pub struct Swtpm {
    child: Child,
    pub state: PathBuf,
    pub tpm_addr: String,
    pub ctrl: SwtpmCtrl,
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.ctrl.shutdown();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.state);
    }
}

/// Two distinct free ports: both listeners are held until both ports are
/// known, so the pair cannot collide with itself. Released before swtpm
/// binds them; a race against another process is possible but the spawn
/// below retries.
fn ephemeral_ports() -> (u16, u16) {
    let bind = || TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let (a, b) = (bind(), bind());
    let port = |l: &TcpListener| l.local_addr().expect("local addr").port();
    (port(&a), port(&b))
}

/// Serializes swtpm startup within one test binary: tests run in parallel,
/// and two of them picking ports at once could each release a port the
/// other is about to bind.
static START: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn start_swtpm(tag: &str) -> Swtpm {
    let _guard = START.lock().unwrap_or_else(|p| p.into_inner());
    for attempt in 0..3 {
        let state = std::env::temp_dir().join(format!(
            "obsign-swtpm-{tag}-{}-{attempt}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&state);
        std::fs::create_dir_all(&state).expect("create state dir");
        let (tpm_port, ctrl_port) = ephemeral_ports();
        let child = Command::new("swtpm")
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", state.display()),
                "--server",
                &format!("type=tcp,port={tpm_port},bindaddr=127.0.0.1"),
                "--ctrl",
                &format!("type=tcp,port={ctrl_port},bindaddr=127.0.0.1"),
            ])
            .spawn()
            .expect("spawn swtpm");
        let ctrl = SwtpmCtrl::new(format!("127.0.0.1:{ctrl_port}"));
        // Ready means CMD_INIT succeeded, so callers get an initialized TPM;
        // give it 5 seconds. A bare connect probe is not enough: swtpm's
        // control channel serves one connection at a time, and a probe
        // closed under load can reset the CMD_INIT that follows it. And a
        // swtpm that lost a port race exits, its port possibly someone
        // else's, so the child must still be alive.
        let mut child = child;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if matches!(child.try_wait(), Ok(Some(_))) {
                break; // exited: lost a port race, retry on fresh ports
            }
            if ctrl.init().is_ok() && matches!(child.try_wait(), Ok(None)) {
                return Swtpm {
                    child,
                    state,
                    tpm_addr: format!("127.0.0.1:{tpm_port}"),
                    ctrl,
                };
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // Port race or startup failure: reap and retry on fresh ports.
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&state);
    }
    panic!("swtpm did not come up on three attempts");
}
