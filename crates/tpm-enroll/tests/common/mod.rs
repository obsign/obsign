//! Shared swtpm process management for the integration tests: temp state
//! dir, ephemeral ports, cleanup on drop. Nothing here is test-logic — the
//! tests own what they prove against the instance.

#![allow(dead_code)] // each integration test binary uses its own subset

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tpm_enroll::ctrl::SwtpmCtrl;

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

fn ephemeral_port() -> u16 {
    // Bind :0, note the port, release it. A race against another process is
    // possible but the spawn below retries.
    TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

pub fn start_swtpm(tag: &str) -> Swtpm {
    for attempt in 0..3 {
        let state = std::env::temp_dir().join(format!(
            "probant-swtpm-{tag}-{}-{attempt}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&state);
        std::fs::create_dir_all(&state).expect("create state dir");
        let (tpm_port, ctrl_port) = (ephemeral_port(), ephemeral_port());
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
        // The control socket appears when swtpm is ready; give it 5 seconds.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if TcpStream::connect(format!("127.0.0.1:{ctrl_port}")).is_ok() {
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
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&state);
    }
    panic!("swtpm did not come up on three attempts");
}
