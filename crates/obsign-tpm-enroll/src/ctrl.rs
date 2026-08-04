//! swtpm control channel, the out-of-band socket that stands in for the
//! platform's power and reset lines. A hardware TPM is initialized by the
//! machine it sits in; swtpm waits for `CMD_INIT` on this channel before the
//! command socket answers anything. Only the two commands enrollment and its
//! tests need; the protocol is a 4-byte big-endian command code, an optional
//! payload, and a 4-byte big-endian result (0 on success), one connection
//! per command.

use crate::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const CMD_INIT: u32 = 2;
const CMD_SHUTDOWN: u32 = 3;

/// One swtpm control endpoint (`--ctrl type=tcp,port=...`).
pub struct SwtpmCtrl {
    addr: String,
}

impl SwtpmCtrl {
    pub fn new(addr: impl Into<String>) -> Self {
        SwtpmCtrl { addr: addr.into() }
    }

    /// Brings the TPM up (`CMD_INIT`, no flags): until this, the command
    /// socket refuses everything.
    pub fn init(&self) -> Result<(), Error> {
        self.exec("CMD_INIT", CMD_INIT, &0u32.to_be_bytes())
    }

    /// Asks the swtpm process to exit (`CMD_SHUTDOWN`), for test cleanup.
    pub fn shutdown(&self) -> Result<(), Error> {
        self.exec("CMD_SHUTDOWN", CMD_SHUTDOWN, &[])
    }

    fn exec(&self, name: &'static str, cmd: u32, payload: &[u8]) -> Result<(), Error> {
        let mut s = TcpStream::connect(&self.addr)?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        s.set_write_timeout(Some(Duration::from_secs(10)))?;
        let mut buf = cmd.to_be_bytes().to_vec();
        buf.extend_from_slice(payload);
        s.write_all(&buf)?;
        let mut code = [0u8; 4];
        s.read_exact(&mut code)?;
        let code = u32::from_be_bytes(code);
        if code != 0 {
            return Err(Error::Ctrl {
                command: name,
                code,
            });
        }
        Ok(())
    }
}
