// Copyright © 2022, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

use anyhow::anyhow;
use nix::sys::socket::{recv, recvfrom, sendmsg, ControlMessage, MsgFlags};
use nix::sys::uio::IoVec;
use std::io::prelude::*;
use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::str;
use std::thread::sleep;
use std::time::{Duration, Instant};
use thiserror::Error;

const TPM_TIS_BUFFER_MAX: usize = 4096;

#[derive(Error, Debug)]
pub enum TPMSocError {
    #[error("Cannot connect to TPM Socket even after retrying for 1 min")]
    TPMSocCannotConnect(#[source] anyhow::Error),
    #[error("Failed to read from TPM socket")]
    TPMSocFailedRead(#[source] anyhow::Error),
    #[error("Failed to write to TPM socket")]
    TPMSocFailedWrite(#[source] anyhow::Error),
    #[error("Failed to configure TPM Char backend")]
    TPMSocBackendConfigureFailed(#[source] anyhow::Error)
}
type Result<T> = anyhow::Result<T, TPMSocError>;

#[derive(PartialEq)]
enum SocDevState {
    SocDevStateDisconnected,
    SocDevStateConnecting,
    SocDevStateConnected,
}

/// Copy data in `from` into `to`, until the shortest
/// of the two slices.
///
/// Return the number of bytes written.
///TODO::: this should be dropped
fn byte_copy(from: &[u8], mut to: &mut [u8]) -> usize {
    to.write(from).unwrap()
}

pub struct SocketDev {
    state: SocDevState,
    stream: Option<UnixStream>,
    /// Fd sent to swtpm process for Data
    write_msgfd: RawFd,
    /// Control Channel
    ctrl_fd: RawFd,
    /// Data Channel
    data_fd: RawFd,
}

impl SocketDev {
    pub fn new() -> Self {
        Self {
            state: SocDevState::SocDevStateDisconnected,
            stream: None,
            write_msgfd: -1,
            ctrl_fd: -1,
            data_fd: -1,
        }
    }

    pub fn init(&mut self, path: String) -> Result<()> {
        let _ = self.connect(&path)?;
        Ok(())
    }

    pub fn connect(&mut self, socket_path: &str) -> Result<isize> {
        self.state = SocDevState::SocDevStateConnecting;

        let now = Instant::now();

        // Retry connecting for a full minute
        loop {
            match UnixStream::connect(socket_path) {
                Ok(s) => {
                    let fd = s.as_raw_fd();
                    self.ctrl_fd = fd;
                    self.stream = Some(s);
                    self.state = SocDevState::SocDevStateConnected;
                    debug!("Connected to vTPM socket path : {:?}\n", socket_path);
                    return Ok(0);
                }
                Err(_e) => {}
            };
            sleep(Duration::from_millis(100));

            if now.elapsed().as_secs() >= 60 {
                break;
            }
        }
        Err(TPMSocError::TPMSocCannotConnect(anyhow!(
            "Failed to connect to vTPM Socket"
        )))
    }

    pub fn set_datafd(&mut self, fd: RawFd) {
        self.data_fd = fd;
    }

    pub fn set_msgfd(&mut self, fd: RawFd) {
        self.write_msgfd = fd;
    }

    pub fn sync_read(&self, buf: &mut [u8], _len: usize) -> Result<usize> {
        if self.state != SocDevState::SocDevStateConnected {
            return Ok(0);
        }
        debug!("synchronous read from vTPM Socket");
        let size = recv(self.ctrl_fd, buf, MsgFlags::empty()).map_err(|e| {
            TPMSocError::TPMSocFailedRead(anyhow!(
                "Failed to read from vTPM socket. Error Code {:?}",
                e
            ))
        })?;
        debug!("sync read completed");
        Ok(size as usize)
    }

    pub fn send_full(&self, buf: &mut [u8], _len: usize) -> Result<usize> {
        let iov = &[IoVec::from_slice(buf)];
        let write_fd = self.write_msgfd;
        let write_vec = &[write_fd];
        let cmsgs = &[ControlMessage::ScmRights(write_vec)];
        debug!("send full message");

        // Send Ancillary data, along with cmds and data
        let size = sendmsg(self.ctrl_fd, iov, cmsgs, MsgFlags::empty(), None).map_err(|e| {
            TPMSocError::TPMSocFailedWrite(anyhow!(
                "Failed to write to vTPM Socket. Error Code {:?}", e
            ))
        })?;
        Ok(size as usize)
    }

    pub fn write(&mut self, buf: &mut [u8], len:usize) -> Result<usize> {
        debug!("write initialized");

        if let Some(ref mut _sock) = self.stream {
               let res = match self.state {
                    SocDevState::SocDevStateConnected => {
                        warn!("State Connected");
                        let ret = self.send_full(buf, len)?;
                        // swtpm will receive data Fd after a successful send
                        // reset cached write_msgfd after a successful send
                        self.write_msgfd = 0;
                        ret
                    },
                    _ => return Err(TPMSocError::TPMSocFailedWrite(anyhow!(
                        "TPM Socket was not in Connected State"))),
            };
            debug!("write succeeded");

            Ok(res)
        } else {
            return Err(TPMSocError::TPMSocFailedWrite(anyhow!("Stream for TPM Socket was not initialized")))
        }
    }

    pub fn read(&mut self, buf: &mut [u8], _len: usize) -> Result<usize> {
        //Grab all response bytes so none is left behind
        debug!("read initialized");

        let mut newbuf: &mut [u8] = &mut [0; TPM_TIS_BUFFER_MAX];

        if let Some(ref mut sock) = self.stream {
            let size:usize = sock.read(&mut newbuf).map_err(|e| TPMSocError::TPMSocFailedRead(anyhow!(
                "Failed to read from vTPM Socket. Error Code {:?}",
                e
            )))?;
            byte_copy(&newbuf, buf);  //TODO: Replace with proper copy
            Ok(size)
        } else {
            return Err(TPMSocError::TPMSocFailedRead(anyhow!("Stream for TPM Socket was not initialized")))
        }
    }
}

/***
/// This is the backend seen by frontend
/// Actual Backend is SocketCharDev
pub struct CharBackend {
    pub chr: Option<SocketDev>,
    fe_open: bool,
}

impl CharBackend {
    pub fn new() -> Self {
        Self {
            chr: None,
            fe_open: false,
        }
    }

    pub fn chr_be_init(&mut self, path: String) -> Result<()> {
        let mut sockdev = SocketDev::new();
        let _ = sockdev.connect(&path)?;

        self.chr = Some(sockdev);
        self.fe_open = true;
        Ok(())
    }

    pub fn chr_be_set_msgfd(&mut self, fd: RawFd) -> Result<()> {
        if let Some(ref mut dev) = self.chr {
            dev.set_msgfd(fd);
            Ok(())
        } else {
            return Err(TPMSocError::TPMSocBackendConfigureFailed(anyhow!("SocketCharDev was not initialized")))
        }
    }

    pub fn chr_be_set_datafd(&mut self, fd: RawFd) -> Result<isize> {
        if let Some(ref mut dev) = self.chr {
            dev.set_datafd(fd);
            Ok(0)
        } else {
            return Err(TPMSocError::TPMSocBackendConfigureFailed(anyhow!("SocketCharDev was not initialized")))
        }
    }

    /**
     * chr_be_write_all:
     * @buf: the data
     * @len: the number of bytes to send
     *
     * Write data to a character backend from the front end.  This function will
     * send data from the front end to the back end.  Unlike @chr_fe_write,
     * this function will block if the back end cannot consume all of the data
     * attempted to be written.  This function is thread-safe.
     *
     * Returns: the number of bytes consumed (0 if no associated Chardev)
     */
    pub fn chr_be_write_all(&mut self, buf: &mut [u8], len: usize) -> Result<usize> {
        if let Some(ref mut dev) = self.chr {
            dev.write(buf, len)
        } else {
            return Err(TPMSocError::TPMSocBackendConfigureFailed(anyhow!("SocketCharDev was not initialized")))
        }
    }

    /**
     * chr_be_read_all:
     * @buf: the data buffer
     * @len: the number of bytes to read
     *
     * Read data to a buffer from the back end.
     *
     * Returns: the number of bytes read (0 if no associated Chardev)
     */
    pub fn chr_be_read_all(&mut self, mut buf: &mut [u8]) -> Result<usize> {
        if let Some(ref mut dev) = self.chr {
            let (s, _) = recvfrom(dev.ctrl_fd, &mut buf).map_err(|e| TPMSocError::TPMSocFailedRead(anyhow!(
                "Failed to read from vTPM Socket. Error Code {:?}",
                e
            )))?;
            //expect("char.rs: sync_read recvmsg error");
            Ok(s)
        } else {
            return Err(TPMSocError::TPMSocBackendConfigureFailed(anyhow!("SocketCharDev was not initialized")))
        }
    }
}
***/