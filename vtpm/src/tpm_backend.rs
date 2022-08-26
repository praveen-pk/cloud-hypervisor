extern crate nix;

use crate::socket::SocketDev;
use crate::tpm_ioctl::{Commands, MemberType, Ptm, PtmCap, PtmEst, PtmRes, PtmInit, PtmSetBufferSize};
use anyhow::anyhow;
use std::convert::TryInto;
use std::mem;
use std::os::unix::io::RawFd;
use std::path::Path;
use thiserror::Error;
use nix::sys::uio::IoVec;
use nix::sys::socket::{socketpair, AddressFamily, SockType, SockFlag, sendmsg, recvfrom, MsgFlags };


/*
use std::sync::{Arc, Mutex};
use std::io::Error as IOError;


use std::option::Option;
use nix::sys::uio::IoVec;
use nix::sys::socket::{socketpair, AddressFamily, SockType, SockFlag, sendmsg, recvfrom, MsgFlags };
type TPMBackendResult<T> = std::result::Result<T, std::io::Error>;
*/
const TPM_VERSION: u32 = 2;
const TPM_TIS_BUFFER_MAX: usize = 4096;
const TPM_REQ_HDR_SIZE: u32 = 10;
const TPM_RESP_HDR_SIZE: usize = 10;
const PTM_INIT_FLAG_DELETE_VOLATILE: u32 = 1 << 0;

/* capability flags returned by PTM_GET_CAPABILITY */
const PTM_CAP_INIT: u64 = 1;
const PTM_CAP_SHUTDOWN: u64 = 1 << 1;
const PTM_CAP_GET_TPMESTABLISHED: u64 = 1 << 2;
const PTM_CAP_SET_LOCALITY: u64 = 1 << 3;
const PTM_CAP_HASHING: u64 = 1 << 4;
const PTM_CAP_CANCEL_TPM_CMD: u64 = 1 << 5;
const PTM_CAP_STORE_VOLATILE: u64 = 1 << 6;
const PTM_CAP_RESET_TPMESTABLISHED: u64 = 1 << 7;
const PTM_CAP_GET_STATEBLOB: u64 = 1 << 8;
const PTM_CAP_SET_STATEBLOB: u64 = 1 << 9;
const PTM_CAP_STOP: u64 = 1 << 10;
const PTM_CAP_GET_CONFIG: u64 = 1 << 11;
const PTM_CAP_SET_DATAFD: u64 = 1 << 12;
const PTM_CAP_SET_BUFFERSIZE: u64 = 1 << 13;

///Check if the input command is selftest
///
pub fn tpm_util_is_selftest(input: Vec<u8>, in_len: u32) -> bool {
    if in_len >= TPM_REQ_HDR_SIZE {
        let ord: &[u8; 4] = input[6..6 + 4]
            .try_into()
            .expect("tpm_util_is_selftest: slice with incorrect length");
        return u32::from_ne_bytes(*ord).to_be() == 0x53;
    }
    false
}
#[derive(Error, Debug)]
pub enum TPMEmuError {
    #[error("Input socket path for TPM Emulator does not exist")]
    TPMSocketPathExists(),
    #[error("Could not initialize TPM Emulator Backend")]
    InitializeTPMEmulator(#[source] anyhow::Error),
    #[error("Failed to create data fd to pass to swtpm")]
    PrepareDataFd(#[source] anyhow::Error),
    #[error("Failed to run Control Cmd: {0}")]
    RunTPMCtrlCmd(#[source] anyhow::Error),
    #[error("TPM Emulator doesn't implement min required capabilities: {0}")]
    TPMCheckCaps(#[source] anyhow::Error),
}

type Result<T> = anyhow::Result<T, TPMEmuError>;

#[derive(Clone)]
pub struct TPMBackendCmd {
    pub locty: u8,
    pub input: Vec<u8>,
    pub input_len: u32,
    pub output: Vec<u8>,
    pub output_len: isize,
    pub selftest_done: bool,
}

pub struct TPMEmulator {
    had_startup_error: bool,
    cmd: Option<TPMBackendCmd>,
    version: u32, /* TPM specification version */
    caps: PtmCap, /* capabilities of the TPM */
    ctrl_soc: SocketDev,
    data_ioc: RawFd,
    cur_locty_number: u8, /* last set locality */
    //   mutex: Arc<Mutex<usize>>,
    established_flag_cached: u8,
    established_flag: u8,
}

impl TPMEmulator {
    /// Create TPMEmulator Instance
    ///
    /// # Arguments
    ///
    /// * `path` - A path to the Unix Domain Socket, swtpm is listening on
    ///
    pub fn new(path: String) -> Result<Self> {
        // tpm_emulator_handle_device_ops
        if !Path::new(&path).exists() {
            return Err(TPMEmuError::InitializeTPMEmulator(anyhow!(
                "The input TPM Socket path: {:?} does not exist",
                path
            )));
        }
        let mut tpmsoc = SocketDev::new();
        tpmsoc.init(path).map_err(|e| {
            TPMEmuError::InitializeTPMEmulator(anyhow!(
                "Failed while initializing TPM Emulator: {:?}",
                e
            ))
        })?;

        let mut tmpEmu = Self {
            had_startup_error: false,
            cmd: None,
            version: TPM_VERSION, // Only TPM2 available
            caps: 0,
            ctrl_soc: tpmsoc,
            data_ioc: -1,
            cur_locty_number: 255,
            //   mutex: Arc::new(Mutex::new(0)),
            established_flag_cached: 0,
            established_flag: 0,
        };

        tmpEmu.tpm_emulator_prepare_data_fd()?;

        tmpEmu.tpm_emulator_probe_caps()?;
        if !tmpEmu.tpm_emulator_check_caps() {
            tmpEmu.had_startup_error = true;
        }

        if !tmpEmu.get_tpm_established_flag() {
            tmpEmu.had_startup_error = true;
            // ERROR: tpm-emulator: Could not get the TPM established flag:
        }

        // res.debugsend();

        Ok(tmpEmu)
    }

    /// Create socketpair, assign one socket/FD as data_fd in TPM Socket
    /// The other socket/FD will be assigned to msg_fd, which will be sent to swtpm
    ///
    fn tpm_emulator_prepare_data_fd(&mut self) -> Result<()> {
        let mut res: PtmRes = 0;

        let (fd1, fd2) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .map_err(|e| {
            TPMEmuError::PrepareDataFd(anyhow!(
                "Failed to prepare data Fd for TPM Emulator: {:?}",
                e
            ))
        })?;

        self.ctrl_soc.set_msgfd(fd2);

        self.tpm_emulator_ctrlcmd(Commands::CmdSetDatafd, &mut res, 0, mem::size_of::<u32>())?;

        self.data_ioc = fd1;
        self.ctrl_soc.set_datafd(fd1);

        Ok(())
    }

    /// Gather TPM Capabilities and cache them in TPM Emulator
    ///
    fn tpm_emulator_probe_caps(&mut self) -> Result<()> {
        let mut caps = self.caps;
        self.tpm_emulator_ctrlcmd(
            Commands::CmdGetCapability,
            &mut caps,
            0,
            mem::size_of::<u64>(),
        )?;

        self.caps = u64::from_be(self.caps);
        Ok(())
    }

    ///
    /// # Arguments
    ///
    /// * `cmd` - A string slice that holds the name of the person
    ///
    fn tpm_emulator_ctrlcmd<'a>(
        &mut self,
        cmd: Commands,
        msg: &'a mut dyn Ptm,
        msg_len_in: usize,
        msg_len_out: usize,
    ) -> Result<()> {
        debug!("TPM Ctrl Cmd to send : {:?}", cmd);

        let cmd_no = (cmd as u32).to_be_bytes();
        let n: isize = (mem::size_of::<u32>() + msg_len_in) as isize;

        let converted_req = msg.convert_to_reqbytes();
        debug!("converted msg: {:?}", converted_req);

        //
        let mut buf = Vec::<u8>::with_capacity(n as usize);
        buf.extend(cmd_no);
        buf.extend(converted_req);
        debug!("Full TPM Control message {:?}", buf);

        let _res = self.ctrl_soc.write(&mut buf, n as usize).map_err(|e| {
            TPMEmuError::RunTPMCtrlCmd(anyhow!(
                "Failed while running {:?} TPM Ctrl Cmd. Error: {:?}",
                cmd,
                e
            ))
        })?;

        let mut output = [0 as u8; TPM_TIS_BUFFER_MAX];

        if msg_len_out != 0 {
            let _res = self
                .ctrl_soc
                .read(&mut output)
                .map_err(|e| TPMEmuError::RunTPMCtrlCmd(e.into()))?;
            msg.convert_to_ptm(&output);
        } else {
            msg.set_mem(MemberType::Response);
        }
        Ok(())
    }

    fn tpm_emulator_check_caps(&mut self) -> bool {
        let mut caps: PtmCap;

        /* min. required capabilities for TPM 2.0*/
        caps = PTM_CAP_INIT
            | PTM_CAP_SHUTDOWN
            | PTM_CAP_GET_TPMESTABLISHED
            | PTM_CAP_SET_LOCALITY
            | PTM_CAP_RESET_TPMESTABLISHED
            | PTM_CAP_SET_DATAFD
            | PTM_CAP_STOP
            | PTM_CAP_SET_BUFFERSIZE;

        if self.caps & caps != caps {
            return false;
        }
        true
    }

    pub fn get_tpm_established_flag(&mut self) -> bool {
        let mut est: PtmEst = PtmEst::new();

        if self.established_flag_cached == 1 {
            debug!("established_flag already cachedd");
            return self.established_flag == 1;
        }

        match self.tpm_emulator_ctrlcmd(
            Commands::CmdGetTpmEstablished,
            &mut est,
            0,
            2 * mem::size_of::<u32>(),
        ) {
            Err(e) => {
                error!("Unsuccessful ctrlcmd: CmdGetTpmEstablished: {:?}", e);
                return false;
            }
            Ok(_) => {}
        }

        self.established_flag_cached = 1;
        if est.resp.bit != 0 {
            return true;
        } else {
            return false;
        }
    }

    /// Function to write to emulator socket and read the response from it
    fn unix_tx_bufs(&mut self) -> isize {
        let mut is_selftest: bool = false;
        if let Some(ref mut cmd) = self.cmd {
            if cmd.selftest_done {
                cmd.selftest_done = false;
                let input = &cmd.input;
                is_selftest = tpm_util_is_selftest((input).to_vec(), cmd.input_len);
            }

            //qio_channel_write_all
            let iov = &[IoVec::from_slice(cmd.input.as_slice())];
            let ret = sendmsg(self.data_ioc, iov, &[], MsgFlags::empty(), None).expect("char.rs: ERROR ON send_full sendmsg") as isize;
            if ret <= 0 {
                return -1
            }

            //qio_channel_read_all
            let (size, sock) = recvfrom(self.data_ioc, &mut cmd.output).expect("unix_tx_bufs: sync_read recvmsg error");

            if is_selftest {
                let errcode: &[u8; 4] = cmd.output[6..6+4].try_into().expect("tpm_util_is_selftest: slice with incorrect length");
                cmd.selftest_done = u32::from_ne_bytes(*errcode).to_be() == 0;
            }
        }

        0
    }

    pub fn handle_request(&mut self) -> isize {
    // Skip setting Locy here, as CRB interface is being used
        if self.cmd.is_some() {
            if self.unix_tx_bufs() < 0 {
                return -1
            }
            return 0
        }
        -1
    }

    pub fn worker_thread(&mut self) -> isize {
        warn!("Worker Thread");
        let err = self.handle_request();
        if err < 0 {
            // error_report_err(err);
            return -1
        }
        self.tpm_backend_request_completed();
        0
    }
    pub fn deliver_request(&mut self, cmd: &TPMBackendCmd) -> (isize, Vec<u8>) {
        debug!("tpm_emualtor: Deliver Request");
        if self.cmd.is_none() {
            self.cmd = Some(cmd.clone());
            //self.cmd.replace(cmd.clone());

            let ret = self.worker_thread();
            let output = self.cmd.as_ref().unwrap().output.clone();
            self.tpm_backend_request_completed();
            return (ret, output)
        }
        (-1, vec![])
    }

    pub fn tpm_backend_request_completed(&mut self) {
        self.cmd = None;
    }

    pub fn cancel_cmd(&mut self) -> Result<()> {
        let mut res: PtmRes = 0;

        // If Emulator implements all caps
        if !((self.caps & (1 << 5)) == ((1 << 5))) {
                return Err(TPMEmuError::TPMCheckCaps(anyhow!(
                "Emulator does not implement Capabilities to Cancel Commands"
            )));
        }
        /* FIXME: make the function non-blocking, or it may block a VCPU */
        self.tpm_emulator_ctrlcmd(Commands::CmdCancelTpmCmd, &mut res, 0, mem::size_of::<u32>())?;
        Ok(())
    }

    fn tpm_emulator_set_buffer_size(&mut self, wantedsize: usize, actualsize: &mut usize) ->  Result<()> {
        let mut psbs: PtmSetBufferSize = PtmSetBufferSize::new();

        self.tpm_emulator_stop_tpm()?;

        psbs.req.buffersize = (wantedsize as u32).to_be();

        self.tpm_emulator_ctrlcmd(Commands::CmdSetBufferSize, &mut psbs, mem::size_of::<u32>(), 4*mem::size_of::<u32>())?;

        psbs.tpm_result = u32::from_be(psbs.tpm_result);
        //TODO: Handle this error case
        if psbs.tpm_result != 0 {
               error!("tpm-emulator: TPM result for set buffer size : 0x{:?}",
                               psbs.tpm_result);
        }

        debug!("buffersize: {}", psbs.resp.bufsize);

        *actualsize = psbs.resp.bufsize as usize;

        Ok(())
    }

    pub fn tpm_emulator_startup_tpm(&mut self, buffersize: usize) -> Result<()>{
        let mut init: PtmInit = PtmInit::new();

        let mut actual_size: usize = 0;

        //TODO: handle this error case
        //buffersize != 0 &&
        self.tpm_emulator_set_buffer_size(buffersize, &mut actual_size)?;

        self.tpm_emulator_ctrlcmd(Commands::CmdInit, &mut init, mem::size_of::<u32>(), mem::size_of::<u32>())?;

        //TODO: handle this error case
        /*if init.tpm_result != 0 {
            // error_report("tpm-emulator: TPM result for CMD_INIT: 0x%x %s", res,
            //          tpm_emulator_strerror(res));
            return -1
        }*/

        Ok(())
    }

    fn tpm_emulator_stop_tpm(&mut self) ->  Result<()> {
        let mut res: PtmRes = 0;

        self.tpm_emulator_ctrlcmd(Commands::CmdStop, &mut res, 0, mem::size_of::<u32>())?;

        res = u32::from_be(res);

        //TODO: Handle this error case
        /*if res != 0 {
            // error_report("tpm-emulator: TPM result for CMD_STOP: 0x%x %s", res,
            //          tpm_emulator_strerror(res));
            return -1;
        }*/

        Ok(())
    }
    pub fn get_buffer_size(&mut self) -> Result<usize> {
        let mut actual_size: usize = 0;

        match self.tpm_emulator_set_buffer_size(0, &mut actual_size){
            Err(e) =>  {
                return Ok(4906);
            }
            _ => {}
        }
        Ok(actual_size)
    }
}
