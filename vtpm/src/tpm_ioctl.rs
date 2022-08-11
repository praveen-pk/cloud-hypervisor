use anyhow::anyhow;
use byteorder::{BigEndian, ReadBytesExt};
use std::convert::TryInto;
use thiserror::Error;

/*
 * Commands used by the non-CUSE TPMs
 *
 * All messages contain big-endian data.
 *
 * The return messages only contain the 'resp'
 */
#[derive(Debug, Clone, Copy)]
pub enum Commands {
    CmdGetCapability = 1,
    CmdInit,                // 2
    CmdShutdown,            // 3
    CmdGetTpmEstablished,   // 4
    CmdSetLocality,         // 5
    CmdHashStart,           // 6
    CmdHashData,            // 7
    CmdHashEnd,             // 8
    CmdCancelTpmCmd,        // 9
    CmdStoreVolatile,       // 10
    CmdResetTpmEstablished, // 11
    CmdGetStateBlob,        // 12
    CmdSetStateBlob,        // 13
    CmdStop,                // 14
    CmdGetConfig,           // 15
    CmdSetDatafd,           // 16
    CmdSetBufferSize,       // 17
}

#[derive(Error, Debug)]
pub enum TPMIocError {
    #[error("Failed converting buf to ptm {0}")]
    TPMConvertToPtm(#[source] anyhow::Error),
}
type Result<T> = anyhow::Result<T, TPMIocError>;

#[derive(Debug)]
pub struct TPMReqHdr {
    tag: u16,
    len: u32,
    ordinal: u32,
}

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum MemberType {
    Request,
    Response,
    Error,
    Cap,
}

pub trait Ptm {
    /* Get which */
    fn get_mem(&self) -> MemberType;
    /* Convert to buffer with size of MAX(Req, Res) */
    fn convert_to_reqbytes(&self) -> Vec<u8>;
    fn convert_to_ptm(&mut self, buf: &[u8]) -> Result<()>;
    fn set_mem(&mut self, mem: MemberType);
    fn set_res(&mut self, res: u32);
}

/*
 * Every response from a command involving a TPM command execution must hold
 * the ptm_res as the first element.
 * ptm_res corresponds to the error code of a command executed by the TPM.
 */
pub type PtmRes = u32;

impl Ptm for PtmRes {
    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf
    }

    fn get_mem(&self) -> MemberType {
        MemberType::Error
    }

    fn convert_to_ptm(&mut self, buf: &[u8]) -> Result<()> {
        if buf.len() < 4 {
            return Err(TPMIocError::TPMConvertToPtm(anyhow!(
                "PtmRes buffer is of insufficient length. Buffer length should be atleast 4"
            )));
        }

        //let num_buf: &[u8; 4] = buf[0..4];
        //let num: &mut u32 = &mut u32::from_be_bytes(*num_buf);
        *self = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        Ok(())
    }

    fn set_mem(&mut self, _mem: MemberType) {}

    fn set_res(&mut self, _res: u32) {}
}

pub type PtmCap = u64;
impl Ptm for PtmCap {
    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf
    }

    fn get_mem(&self) -> MemberType {
        MemberType::Cap
    }

    fn convert_to_ptm(&mut self, mut buf: &[u8]) -> Result<()> {
        if buf.len() < 8 {
            return Err(TPMIocError::TPMConvertToPtm(anyhow!(
                "PtmCap buffer is of insufficient length. Buffer length should be atleast 8"
            )));
        }
        *self = buf.read_u64::<BigEndian>().unwrap();
        Ok(())
    }

    fn set_mem(&mut self, _mem: MemberType) {}

    fn set_res(&mut self, _res: u32) {}
}

/* PTM_GET_TPMESTABLISHED: get the establishment bit */
#[derive(Debug)]
pub struct PtmEstResp {
    pub bit: u8,
}

#[derive(Debug)]
pub struct PtmEst {
    mem: MemberType,
    pub resp: PtmEstResp,
    pub tpm_result: PtmRes,
}

impl PtmEst {
    pub fn new() -> Self {
        Self {
            mem: MemberType::Request,
            tpm_result: 0,
            resp: PtmEstResp {
                bit: 0,
            },
        }
    }
}

impl Ptm for PtmEst {
    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf
    }

    fn get_mem(&self) -> MemberType { self.mem }

    fn convert_to_ptm(&mut self, buf: &[u8]) -> Result<()>{
        if buf.len() < 5 {
            return Err(TPMIocError::TPMConvertToPtm(anyhow!(
                "PtmEst buffer is of insufficient length. Buffer length should be atleast 5"
            )));
        }
        self.set_mem(MemberType::Response);
        let mut res = &buf[0..4];
        self.set_res(res.read_u32::<BigEndian>().unwrap());
        let bit = &buf[4];
        self.resp.bit = *bit;
        Ok(())
    }

    fn set_mem(&mut self, mem:MemberType) { self.mem = mem }

    fn set_res(&mut self, res: u32) { self.tpm_result = res }
}

/* PTM_INIT */

#[derive(Debug)]
pub struct PtmInit {
    pub mem: MemberType,
    /* request */
    pub init_flags: u32,
    /* response */
    pub tpm_result: PtmRes,
}

impl PtmInit {
    pub fn new() -> Self {
        Self {
            mem: MemberType::Request,
            init_flags: 0,
            tpm_result: 0,
        }
    }
}

impl Ptm for PtmInit {
    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::<u8>::new();
        buf.extend_from_slice(&self.init_flags.to_be_bytes());
        buf
    }

    fn get_mem(&self) -> MemberType {self.mem}

    fn convert_to_ptm(&mut self, buf: &[u8]) -> Result<()>{

        if buf.len() < 4 {
            return Err(TPMIocError::TPMConvertToPtm(anyhow!(
                "PtmInit buffer is of insufficient length. Buffer length should be atleast 4"
            )));
        }
        self.set_mem(MemberType::Response);
        let mut res = &buf[0..4];
        self.set_res(res.read_u32::<BigEndian>().unwrap());

        Ok(())
    }

    fn set_mem(&mut self, mem:MemberType) { self.mem = mem }

    fn set_res(&mut self, res: u32) { self.tpm_result = res }
}

/*
 * PTM_SET_BUFFERSIZE: Set the buffer size to be used by the TPM.
 * A 0 on input queries for the current buffer size. Any other
 * number will try to set the buffer size. The returned number is
 * the buffer size that will be used, which can be larger than the
 * requested one, if it was below the minimum, or smaller than the
 * requested one, if it was above the maximum.
 */
#[derive(Debug)]
pub struct PtmSBSReq {
    pub buffersize: u32,
}

#[derive(Debug)]
pub struct PtmSBSResp {
    pub bufsize: u32,
    minsize: u32,
    maxsize: u32,
}

#[derive(Debug)]
pub struct PtmSetBufferSize{
    pub mem: MemberType,
    /* request */
    pub req: PtmSBSReq,
    /* response */
    pub resp: PtmSBSResp,
    pub tpm_result: PtmRes,
}

impl PtmSetBufferSize {
    pub fn new() -> Self {
        Self {
            mem: MemberType::Request,
            req: PtmSBSReq {buffersize:0},
            resp: PtmSBSResp {bufsize:0,minsize:0,maxsize:0},
            tpm_result: 0,
        }
    }
}

impl Ptm for PtmSetBufferSize {
    fn convert_to_reqbytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::<u8>::new();
        buf.extend_from_slice(&self.req.buffersize.to_be_bytes());
        buf
    }

    fn get_mem(&self) -> MemberType {self.mem}

    fn convert_to_ptm(&mut self, buf: &[u8]) ->  Result<()> {

        if buf.len() < 16 {
            return Err(TPMIocError::TPMConvertToPtm(anyhow!(
                "PtmSetBufferSize buffer is of insufficient length. Buffer length should be atleast 16"
            )));
        }
        self.set_mem(MemberType::Response);
        let mut res = &buf[0..4];
        self.set_res(res.read_u32::<BigEndian>().unwrap());

        let mut bufsize = &buf[4..8];
        self.resp.bufsize = bufsize.read_u32::<BigEndian>().unwrap();

        let mut minsize = &buf[8..12];
        self.resp.minsize = minsize.read_u32::<BigEndian>().unwrap();

        let mut maxsize = &buf[12..16];
        self.resp.maxsize = maxsize.read_u32::<BigEndian>().unwrap();

        Ok(())
    }

    fn set_mem(&mut self, mem:MemberType) { self.mem = mem }

    fn set_res(&mut self, res: u32) { self.tpm_result = res }
}