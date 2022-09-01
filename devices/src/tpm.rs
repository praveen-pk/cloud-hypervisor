use phf::{phf_map};
use anyhow::anyhow;
use thiserror::Error;
use vtpm::tpm_backend::{TPMBackendCmd, TPMEmulator};
use vm_device::BusDevice;
//use core::slice::SlicePattern;
use std::ops::Deref;
use std::sync::{Arc, Barrier};
use std::cmp;



#[derive(Error, Debug)]
pub enum TPMError {
    #[error("TPM Emulator doesn't implement min required capabilities: {0}")]
    TPMCheckCaps(#[source] anyhow::Error),
    #[error("TPM Emulator doesn't implement min required capabilities: {0}")]
    TPMInit(#[source] anyhow::Error),
}
type Result<T> = anyhow::Result<T, TPMError>;



/* crb 32-bit registers */
const CRB_LOC_STATE:u32 = 0x0;
//Register Fields
// Field => (start, length)
// start: lowest bit in the bit field numbered from 0
// length: length of the bit field
const CRB_LOC_STATE_FIELDS:phf::Map<&str,[u32;2]> = phf_map! {
    "tpmEstablished" => [0, 1],
    "locAssigned" => [1,1],
    "activeLocality"=> [2, 3],
    "reserved" => [5, 2],
    "tpmRegValidSts" => [7, 1]
};
const CRB_LOC_CTRL:u32 = 0x08;
const CRB_LOC_CTRL_REQUEST_ACCESS:u32 = 1<<0;
const CRB_LOC_CTRL_RELINQUISH:u32 = 1<<1;
const CRB_LOC_CTRL_SEIZE:u32 = 1<<2;
const CRB_LOC_CTRL_RESET_ESTABLISHMENT_BIT:u32 = 1<<3;
const CRB_LOC_STS: u32 = 0x0C;
const CRB_LOC_STS_FIELDS:phf::Map<&str,[u32;2]> = phf_map! {
    "Granted" => [0, 1],
    "beenSeized" => [1,1]
};
const CRB_INTF_ID:u32 = 0x30;
const CRB_INTF_ID_FIELDS:phf::Map<&str,[u32;2]> = phf_map! {
    "InterfaceType" => [0, 4],
    "InterfaceVersion" => [4, 4],
    "CapLocality" =>  [8, 1],
    "CapCRBIdleBypass" => [9, 1],
    "Reserved1" => [10, 1],
    "CapDataXferSizeSupport" => [11, 2],
    "CapFIFO" =>  [13, 1],
    "CapCRB" => [14, 1],
    "CapIFRes" => [15, 2],
    "InterfaceSelector" => [17, 2],
    "IntfSelLock" =>  [19, 1],
    "Reserved2" => [20, 4],
    "RID" => [24, 8]
};
const CRB_INTF_ID2:u32 = 0x34;
const CRB_INTF_ID2_FIELDS:phf::Map<&str,[u32;2]> = phf_map! {
    "VID" => [0, 16],
    "DID" => [16, 16]
};
const CRB_CTRL_EXT:u32 = 0x38;
const CRB_CTRL_REQ:u32 = 0x40;
const CRB_CTRL_REQ_CMD_READY:u32 = 1<<0;
const CRB_CTRL_REQ_GO_IDLE:u32 = 1<<1;
const CRB_CTRL_STS:u32 = 0x44;
const CRB_CTRL_STS_FIELDS:phf::Map<&str,[u32;2]> = phf_map! {
    "tpmSts" => [0, 1],
    "tpmIdle" => [1, 1]
};
const CRB_CTRL_CANCEL:u32 = 0x48;
const CRB_CANCEL_INVOKE:u32 = 1 << 0;
const CRB_CTRL_START:u32 = 0x4C;
const CRB_START_INVOKE:u32 = 1 << 0;
const CRB_INT_ENABLED:u32 = 0x50;
const CRB_INT_STS:u32 = 0x54;
//const CRB_CTRL_CMD_SIZE:u32 = 0x58;
const CRB_CTRL_CMD_LADDR:u32 = 0x5C;
const CRB_CTRL_CMD_HADDR:u32 = 0x60;
const CRB_CTRL_RSP_SIZE:u32 = 0x64;
const CRB_CTRL_RSP_ADDR:u32 = 0x68;
const CRB_DATA_BUFFER:u32 = 0x80;

const TPM_CRB_NO_LOCALITY:u32 = 0xff;

//TODO: this value is duplicated.
const TPM_CRB_ADDR_BASE:u32 = 0xFED40000;
const TPM_CRB_ADDR_SIZE:u32 = 0x1000;

const TPM_CRB_ADDR_CTRL:u32 =TPM_CRB_ADDR_BASE + CRB_CTRL_REQ;
const TPM_CRB_R_MAX:u32 = CRB_DATA_BUFFER;

// CRB Protocol details
const CRB_INTF_TYPE_CRB_ACTIVE:u32 = 0b1;
const CRB_INTF_VERSION_CRB:u32 = 0b1;
const CRB_INTF_CAP_LOCALITY_0_ONLY:u32 = 0b0;
const CRB_INTF_CAP_IDLE_FAST:u32 = 0b0;
const CRB_INTF_CAP_XFER_SIZE_64:u32 = 0b11;
const CRB_INTF_CAP_FIFO_NOT_SUPPORTED:u32 = 0b0;
const CRB_INTF_CAP_CRB_SUPPORTED:u32 = 0b1;
const CRB_INTF_IF_SELECTOR_CRB:u32 = 0b1;
const PCI_VENDOR_ID_IBM:u32 = 0x1014;
const CRB_CTRL_CMD_SIZE_REG:u32 = 0x58;
const CRB_CTRL_CMD_SIZE:u32 = TPM_CRB_ADDR_SIZE - CRB_DATA_BUFFER;


fn get_fields_map(reg:u32) -> phf::Map<&'static str,[u32;2]> {
    match reg {
        CRB_LOC_STATE => {return CRB_LOC_STATE_FIELDS;},
        CRB_LOC_STS => {return CRB_LOC_STS_FIELDS;},
        CRB_INTF_ID => {return CRB_INTF_ID_FIELDS;},
        CRB_INTF_ID2 => {return CRB_INTF_ID2_FIELDS;},
        CRB_CTRL_STS => {return CRB_CTRL_STS_FIELDS;}
        _ => {panic!("Unknown Register Fields in TPM were accessed")}
    };
}

/// Set a particular field in a Register
fn set_reg_field(regs:&mut [u32;TPM_CRB_R_MAX as usize], reg:u32, field:&str, value:u32) {
    let reg_fields = get_fields_map(reg);
    if reg_fields.contains_key(field){
        let start = reg_fields.get(field).unwrap()[0];
        let len = reg_fields.get(field).unwrap()[1];
        let mask =  (!(0 as u32) >> (32 - len)) << start;
        regs[reg as usize] = (regs[reg as usize] & !mask ) | ((value << start) & mask);
    }
    else{
        error!("Failed while updating TPM Register. {:?} is not a valid field in Reg {:#X}",field,reg)
    }
}

/// Get the value of a particular field in a Register
fn get_reg_field(regs:&[u32;TPM_CRB_R_MAX as usize], reg:u32, field:&str,) -> u32{
    let reg_fields = get_fields_map(reg);
    if reg_fields.contains_key(field){
        let start = reg_fields.get(field).unwrap()[0];
        let len = reg_fields.get(field).unwrap()[1];
        let mask =  (!(0 as u32) >> (32 - len)) << start;
        return (regs[reg as usize] & mask) >>start ;
    }
    else{
        // TODO: Sensible return value if fields do not exist
        return 0x0;
    }
}

/* Helper Functions */
fn tpm_locality_from_addr(addr: u32) -> u8 {
    (addr >> 12) as u8
}


fn u8_arr_to_u32(data: [u8;4]) ->u32{
    u32::from_le_bytes(data)
}
/// Return an u8 array of length len
fn u32_to_u8_arr(data: u32) ->[u8;4]{
        return unsafe{std::mem::transmute::<u32,[u8; 4]>(data)};
    }



pub struct TPM {
    emulator: TPMEmulator,
    cmd: Option<TPMBackendCmd>,
    regs: [u32;TPM_CRB_R_MAX as usize],
    be_buffer_size: usize,
    ppi_enabled: bool,
    data_buff: [u8;CRB_CTRL_CMD_SIZE as usize],
    data_buff_len: usize
}

impl TPM {
    pub  fn new(path: String) -> Result<Self> {
    let tpm_emu =  TPMEmulator::new(path).map_err(|e| {
        TPMError::TPMInit(anyhow!(
            "Failed while initializing TPM Emulator: {:?}",
            e
        ))
    })?;
    let mut tpm = TPM{
            emulator: tpm_emu,
            cmd: None,
            regs: [0;TPM_CRB_R_MAX as usize],
            be_buffer_size: CRB_CTRL_CMD_SIZE as usize,
            ppi_enabled: false,
            data_buff: [0;CRB_CTRL_CMD_SIZE as usize],
            data_buff_len: 0
        };
        tpm.reset();
        Ok(tpm)
    }
    fn tpm_get_active_locty(&mut self) -> u32{
        if get_reg_field(&self.regs, CRB_LOC_STATE, "locAssigned") == 0 {
            return TPM_CRB_NO_LOCALITY;
        }
        let locty =  get_reg_field (&self.regs, CRB_LOC_STATE, "activeLocality");
        warn!("PPK: Active locty returned = {:?}", locty);
        return locty;
    }

    fn tpm_request_completed(&mut self,result: isize){

        self.regs[CRB_CTRL_START as usize] = !CRB_START_INVOKE;
        if result != 0 {
            set_reg_field(&mut self.regs, CRB_CTRL_STS, "tpmSts", 1);
        }
    }
    fn reset (&mut self) {

        let curr_buff_size = self.emulator.get_buffer_size().unwrap();
    //TODO: Reset TPM Emulator here
    //        tpm_backend_reset(s->tpmbe);
        self.regs = [0;TPM_CRB_R_MAX as usize];
        set_reg_field(&mut self.regs, CRB_LOC_STATE, "tpmRegValidSts", 1);
        set_reg_field(&mut self.regs, CRB_CTRL_STS, "tpmIdle", 1);
        set_reg_field(&mut self.regs, CRB_INTF_ID, "InterfaceType", CRB_INTF_TYPE_CRB_ACTIVE);
        set_reg_field(&mut self.regs, CRB_INTF_ID,"InterfaceVersion", CRB_INTF_VERSION_CRB);
        set_reg_field(&mut self.regs, CRB_INTF_ID,"CapLocality", CRB_INTF_CAP_LOCALITY_0_ONLY);
        set_reg_field(&mut self.regs, CRB_INTF_ID, "CapCRBIdleBypass", CRB_INTF_CAP_IDLE_FAST);
        set_reg_field(&mut self.regs, CRB_INTF_ID, "CapDataXferSizeSupport", CRB_INTF_CAP_XFER_SIZE_64);
        set_reg_field(&mut self.regs, CRB_INTF_ID,"CapFIFO", CRB_INTF_CAP_FIFO_NOT_SUPPORTED);
        set_reg_field(&mut self.regs, CRB_INTF_ID, "CapCRB", CRB_INTF_CAP_CRB_SUPPORTED);
        set_reg_field(&mut self.regs, CRB_INTF_ID,"InterfaceSelector", CRB_INTF_IF_SELECTOR_CRB);
        set_reg_field(&mut self.regs, CRB_INTF_ID, "RID", 0b0000);
        set_reg_field(&mut self.regs, CRB_INTF_ID2,"VID", PCI_VENDOR_ID_IBM);

        self.regs[CRB_CTRL_CMD_SIZE_REG as usize] = CRB_CTRL_CMD_SIZE;
        self.regs[CRB_CTRL_CMD_LADDR as usize] = TPM_CRB_ADDR_BASE + CRB_DATA_BUFFER;
        self.regs[CRB_CTRL_RSP_SIZE as usize] = CRB_CTRL_CMD_SIZE;
        self.regs[CRB_CTRL_RSP_ADDR as usize] = TPM_CRB_ADDR_BASE + CRB_DATA_BUFFER;

        self.be_buffer_size = cmp::min(curr_buff_size, CRB_CTRL_CMD_SIZE as usize);

        self.emulator.tpm_emulator_startup_tpm(self.be_buffer_size);
    }
}

//impl BusDevice for TPM
impl BusDevice for TPM {

    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]){
        let addr:u64 = base + offset;
        let mut offset:u32 = offset as u32;
        let data_len:usize = data.len();

        if offset >= CRB_DATA_BUFFER && offset <=CRB_DATA_BUFFER + (CRB_CTRL_CMD_SIZE as u32) {
            let start:usize = (offset as usize) - (CRB_DATA_BUFFER as usize);
            let end:usize = start + data.len();
            let len = data.len();
            data[0..len].clone_from_slice(&self.data_buff[start..end]);
        }
        else {
            offset = offset & 0xff;
            let mut val = self.regs[offset as usize];

            match offset {
                CRB_LOC_STATE => {
                    if !self.emulator.get_tpm_established_flag() {
                        val = val | 0x1;
                    }
                },
                _ => {}
            };
            if data.len() <= 4 {
                //Individual Registers are of size 4 Bytes.
                /*for (byte, read) in data.iter_mut().zip(<u32>::to_le_bytes(val).iter().cloned()) {
                    *byte = read as u8;
                }*/
                data.clone_from_slice(u32_to_u8_arr(val)[0..data_len].as_ref());
                /*let mut data_arr:[u8;4]=[0;4];
                data_arr[0..data.len()].copy_from_slice(data);
                val = u8_arr_to_u32(data_arr);*/
                debug!("mmio.read completed: offset: {:#X}, data: {:?}, val = {:#X}", offset, data, val);

            } else {
                error!(
                    "Invalid TPM read: offset {:#X}, data length {:?}",
                    offset,
                    data.len()
                );
            }
        }
        warn!("TPM MMIO Read: offset {:#X} len {:?} val = {:02X?}  ", offset, data.len(), data);

        //for i in 0..data.len(){
        //    warn!("data at offset {:?} = {:#X}",i,data[i]);
        //}
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        warn!("TPM MMIO Write1: offset {:#X} len {:?} data {:?}", offset, data.len(), data);
        //let addr: u64 = base + offset;
        let mut offset:u32 = offset as u32;
        if offset < CRB_DATA_BUFFER{
            offset = offset & 0xff;
        }
        let locty = tpm_locality_from_addr(offset) as u32;
        let size = data.len();

        // This is from TPM TIS
        // TODO: Confirm if this applies to CRB interface as well
        if size > 4 &&  offset < CRB_DATA_BUFFER {
            warn!(
                "Invalid TPM write: offset {}, data length {}",
                offset,
                data.len()
            );
            return None;
        }

        let mut data_arr:[u8;4]=[0;4];
        data_arr[0..data.len()].copy_from_slice(data);
        let v = u8_arr_to_u32(data_arr);
        /*let v = {
            let mut array = [0u8;4];
            for (byte, read) in array.iter_mut().zip(data.iter().cloned()) {
                *byte = read as u8;
            }
            u32::from_le_bytes(array)
        };*/
        warn!("TPM MMIO Write2: value {:#X}", v);

        //let mask: u32 = if size == 1 { 0xff } else { if size == 2 { 0xffff } else { !0 } };
        //debug!("Mask value during Write: {}", mask);

        match offset {
            CRB_CTRL_CMD_SIZE_REG => {
                self.regs[CRB_CTRL_CMD_SIZE_REG as usize] = v;
                return None
            },
            CRB_CTRL_CMD_LADDR => {
                self.regs[CRB_CTRL_CMD_LADDR as usize] = v;
                return None
            },
            CRB_CTRL_CMD_HADDR => {
                self.regs[CRB_CTRL_CMD_HADDR as usize] = v;
                return None
            },
            CRB_CTRL_RSP_SIZE =>{
                self.regs[CRB_CTRL_RSP_SIZE as usize] = v;
            },
            CRB_CTRL_RSP_ADDR =>{
                self.regs[CRB_CTRL_RSP_ADDR as usize] = v;
            },
            CRB_CTRL_REQ => {
                match v {
                    CRB_CTRL_REQ_CMD_READY => {
                        set_reg_field(&mut self.regs, CRB_CTRL_STS, "tpmIdle", 0);
                        return None
                    }
                    CRB_CTRL_REQ_GO_IDLE => {
                        set_reg_field(&mut self.regs, CRB_CTRL_STS, "tpmIdle", 1);
                        return None
                    }
                    _ => {
                        error!("Invalid value passed to CRTL_REQ register");
                        return None
                    }
                }
            },
            CRB_CTRL_CANCEL => {
                if v == CRB_CANCEL_INVOKE &&
                    (self.regs[CRB_CTRL_START as usize] & CRB_START_INVOKE != 0) {
                        self.emulator.cancel_cmd();
                    }
            },
            CRB_CTRL_START =>{
                let start_reg = self.regs[CRB_CTRL_START as usize];
                warn!("PPK:write CRB_CTRL_START v = {:#X}  {:#X} locty = {:?} , act_locty = {:?}", v,start_reg, locty,self.tpm_get_active_locty() );
                if (v == CRB_START_INVOKE &&
                    ((self.regs[CRB_CTRL_START as usize] & CRB_START_INVOKE) == 0) &&
                    self.tpm_get_active_locty() == locty) {
                   // warn!("CTRL_START with buffer {:?}",self.data_buff);

                    self.regs[CRB_CTRL_START as usize] |= CRB_START_INVOKE;
                    //TODO: Store the input Length to send
                    self.cmd = Some(TPMBackendCmd{
                        locty: locty as u8,
                        input: self.data_buff[0..self.data_buff_len].to_vec(),
                        input_len: cmp::min(self.data_buff_len as u32, CRB_CTRL_CMD_SIZE),
                        output: self.data_buff.to_vec(),   // initialize zeroed vector with full length. len is used while reading output with recvfrom
                        output_len: CRB_CTRL_CMD_SIZE as isize,
                        selftest_done: false,
                    });
                    let mut cmd = self.cmd.as_ref().unwrap().clone();
                    let (ret,output) = self.emulator.deliver_request(&mut cmd);
                    warn!("PPK cmd.output after deliver_request = {:?}",cmd.output);
                    self.data_buff.fill(0);
                    self.data_buff.clone_from_slice(output.as_slice());
                  //  warn!("data_buff returnd by CTRL_START = {:?}",self.data_buff);
                    self.tpm_request_completed(ret);
                }
            },
            CRB_LOC_CTRL => {
                warn!("CRB_LOC_CTRL  locty to write = {:?} val = {:?}",locty, v);
                match v {
                    CRB_LOC_CTRL_RESET_ESTABLISHMENT_BIT => {
                        return None;
                    },
                    CRB_LOC_CTRL_RELINQUISH => {
                        set_reg_field(&mut self.regs, CRB_LOC_STATE, "locAssigned", 0);
                        set_reg_field(&mut self.regs, CRB_LOC_STS, "Granted", 0);
                    },
                    CRB_LOC_CTRL_REQUEST_ACCESS => {
                        set_reg_field(&mut self.regs, CRB_LOC_STS, "Granted", 1);
                        set_reg_field(&mut self.regs, CRB_LOC_STS, "beenSeized", 0);
                        set_reg_field(&mut self.regs, CRB_LOC_STATE, "locAssigned", 1);
                    }
                    _ => {error!("Invalid value to write in CRB_LOC_CTRL {:#X} ", v);}
                }

            },
            _ => {
                if offset < CRB_DATA_BUFFER  || offset >= (CRB_DATA_BUFFER + (CRB_CTRL_CMD_SIZE))  {
                    error!("Invalid Offset: {:#X} during write to TPM", offset);
                    return None;
                }
                //TODO: Like Qemu, assign a subregion of memory and handle writes directly
                //Store the data to a local object and pass it to start when needed
                let start:usize = (offset as usize) - (CRB_DATA_BUFFER as usize);
                if start == 0 {
                    // If filling data_buff at index 0, reset length to 0
                    self.data_buff_len = 0;
                    self.data_buff.fill(0);
                }
                let end:usize = start + data.len();
                self.data_buff[start..end].clone_from_slice(data);
                self.data_buff_len += data.len();
               // warn!("Data Buffer after write {:02X?}",self.data_buff);
            }

        }
        return None

    }
}



pub(crate) mod tests {
    use super::*;

    #[test]
    fn test_set_get_reg_field() {
        let mut regs: [u32;TPM_CRB_R_MAX as usize] = [0;TPM_CRB_R_MAX as usize];
        set_reg_field(&mut regs, CRB_INTF_ID, "RID", 0xAC);
        assert_eq!(get_reg_field(&regs, CRB_INTF_ID, "RID"), 0xAC,
            concat!("Test: ", stringify!(set_reg_field))
        );
    }
}
