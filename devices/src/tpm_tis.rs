use byteorder::{ByteOrder, LittleEndian};
use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Barrier};
use std::{io, result};
use versionize::{VersionMap, Versionize, VersionizeResult};
use vm_device::interrupt::InterruptSourceGroup;
use vm_device::BusDevice;
use std::io::Write;
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable, VersionMapped,
};
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, LegacyIrqGroupConfig, MsiIrqGroupConfig,
};
use std::cmp;
use std::convert::TryInto;
use vtpm::tpm_backend::{TPMVersion, TPMType, TPMBackendCmd, TPMEmulator, TPMBackend,};
use std::{thread, time};


/* Costants */
const TPM_TIS_NUM_LOCALITIES: u8 = 5;
const TPM_TIS_BUFFER_MAX: u32 = 4096;
const TPM_TIS_NO_LOCALITY: u8 = 255;
const TPM_TIS_ACCESS_TPM_REG_VALID_STS: u32 = 1 << 7;
const TPM_TIS_STS_TPM_FAMILY2_0: u32 = 1 << 26;
const TPM_TIS_IFACE_ID_SUPPORTED_FLAGS2_0: u32 = (0x0) | (0 << 4) | (1 << 8) | (1 << 13);
const TPM_TIS_INT_POLARITY_LOW_LEVEL: u32 = 1 << 3;
const TPM_TIS_ACCESS_SEIZE: u8 = 1 << 3;
const TPM_TIS_ACCESS_PENDING_REQUEST: u32 = 1 << 2;
const TPM_TIS_CAPABILITIES_SUPPORTED2_0: u32 = (1 << 4) | (0 << 8) | (3 << 9) | (3 << 28) | ((1 << 2) | (1 << 0) | (1 << 1) | (1 << 7));
const TPM_TIS_STS_DATA_AVAILABLE: u32 = 1 << 4;
const TPM_TIS_NO_DATA_BYTE: u32 = 0xff;
const TPM_TIS_TPM_DID: u32 = 0x0001;
const TPM_TIS_TPM_VID: u32 = 0x1014;
const TPM_TIS_TPM_RID: u32 = 0x0001;
const TPM_TIS_LOCALITY_SHIFT: u32 = 12;
const TPM_TIS_ACCESS_REQUEST_USE: u8 = 1 << 1;
const TPM_TIS_ACCESS_ACTIVE_LOCALITY: u8 = 1 << 5;
const TPM_TIS_ACCESS_BEEN_SEIZED: u32 = 1 << 4;
const TPM_TIS_INT_ENABLED: u32 = 1 << 31;
const TPM_TIS_INT_POLARITY_MASK: u32 = 3 << 3;
const TPM_TIS_INTERRUPTS_SUPPORTED: u32 = (1 << 2) | (1 << 0) | (1 << 1) | (1 << 7);
const TPM_TIS_STS_VALID: u32 = 1 << 7;
const TPM_TIS_INT_STS_VALID: u32 = 1 << 1;
const TPM_TIS_STS_SELFTEST_DONE: u32 = 1 << 2;
const TPM_TIS_STS_TPM_FAMILY_MASK: u32 = 0x3 << 26;
const TPM_TIS_STS_COMMAND_READY: u32 = 1 << 6;
const TPM_TIS_INT_DATA_AVAILABLE: u32 = 1 << 0;
const TPM_TIS_INT_LOCALITY_CHANGED: u32 = 1 << 2;
const TPM_TIS_INT_COMMAND_READY: u32 = 1 << 7;
const TPM_TIS_STS_COMMAND_CANCEL: u32 = 1 << 24;
const TPM_TIS_STS_RESET_ESTABLISHMENT_BIT: u32 = 1 << 25;
const TPM_TIS_STS_TPM_GO: u32 = 1 << 5;
const TPM_TIS_STS_RESPONSE_RETRY: u32 = 1 << 1;
const TPM_TIS_STS_EXPECT: u32 = 1 << 3;
const TPM_TIS_IFACE_ID_INT_SEL_LOCK: u32 = 1 << 19;

/* tis registers */
const TPM_TIS_REG_ACCESS: u64 = 0x00;
const TPM_TIS_REG_INT_ENABLE: u64 = 0x08;
const TPM_TIS_REG_INT_VECTOR: u64 = 0x0c;
const TPM_TIS_REG_INT_STATUS: u64 = 0x10;
const TPM_TIS_REG_INTF_CAPABILITY: u64 = 0x14;
const TPM_TIS_REG_STS: u64 = 0x18;
const TPM_TIS_REG_DATA_FIFO: u64 = 0x24;
const TPM_TIS_REG_INTERFACE_ID: u64 = 0x30;
const TPM_TIS_REG_DATA_XFIFO: u64 = 0x80;
const TPM_TIS_REG_DATA_XFIFO_END:u64 = 0xbc;
const TPM_TIS_REG_DID_VID: u64 = 0xf00;
const TPM_TIS_REG_RID: u64 = 0xf04;

/* Helper Functions */
fn tpm_tis_locality_from_addr(addr: u64) -> u8 {
    ((addr >> TPM_TIS_LOCALITY_SHIFT) & 0x7) as u8
}

#[derive(Debug)]
pub enum Error {
    BadWriteOffset(u64),
    DmaNotImplemented,
    InterruptFailure(io::Error),
    WriteAllFailure(io::Error),
    FlushFailure(io::Error),
    TPMBackendFailure,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::BadWriteOffset(offset) => write!(f, "tpm_tis_write: Bad Write Offset: {}", offset),
            Error::DmaNotImplemented => write!(f, "tpm_tis: DMA not implemented."),
            Error::InterruptFailure(e) => write!(f, "Failed to trigger interrupt: {}", e),
            Error::WriteAllFailure(e) => write!(f, "Failed to write: {}", e),
            Error::FlushFailure(e) => write!(f, "Failed to flush: {}", e),
            Error::TPMBackendFailure => write!(f, "tpm_tis: TPM Backend failed to start.")
        }
    }
}

type Result<T> = result::Result<T, Error>;

/* TPM Device Structs */
#[derive(PartialEq, Debug)]
enum TPMTISState {
    TpmTisStateIdle,
    TpmTisStateReady,
    TpmTisStateCompletion,
    TpmTisStateExecution,
    TpmTisStateReception,
}

impl Clone for TPMTISState {
    fn clone(&self) -> Self {
        match self {
            TPMTISState::TpmTisStateIdle => TPMTISState::TpmTisStateIdle,
            TPMTISState::TpmTisStateReady => TPMTISState::TpmTisStateReady,
            TPMTISState::TpmTisStateCompletion => TPMTISState::TpmTisStateCompletion,
            TPMTISState::TpmTisStateExecution => TPMTISState::TpmTisStateExecution,
            TPMTISState::TpmTisStateReception => TPMTISState::TpmTisStateReception,
        }
    }
}

#[derive(Debug)]
pub struct TPMLocality {
    state: TPMTISState,
    access: u8,
    sts: u32,
    iface_id: u32,
    inte: u32,
    ints: u32,
}

impl Clone for TPMLocality {
    fn clone(&self) -> Self {
        TPMLocality {
            state: self.state.clone(),
            access: self.access.clone(),
            sts: self.sts.clone(),
            iface_id: self.iface_id.clone(),
            inte: self.inte.clone(),
            ints: self.ints.clone(),
        }
    }
}

pub struct TPMState {
    buffer: Vec<u8>,
    rw_offset: u16,
    active_locty: u8,
    aborting_locty: u8,
    next_locty: u8,
    locs: Vec<TPMLocality>,
}

/// TPM Device
pub struct TPMIsa {
    buffer: Vec<u8>,
    rw_offset: u16,
    active_locty: u8,
    aborting_locty: u8,
    next_locty: u8,
    cmd: Option<TPMBackendCmd>,
    locs: Vec<TPMLocality>,
    be_buffer_size: usize,
    be_driver: TPMBackend,
    be_tpm_version: TPMVersion,
    count: usize,
    irq_num: InterruptIndex,
    irq: Arc<dyn InterruptSourceGroup>,
    startup_invoked: bool,
    // out: Option<Box<dyn io::Write + Send>>,
}

impl VersionMapped for TPMState {}

impl TPMIsa {
    pub fn new(
        irq: Arc<dyn InterruptSourceGroup>,
        irq_num: InterruptIndex,
        // out: Option<Box<dyn io::Write + Send>>,
    ) -> Self {
        let mut locs = Vec::with_capacity(TPM_TIS_NUM_LOCALITIES as usize);
        for _ in 0..TPM_TIS_NUM_LOCALITIES {
            locs.push(TPMLocality {
                state: TPMTISState::TpmTisStateIdle,
                access: TPM_TIS_ACCESS_TPM_REG_VALID_STS as u8,
                sts: TPM_TIS_STS_TPM_FAMILY2_0,
                iface_id: TPM_TIS_IFACE_ID_SUPPORTED_FLAGS2_0,
                inte: TPM_TIS_INT_POLARITY_LOW_LEVEL,
                ints: 0,
            });
        }
        let mut be_driver = TPMBackend::new();
        warn!("Backend Buffer Size: {}", be_driver.get_buffer_size());
        let be_buffer_size = cmp::min(be_driver.get_buffer_size(), TPM_TIS_BUFFER_MAX as usize);
        warn!("Min: {}", be_buffer_size);

        if be_driver.startup_tpm(be_buffer_size) < 0 {
            // Handle Backend failed to startup
        }
        warn!("IRQ: {}", irq_num);

        Self {
            buffer: Vec::<u8>::with_capacity(4096), //IMPLEMENT
            rw_offset: 0,
            active_locty: TPM_TIS_NO_LOCALITY,
            aborting_locty: TPM_TIS_NO_LOCALITY,
            next_locty: TPM_TIS_NO_LOCALITY,
            cmd: None,
            be_buffer_size,
            be_driver,
            count: 0,
            /* TPM 2 only supported for now. This value should be modified for other versions of TPM */
            be_tpm_version: TPMVersion::TpmVersionTwo,
            locs,
            irq_num,
            irq,
            startup_invoked: false,
        }
    }

    fn get_state(&self) -> TPMState {
        TPMState {
            buffer: self.buffer.clone().into(),
            rw_offset: self.rw_offset,
            active_locty: self.active_locty,
            aborting_locty: self.aborting_locty,
            next_locty: self.next_locty,
            locs: self.locs.clone().into(),
        }
    }

    fn set_state(&mut self, state: &TPMState) {
        self.buffer = state.buffer.clone().into();
        self.rw_offset = state.rw_offset;
        self.active_locty = state.active_locty;
        self.aborting_locty = state.aborting_locty;
        self.next_locty = state.next_locty;
        self.locs = state.locs.clone().into();
    }
    fn set_startup_invoked(&mut self) {
        self.startup_invoked = true;
    }
    fn startup_invoked(mut self) -> bool {
        self.startup_invoked
    }

    fn invoke_startup(&self, base:u64, offset: u64) -> isize {
/*         let locty: u8 = 0; // Hardcode to zero temporarily
        let locty: u8 = tpm_tis_locality_from_addr(base + offset);
        // TPM Startup should run only once.
        // This is temporary work around until Startup is run from firmware
        if self.startup_invoked() {
            return 0;
        }
        let startup_command:[u8; 12] = [
            0x80, 0x01, // TPM_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x0c, // commandSize = 12
            0x00, 0x00, 0x01, 0x44, // TPM_CC_Startup
            0x00, 0x00, // TPM_SU_CLEAR
        ];
        let mut data:[u8; 4] = [0,0,0,0];
        //self.locs[locty as usize].sts;


        if self.locs[locty as usize].sts & TPM_TIS_INT_COMMAND_READY == 0 {
            warn!("PPK: TPM at locty {:?} not ready for Startup", locty);
            return 1;
        }
        warn!("PPK: TPM is Ready");
        self.read(base, TPM_TIS_REG_STS, &mut data);
        warn!("PPK: sts return {:?}", data);
        let mut burstcnt = (u32::from_le_bytes(data) >> 8) & 0xFFFF;

        while true {
            if burstcnt >= 0 {
                break;
            }
            else{
                //sleep for 10 ms
                thread::sleep(time::Duration::from_millis(10));
                self.read(base, TPM_TIS_REG_STS, &mut data);
                burstcnt = (u32::from_le_bytes(data) >> 8) & 0xFFFF;
            }
        }

         warn!("PPK: burstcnt = {:?}", burstcnt);
        self.write(base, fifo_offset, &startup_command);
        let sts = self.read(base, TPM_TIS_REG_STS, data);
        while(1){
            if sts & TPM_TIS_INT_COMMAND_READY == 1{
                break;
            }
            else{
                //sleep for 10 ms
                thread::sleep(time::Duration::from_millis(10));
                sts = self.read(base, TPM_TIS_REG_STS, data);
            }
        }
        warn!("PPK: TPM is Ready: 2");

        let sts = self.read(base, TPM_TIS_REG_STS, data);
        warn!("PPK: STS Register {:#x}",sts);
        let tpm_go_command:[u8] = [0x20];
        self.write(base, TPM_TIS_REG_STS, &tpm_go_command);
*/


        0
    }
    fn trigger_interrupt(&mut self) -> result::Result<(), io::Error> {
        warn!("Trigger Interrupt at {:?}", self.irq_num);
        self.irq.trigger(self.irq_num)
    }

    /* TpmIsa helper functions */
    fn tpm_cmd_get_size(&mut self) -> u32 {
        let size: [u8; 4] = self.buffer[2..2+4].try_into().expect("tpm_util_is_selftest: slice with incorrect length");
        u32::from_ne_bytes(size).to_be()
    }

    fn tpm_tis_check_request_use_except(&mut self, locty: u8) -> u32 {
        for l in 0..TPM_TIS_NUM_LOCALITIES-1 {
            if l as u8 == locty {
                continue;
            }
            if (self.locs[l as usize].access & TPM_TIS_ACCESS_REQUEST_USE) != 0 {
                return 1;
            }
        }

        0
    }

    /* raise an interrupt if allowed */
    fn tpm_tis_raise_irq(&mut self, locty: u8, irqmask: u32) {
        warn!("Raise IRQ, locty {:?}", locty);
        if !(locty < 5) {
            return;
        }

        if (self.locs[locty as usize].inte & TPM_TIS_INT_ENABLED != 0) && (self.locs[locty as usize].inte & irqmask != 0) {
            self.trigger_interrupt();
            self.locs[locty as usize].ints |= irqmask;
        }
    }

    /*
    * Read a byte of response data
    */
    fn tpm_tis_data_read(&mut self, locty: u8) -> u8 {
        let mut ret = TPM_TIS_NO_DATA_BYTE as u8;
        let len: u32;

        if (self.locs[locty as usize].sts & TPM_TIS_STS_DATA_AVAILABLE) != 0 {
            len = cmp::min(self.tpm_cmd_get_size() as u32, self.be_buffer_size as u32);
            ret = self.buffer[self.rw_offset as usize];
            self.rw_offset +=1;
            if self.rw_offset as u32 >= len {
                /* got last byte */
                self.tpm_tis_sts_set(locty, TPM_TIS_STS_VALID);
                self.tpm_tis_raise_irq(locty, TPM_TIS_INT_STS_VALID);
            }
        }

        ret
    }

    fn tpm_tis_new_active_locality(&mut self, new_active_locality: u8) {
        let change = self.active_locty != new_active_locality;
        let is_seize: bool;
        let mask: u8;

        if change && (self.active_locty < 5) {
            is_seize = (new_active_locality < 5) && ((self.locs[new_active_locality as usize].access & TPM_TIS_ACCESS_SEIZE as u8) != 0);

            if is_seize {
                mask = !TPM_TIS_ACCESS_ACTIVE_LOCALITY as u8;
            } else {
                mask = !(TPM_TIS_ACCESS_ACTIVE_LOCALITY | TPM_TIS_ACCESS_REQUEST_USE) as u8;
            }
            /* reset flags on the old active locality */
            self.locs[self.active_locty as usize].access &= mask;

            if is_seize {
                self.locs[self.active_locty as usize].access |= TPM_TIS_ACCESS_BEEN_SEIZED as u8;
            }
        }

        self.active_locty = new_active_locality;

        if new_active_locality < 5 {
            /* set flags on the new active locality */
            self.locs[new_active_locality as usize].access |= TPM_TIS_ACCESS_ACTIVE_LOCALITY;
            self.locs[new_active_locality as usize].access &= !(TPM_TIS_ACCESS_REQUEST_USE | TPM_TIS_ACCESS_SEIZE as u8);
        }

        if change {
            warn!("Change is true");
            self.tpm_tis_raise_irq(self.active_locty, TPM_TIS_INT_LOCALITY_CHANGED);//IMPLEMENT
        }
    }

    /*
    * Set the given flags in the STS register by clearing the register but
    * preserving the SELFTEST_DONE and TPM_FAMILY_MASK flags and then setting
    * the new flags.
    *
    * The SELFTEST_DONE flag is acquired from the backend that determines it by
    * peeking into TPM commands.
    *
    * A VM suspend/resume will preserve the flag by storing it into the VM
    * device state, but the backend will not remember it when Cloud Hypervisor is started
    * again. Therefore, we cache the flag here. Once set, it will not be unset
    * except by a reset.
    */
    fn tpm_tis_sts_set(&mut self, locality: u8, flags: u32) {
        self.locs[locality as usize].sts &= TPM_TIS_STS_SELFTEST_DONE | TPM_TIS_STS_TPM_FAMILY_MASK;
        self.locs[locality as usize].sts |= flags;
        warn!("STS Set for locality: {}", locality);
    }

    fn tpm_backend_get_tpm_established_flag(&mut self) -> bool {
        self.be_driver.get_tpm_established_flag()
    }

    fn tpm_backend_reset_tpm_established_flag(&mut self, locty: u8) -> isize {
        self.be_driver.reset_tpm_established_flag(locty)
    }

    /**
     * tpm_backend_deliver_request:
     * @s: the backend to send the request to
     * @cmd: the command to deliver
     *
     * Send a request to the backend. The backend will then send the request
     * to the TPM implementation.
     */
    fn tpm_backend_deliver_request(&mut self) {
        warn!("tpm_backend_deliver_request");
        if let Some(ref mut cmd) = self.cmd {
            if self.be_driver.deliver_request(cmd) == 0 {
                let locty = cmd.locty;
                assert!(locty < 5);

                if cmd.selftest_done {
                    for l in 0..TPM_TIS_NUM_LOCALITIES-1 {
                        self.locs[l as usize].sts |= 1<<2;
                    }
                }

                self.tpm_tis_sts_set(locty, TPM_TIS_STS_VALID | TPM_TIS_STS_DATA_AVAILABLE);
                self.locs[locty as usize].state = TPMTISState::TpmTisStateCompletion;

                // tpm_util_show_buffer(s->buffer, s->be_buffer_size, "From TPM");

                if self.next_locty < 5 {
                    self.tpm_tis_abort();
                }

                // self.tpm_tis_raise_irq(locty, TPM_TIS_INT_DATA_AVAILABLE | TPM_TIS_INT_STS_VALID);
            }
        }
    }

    fn tpm_backend_had_startup_error(&mut self) -> bool {
        self.be_driver.backend.had_startup_error()
    }

    fn tpm_backend_cancel_cmd(&mut self) {
        self.be_driver.backend.cancel_cmd();
    }

    fn tpm_tis_abort(&mut self) {
        warn!("TIS Abort Prompted");
        self.rw_offset = 0;

        /*
        * Need to react differently depending on who's aborting now and
        * which locality will become active afterwards.
        */
        if self.aborting_locty == self.next_locty {
            self.locs[self.aborting_locty as usize].state = TPMTISState::TpmTisStateReady;
            self.tpm_tis_sts_set(self.aborting_locty, TPM_TIS_STS_COMMAND_READY);
            self.tpm_tis_raise_irq(self.aborting_locty, TPM_TIS_INT_COMMAND_READY);
        }

        /* locality after abort is another one than the current one */
        self.tpm_tis_new_active_locality(self.next_locty);

        self.next_locty = TPM_TIS_NO_LOCALITY;
        /* nobody's aborting a command anymore */
        self.aborting_locty = TPM_TIS_NO_LOCALITY;
    }

    /* prepare aborting current command */
    fn tpm_tis_prep_abort(&mut self, locty: u8, newlocty: u8) {
        assert!(newlocty < 5);

        self.aborting_locty = locty;
        self.next_locty = newlocty;

        /*
        * only abort a command using an interrupt if currently executing
        * a command AND if there's a valid connection to the vTPM.
        */
        for busy_locty in 0..TPM_TIS_NUM_LOCALITIES {
            if self.locs[busy_locty as usize].state == TPMTISState::TpmTisStateExecution {
                /*
                * request the backend to cancel. Some backends may not
                * support it
                */
                warn!("Requesting Backend to Cancel Cmd");
                self.tpm_backend_cancel_cmd();
                return;
            }
        }

        self.tpm_tis_abort();
    }

    fn tpm_tis_tpm_send(&mut self, locty: u8) {
        /*
        * rw_offset serves as length indicator for length of data;
        * it's reset when the response comes back
        */
        warn!("tpm_tis_tpm_send: Attempting to send command to TPM locty: {}", locty);

        self.locs[locty as usize].state = TPMTISState::TpmTisStateExecution;
        self.cmd = Some(TPMBackendCmd {
            locty: locty,
            input: self.buffer.clone(),
            input_len: self.rw_offset as u32,
            output: self.buffer.clone(),
            output_len: self.be_buffer_size as isize,
            selftest_done: false,
        });

        warn!("Input: {:?} , Output: {:?}", self.cmd.as_ref().unwrap().input, self.cmd.as_ref().unwrap().output);

        self.tpm_backend_deliver_request();
    }

    fn handle_write(&mut self, _base: u64, offset: u64, mut val: u32, mut mask: u32, data: &[u8]) -> Result<()> {
        let locty = tpm_tis_locality_from_addr(_base + offset);
        let shift: u8 = (((_base + offset) & 0x3) * 8) as u8;
        let mut size = data.len();
        let addr = _base + offset;
        let mut set_new_locty = 1;

        warn!("Shift to use: {}", shift);
        warn!("Locty to use: {}", locty);
        warn!("Active Locty: {}", self.active_locty);
        warn!("New TPM Write2(base: {}, offset: {}, data: {:?})", _base, offset, data); //DEBUG
        warn!("mmio.write start Locty {:?}, Current STS: {:#X}", locty, self.locs[locty as usize].sts);

        // if self.tpm_backend_had_startup_error(self) {
        //     return Err(Error::TPMBackendFailure);
        // }


        val &= mask;
        warn!("Masked value: {}", val);

        if shift != 0 {
            val <<= shift;
            mask <<= shift;
        }
        warn!("Shifted Value: {}", val);

        mask ^= 0xffffffff;

        match offset {
            TPM_TIS_REG_ACCESS => {
                if val & TPM_TIS_ACCESS_SEIZE as u32 != 0 {
                    val &= !(TPM_TIS_ACCESS_REQUEST_USE | TPM_TIS_ACCESS_ACTIVE_LOCALITY) as u32;
                    warn!("TIS Register Access Seize for val: {}", val);
                }

                let mut active_locty = self.active_locty;

                if val & TPM_TIS_ACCESS_ACTIVE_LOCALITY as u32 != 0 {
                    warn!("TIS Register access active locality request");
                    /* give up locality if currently owned */
                    if self.active_locty == locty {
                        let mut newlocty: u8 = TPM_TIS_NO_LOCALITY;
                        /* anybody wants the locality ? */
                        for c in (0..TPM_TIS_NUM_LOCALITIES).rev() {
                            if self.locs[c as usize].access & TPM_TIS_ACCESS_REQUEST_USE != 0 {
                                newlocty = c as u8;
                                break;
                            }
                        }

                        if newlocty < 5 {
                            set_new_locty = 0;
                            self.tpm_tis_prep_abort(locty, newlocty);
                        } else {
                            active_locty = TPM_TIS_NO_LOCALITY;
                        }
                    } else {
                        /* not currently the owner; clear a pending request */
                        self.locs[locty as usize].access &= !TPM_TIS_ACCESS_REQUEST_USE as u8;
                    }
                }

                if val & TPM_TIS_ACCESS_BEEN_SEIZED != 0 {
                    warn!("TIS Register has been seized val: {}", val);
                    self.locs[locty as usize].access &= !TPM_TIS_ACCESS_BEEN_SEIZED as u8;
                }

                if val & TPM_TIS_ACCESS_SEIZE as u32 != 0 {
                    /*
                    * allow seize if a locality is active and the requesting
                    * locality is higher than the one that's active
                    * OR
                    * allow seize for requesting locality if no locality is
                    * active
                    */
                    while ((self.active_locty < 5) && locty > self.active_locty) || !(self.active_locty < 5) {
                        let mut higher_seize = false;

                        /* already a pending SEIZE ? */
                        if self.locs[locty as usize].access & TPM_TIS_ACCESS_SEIZE as u8 != 0 {
                            break;
                        }

                        /* check for ongoing seize by a higher locality */
                        for l in locty+1..TPM_TIS_NUM_LOCALITIES {
                            if self.locs[l as usize].access & TPM_TIS_ACCESS_SEIZE != 0 {
                                higher_seize = true;
                                break;
                            }
                        }

                        if higher_seize {
                            break;
                        }

                        /* cancel any seize by a lower locality */
                        for l in 0..locty {
                            self.locs[l as usize].access &= !TPM_TIS_ACCESS_SEIZE;
                        }

                        self.locs[locty as usize].access |= TPM_TIS_ACCESS_SEIZE;

                        set_new_locty = 0;
                        self.tpm_tis_prep_abort(self.active_locty, locty);
                        break;
                    }
                }

                if val & TPM_TIS_ACCESS_REQUEST_USE as u32 != 0 {
                    if self.active_locty != locty {
                        if self.active_locty < 5 {
                            self.locs[locty as usize].access |= TPM_TIS_ACCESS_REQUEST_USE;
                        } else {
                            /* no locality active -> make this one active now */
                            active_locty = locty;
                        }
                    }
                }

                if set_new_locty != 0 {
                    self.tpm_tis_new_active_locality(active_locty);

                    warn!("New Active Locality Set: {}", active_locty);
                }
            },
            TPM_TIS_REG_INT_ENABLE => {
                if self.active_locty == locty {
                    self.locs[locty as usize].inte &= mask;
                    self.locs[locty as usize].inte |= val & (TPM_TIS_INT_ENABLED | TPM_TIS_INT_POLARITY_MASK | TPM_TIS_INTERRUPTS_SUPPORTED);
                    warn!("Active locty reached");
                } else {
                    warn!("Not Active locty");
                };

                warn!("Command: IntEnable Access: {}", val);
            },
            TPM_TIS_REG_INT_VECTOR => {},
            TPM_TIS_REG_INT_STATUS => {
                if self.active_locty == locty {
                    /* clearing of interrupt flags */
                    if (val & TPM_TIS_INTERRUPTS_SUPPORTED != 0) && (self.locs[locty as usize].ints & TPM_TIS_INTERRUPTS_SUPPORTED != 0) {
                        self.locs[locty as usize].ints &= !val;
                        if self.locs[locty as usize].ints == 0 {
                            let res = self.trigger_interrupt();
                            //qemu_irq_lower(self.irq)
                        }
                    }
                    self.locs[locty as usize].ints &= !(val & TPM_TIS_INTERRUPTS_SUPPORTED);
                }
            },
            TPM_TIS_REG_STS => {
                if self.active_locty == locty {
                    //ONLY TPM2 Command
                    if val & TPM_TIS_STS_COMMAND_CANCEL != 0 {
                        if self.locs[locty as usize].state == TPMTISState::TpmTisStateExecution {
                            warn!("Request TPM Cancel Command");
                            /*
                            * request the backend to cancel. Some backends may not
                            * support it
                            */
                            self.tpm_backend_cancel_cmd();
                        }
                    }

                    //ONLY TPM2 Command
                    if val & TPM_TIS_STS_RESET_ESTABLISHMENT_BIT != 0 {
                        if locty == 3 || locty == 4 {
                            self.tpm_backend_reset_tpm_established_flag(locty);
                        }
                    }

                    val &= TPM_TIS_STS_COMMAND_READY | TPM_TIS_STS_TPM_GO | TPM_TIS_STS_RESPONSE_RETRY;

                    if val == TPM_TIS_STS_COMMAND_READY {
                        warn!("Status Command Ready: {:?}", self.locs[locty as usize].state);
                        match self.locs[locty as usize].state {
                            TPMTISState::TpmTisStateReady => self.rw_offset = 0,
                            TPMTISState::TpmTisStateIdle => {
                                self.tpm_tis_sts_set(locty, TPM_TIS_STS_COMMAND_READY);
                                self.locs[locty as usize].state = TPMTISState::TpmTisStateReady;
                                self.tpm_tis_raise_irq(locty, TPM_TIS_INT_COMMAND_READY);
                                warn!("Status Command Updated: {:?}", self.locs[locty as usize].state);
                            }
                            TPMTISState::TpmTisStateExecution => self.tpm_tis_prep_abort(locty, locty),
                            TPMTISState::TpmTisStateReception => self.tpm_tis_prep_abort(locty, locty),
                            TPMTISState::TpmTisStateCompletion => {
                                self.rw_offset = 0;
                                /* shortcut to ready state with C/R set */
                                self.locs[locty as usize].state = TPMTISState::TpmTisStateReady;
                                if self.locs[locty as usize].sts & TPM_TIS_STS_COMMAND_READY == 0 {
                                    self.tpm_tis_sts_set(locty, TPM_TIS_STS_COMMAND_READY);
                                    self.tpm_tis_raise_irq(locty, TPM_TIS_INT_COMMAND_READY)
                                }
                                self.locs[locty as usize].sts &= !(TPM_TIS_STS_DATA_AVAILABLE);
                            }
                        }
                    } else if val == TPM_TIS_STS_TPM_GO {
                        match &self.locs[locty as usize].state {
                            TPMTISState::TpmTisStateReception => {
                                if (self.locs[locty as usize].sts & TPM_TIS_STS_EXPECT) == 0 {
                                    self.tpm_tis_tpm_send(locty);
                                    self.tpm_tis_sts_set(locty, TPM_TIS_STS_VALID|TPM_TIS_STS_DATA_AVAILABLE);
                                }
                            }
                            _ => {},
                        }
                    } else if val == TPM_TIS_STS_RESPONSE_RETRY {
                        match &self.locs[locty as usize].state {
                            TPMTISState::TpmTisStateCompletion => {
                                warn!("State Completion");

                                self.rw_offset = 0;
                                self.tpm_tis_sts_set(locty, TPM_TIS_STS_VALID|TPM_TIS_STS_DATA_AVAILABLE);
                            }
                            _ => {},
                        }
                    }
                }
            },
            TPM_TIS_REG_DATA_FIFO => /* data fifo */ {
            if self.active_locty == locty {
                if self.locs[locty as usize].state == TPMTISState::TpmTisStateIdle || self.locs[locty as usize].state == TPMTISState::TpmTisStateExecution || self.locs[locty as usize].state == TPMTISState::TpmTisStateCompletion {
                    /* drop the byte */
                } else {
                    if self.locs[locty as usize].state == TPMTISState::TpmTisStateReady {
                        self.locs[locty as usize].state = TPMTISState::TpmTisStateReception;
                        self.tpm_tis_sts_set(locty, TPM_TIS_STS_EXPECT | TPM_TIS_STS_VALID);
                    }

                    val >>= shift as u32;
                    if size > 4 - (addr & 0x3) as usize {
                        /* prevent access beyond FIFO */
                        size = 4 - (addr & 0x3) as usize;
                    }
                    while (self.locs[locty as usize].sts & TPM_TIS_STS_EXPECT) != 0 && size > 0 {
                        if self.rw_offset < self.be_buffer_size as u16 {
                            self.buffer.push(val as u8);
                            // self.buffer[self.rw_offset as usize] = val as u8;
                            self.rw_offset += 1;
                            val >>= 8;
                            size -= 1;
                        } else {
                            self.tpm_tis_sts_set(locty, TPM_TIS_STS_VALID);
                        }
                    }
                    /* check for complete packet */
                    if self.rw_offset > 5 && (self.locs[locty as usize].sts & TPM_TIS_STS_EXPECT != 0) {
                        warn!("Check for complete pack");
                        /* we have a packet length - see if we have all of it */
                        let need_irq: bool = !(self.locs[locty as usize].sts & TPM_TIS_STS_VALID) != 0;

                        let len = self.tpm_cmd_get_size(); //IMPLEMENT
                        if len > self.rw_offset as u32 {
                            self.tpm_tis_sts_set(locty, TPM_TIS_STS_EXPECT | TPM_TIS_STS_VALID);
                        } else {
                            /* packet complete */
                            self.tpm_tis_sts_set(locty, TPM_TIS_STS_VALID);
                        }
                        if need_irq {
                            self.tpm_tis_raise_irq(locty, TPM_TIS_INT_STS_VALID); //IMPLMEMENT
                        }
                    }
                }
            }
        },
            TPM_TIS_REG_DATA_XFIFO ..= TPM_TIS_REG_DATA_XFIFO_END => {
                /* data fifo */
                if self.active_locty == locty {
                    if self.locs[locty as usize].state == TPMTISState::TpmTisStateIdle || self.locs[locty as usize].state == TPMTISState::TpmTisStateExecution || self.locs[locty as usize].state == TPMTISState::TpmTisStateCompletion {
                        /* drop the byte */
                    } else {
                        if self.locs[locty as usize].state == TPMTISState::TpmTisStateReady {
                            self.locs[locty as usize].state = TPMTISState::TpmTisStateReception;
                            self.tpm_tis_sts_set(locty, TPM_TIS_STS_EXPECT | TPM_TIS_STS_VALID);
                        }

                        val >>= shift as u32;
                        if size > 4 - (addr & 0x3) as usize {
                            /* prevent access beyond FIFO */
                            size = 4 - (addr & 0x3) as usize;
                        }
                        while (self.locs[locty as usize].sts & TPM_TIS_STS_EXPECT) != 0 && size > 0 {
                            if self.rw_offset < self.be_buffer_size as u16 {
                                self.buffer.push(val as u8);
                                // self.buffer[self.rw_offset as usize] = val as u8;
                                self.rw_offset += 1;
                                val >>= 8;
                                size -= 1;
                            } else {
                                self.tpm_tis_sts_set(locty, TPM_TIS_STS_VALID);
                            }
                        }
                        /* check for complete packet */
                        if self.rw_offset > 5 && (self.locs[locty as usize].sts & TPM_TIS_STS_EXPECT != 0) {
                            warn!("Check for complete pack");
                            /* we have a packet length - see if we have all of it */
                            let need_irq: bool = !(self.locs[locty as usize].sts & TPM_TIS_STS_VALID) != 0;

                            let len = self.tpm_cmd_get_size(); //IMPLEMENT
                            if len > self.rw_offset as u32 {
                                self.tpm_tis_sts_set(locty, TPM_TIS_STS_EXPECT | TPM_TIS_STS_VALID);
                            } else {
                                /* packet complete */
                                self.tpm_tis_sts_set(locty, TPM_TIS_STS_VALID);
                            }
                            if need_irq {
                                self.tpm_tis_raise_irq(locty, TPM_TIS_INT_STS_VALID); //IMPLMEMENT
                            }
                        }
                    }
                }
            },
            TPM_TIS_REG_INTERFACE_ID => {
                if val & TPM_TIS_IFACE_ID_INT_SEL_LOCK != 0 {
                    for l in 0..TPM_TIS_NUM_LOCALITIES {
                        self.locs[l as usize].iface_id |= TPM_TIS_IFACE_ID_INT_SEL_LOCK;
                    }
                }
            },
            _ => {
                return Err(Error::BadWriteOffset(offset));
            }
        }
        warn!("mmio.write end: Locty: {}, End STS: {:#X}, offset= {:#X}, data: {:?}", locty, self.locs[locty as usize].sts, offset, data);
        Ok(())
    }
}

impl BusDevice for TPMIsa {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        warn!(""); // Separator
        let locty: u8 = tpm_tis_locality_from_addr(base + offset);
        let addr: u64 = base + offset;
        let mut avail: u32;
        let mut size = data.len();
        let mut v: u8;
        let mut shift: u8 = (((base + offset) & 0x3) * 8) as u8;
        let mut read_ok = true;
        let mut val: u32 = 0xffffffff;
        // self.count +=1;

        warn!("New TPM Read(offset: {:#X}, data: {:?})", offset, data); //DEBUG
        warn!("Locty: {}, Current STS: {:#X}", locty, self.locs[locty as usize].sts);


        // Check tpm_backend_active:
        // if (tpm_backend_had_startup_error(s->be_driver)) {
        //     warn!("TPM HAD STARTUP ERROR");
        //     return
        // }

        match offset {
            TPM_TIS_REG_ACCESS => {
                warn!("Offset: Register Access");
                val = (self.locs[locty as usize].access & !TPM_TIS_ACCESS_SEIZE) as u32;
                /* Get Pending Flag */
                if self.tpm_tis_check_request_use_except(locty) != 0 {
                    val |= TPM_TIS_ACCESS_PENDING_REQUEST;
                    warn!("TPM Tis access pending request locty: {}", locty);
                }
                val |= !self.tpm_backend_get_tpm_established_flag() as u32; // IMPLEMENT
                warn!("Register Access Value: {}", val);
            },
            TPM_TIS_REG_INT_ENABLE => {
                warn!("Offset: Interrupt Enable");
                val = self.locs[locty as usize].inte;
                warn!("Interrupt Enable Value: {}", val);
            },
            TPM_TIS_REG_INT_VECTOR => {
                warn!("Offset: Interrupt Enable");
                val = self.irq_num
            },
            TPM_TIS_REG_INT_STATUS => val = self.locs[locty as usize].ints,
            TPM_TIS_REG_INTF_CAPABILITY => val = TPM_TIS_CAPABILITIES_SUPPORTED2_0, //ONLY IMPLEMENTED TPM2
            TPM_TIS_REG_STS => {
                warn!("Command: Reg status.");
                let buff_size:usize = self.be_buffer_size.try_into().unwrap();
                if self.active_locty == locty {
                    warn!("Active Locty matched. Current STS: {:#X} size = {:?}", self.locs[locty as usize].sts, size);
                    warn!("TIS_REG_STS: be_buffer_size = {:?}, rw_offset= {:?}", buff_size, self.rw_offset);
                    if self.locs[locty as usize].sts & TPM_TIS_STS_DATA_AVAILABLE != 0 {
                        val = ((cmp::min(self.tpm_cmd_get_size(), self.be_buffer_size.try_into().unwrap()) - self.rw_offset as u32) << 8) | self.locs[locty as usize].sts;
                        warn!("TIS_REG_STS: Data available: {}", val);
                    } else {
                        avail = self.be_buffer_size as u32 - self.rw_offset as u32; // IMPLEMENT be_buffer_size
                        /*
                        * byte-sized reads should not return 0x00 for 0x100
                        * available bytes.
                        */
                        if size == 1 && avail > 0xff {
                            avail = 0xff;
                        }
                        val = (avail << 8) | self.locs[locty as usize].sts;
                        self.count+=1;
                        warn!("TIS_REG_STS: Data unavailable: bytes available: {:#x}, buffer_size: {:#x}, rw_offset: {:#x}, new val: {:#x}, sts={:#x}", avail, self.be_buffer_size, self.rw_offset, val,self.locs[locty as usize].sts);
                    }
                }
            },
            TPM_TIS_REG_DATA_FIFO => {
                warn!("XFIFO Region Read");
                if self.active_locty == locty {
                    if size > (4 - (addr & 0x3)) as usize {
                        /* prevent access beyond FIFO */
                        size = (4 - (addr & 0x3)) as usize;
                    }
                    val = 0;
                    shift = 0;
                    while size > 0 {
                        match self.locs[locty as usize].state {
                            TPMTISState::TpmTisStateCompletion => v = self.tpm_tis_data_read(locty),
                            _ => {
                                v = TPM_TIS_NO_DATA_BYTE as u8;
                            }
                        }
                        val |= (v << shift) as u32;
                        shift += 8;
                        size-=1;
                    }
                    shift = 0; /* no more adjustments */
                }
            },
            TPM_TIS_REG_DATA_XFIFO ..= TPM_TIS_REG_DATA_XFIFO_END => {
                warn!("XFIFO Region Read");
                if self.active_locty == locty {
                    if size > (4 - (addr & 0x3)) as usize {
                        /* prevent access beyond FIFO */
                        size = (4 - (addr & 0x3)) as usize;
                    }
                    val = 0;
                    shift = 0;
                    while size > 0 {
                        match self.locs[locty as usize].state {
                            TPMTISState::TpmTisStateCompletion => v = self.tpm_tis_data_read(locty),
                            _ => {
                                v = TPM_TIS_NO_DATA_BYTE as u8;
                            }
                        }
                        val |= (v << shift) as u32;
                        shift += 8;
                        size-=1;
                    }
                    shift = 0; /* no more adjustments */
                }
            },
            TPM_TIS_REG_INTERFACE_ID => val = self.locs[locty as usize].iface_id,
            TPM_TIS_REG_DID_VID => val = (TPM_TIS_TPM_DID << 16) | TPM_TIS_TPM_VID,
            TPM_TIS_REG_RID => val = TPM_TIS_TPM_RID,
            //DEBUG STATE
            _ => {
                read_ok = false;
            }
        }

        if shift != 0 {
            val >>= shift;
        }

        // if self.count >30 {
        //     panic!("30 unavailables reached");
        // }
        if read_ok && data.len() <= 4 {
            for (byte, read) in data.iter_mut().zip(<u32>::to_le_bytes(val).iter().cloned()) {
                *byte = read as u8;
            }
            warn!("mmio.read end: offset: {:#X}, data: {:?}, status = {:#X}", offset, data, self.locs[locty as usize].sts);

        } else {
            warn!(
                "Invalid TPM read: offset {}, data length {}",
                offset,
                data.len()
            );
        }
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {

        self.invoke_startup(base, offset);

        let size = data.len();
        warn!(""); // Separator
        warn!("New TPM Write(base: {}, offset: {}, data: {:?})", base, offset, data); //DEBUG
        if size <= 4 {
            let v = {
                let mut array = [0u8;4];
                for (byte, read) in array.iter_mut().zip(data.iter().cloned()) {
                    *byte = read as u8;
                }
                u32::from_le_bytes(array)
            };

            warn!("Value of input: {}", v);

            let mask: u32 = if size == 1 { 0xff } else { if size == 2 { 0xffff } else { !0 } };
            warn!("Mask value: {}", mask);

            if let Err(e) = self.handle_write(base, offset, v, mask, data) {
                warn!("Failed to write to vTPM device: {}", e);
            }
        } else {
            warn!(
                "Invalid TPM write: offset {}, data length {}",
                offset,
                data.len()
            );
        }
        None
    }
}
