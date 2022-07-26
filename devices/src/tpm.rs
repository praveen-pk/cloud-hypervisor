use phf::{phf_map};
use vtpm::tpm_backend::{TPMBackendCmd, TPMEmulator};
use vm_device::BusDevice;

/*
/* Define SHIFT, LENGTH and MASK constants for a field within a register */

/* This macro will define R_FOO_BAR_MASK, R_FOO_BAR_SHIFT and R_FOO_BAR_LENGTH
 * constants for field BAR in register FOO.
 */
#define FIELD(reg, field, shift, length)                                  \
    enum { R_ ## reg ## _ ## field ## _SHIFT = (shift)};                  \
    enum { R_ ## reg ## _ ## field ## _LENGTH = (length)};                \
    enum { R_ ## reg ## _ ## field ## _MASK =                             \
                                        MAKE_64BIT_MASK(shift, length)};

/* This macro will define A_FOO, for the byte address of a register
 * as well as R_FOO for the uint32_t[] register number (A_FOO / 4).
 */
#define REG32(reg, addr)                                                  \
    enum { A_ ## reg = (addr) };                                          \
    enum { R_ ## reg = (addr) / 4 };
                                        */

/* Extract a field from an array of registers
#define ARRAY_FIELD_EX32(regs, reg, field)                                \
FIELD_EX32((regs)[R_ ## reg], reg, field)
#define ARRAY_FIELD_EX64(regs, reg, field)                                \
FIELD_EX64((regs)[R_ ## reg], reg, field)

#define FIELD_EX32(storage, reg, field)                                   \
    extract32((storage), R_ ## reg ## _ ## field ## _SHIFT,               \
              R_ ## reg ## _ ## field ## _LENGTH)
#define FIELD_EX64(storage, reg, field)                                   \
    extract64((storage), R_ ## reg ## _ ## field ## _SHIFT,               \
              R_ ## reg ## _ ## field ## _LENGTH)

 * extract32:
 * @value: the value to extract the bit field from
 * @start: the lowest bit in the bit field (numbered from 0)
 * @length: the length of the bit field
 *
 * Extract from the 32 bit input @value the bit field specified by the
 * @start and @length parameters, and return it. The bit field must
 * lie entirely within the 32 bit word. It is valid to request that
 * all 32 bits are returned (ie @length 32 and @start 0).
 *
 * Returns: the value of the bit field extracted from the input value.

 static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

*/



/* crb 32-bit registers */
const CRB_DATA_BUFFER:u32 = 0x80;

const TPM_CRB_R_MAX:u32 = CRB_DATA_BUFFER;
const CRB_LOC_STATE:u32 = 0x0;
//LOC Register Fields
// Field => (start, length)
// start: lowest bit in the bit field numbered from 0
// length: length of the bit field
const CRB_LOC_STATE_fields:phf::Map<&str,[u32;2]> = phf_map! {
    "Established" => [0, 1],
    "locAssigned" => [1,1],
    "activeLocality"=> [2, 3],
    "reserved" => [5, 2],
    "tpmRegValidSts" => [7, 1]
};
const CRB_LOC_CTRL:u32 = 0x08;
const CRB_LOC_STS: u32 = 0x0C;
const CRB_INTF_ID:u32 = 0x30;
const CRB_INTF_ID2:u32 = 0x34;
const CRB_CTRL_EXT:u32 = 0x38;
const CRB_CTRL_STS:u32 = 0x44;

fn get_fields_map(reg:&str) -> phf::Map<&str,[u32;2]> {
    println!("PPK: reg = {:?}", reg);
    match reg {
        "CRB_LOC_STATE" => {return CRB_LOC_STATE_fields;},
        _ => {panic!("yahoo!!")}
    };
}

/// Set a particular field in a Register
fn set_reg_field(regs:&mut [u32;TPM_CRB_R_MAX as usize], reg:usize, reg_name:&'static str, field:&str, value:u32) {
    let reg_fields = get_fields_map(reg_name);
    if reg_fields.contains_key(field){
        let start = reg_fields.get(field).unwrap()[0];
        let len = reg_fields.get(field).unwrap()[1];
        let mask =  (!(0 as u32) >> (32 - len)) << start;
        regs[reg] = (regs[reg] & !mask ) | ((value << start) & mask);
    }
}

/// Get the value of a particular field in a Register
/*fn get_reg_field(reg:u32, field:&str) -> u32{

}*/



struct TPM {
    emulator: TPMEmulator,
    cmd: Option<TPMBackendCmd>,
    regs: [u32;TPM_CRB_R_MAX as usize],
    be_buffer_size: usize
}

//impl BusDevice for TPM
impl BusDevice for TPM {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]){

        let addr: u64 = base + offset;
        let reg:u32 = addr as u32 & !3;
        let mut avail: u32;
        let mut size = data.len();
        let mut v: u8;


    }

}



mod tests {
    use super::*;

    #[test]
    fn test_set_reg_field() {
        let mut regs: [u32;TPM_CRB_R_MAX as usize] = [0;TPM_CRB_R_MAX as usize];
        set_reg_field(&mut regs, CRB_LOC_STATE as usize, "CRB_LOC_STATE" , "tpmRegValidSts", 1);
        assert_eq!(
            regs[CRB_LOC_STATE as usize],
            0x80,
            concat!("Test: ", stringify!(set_reg_field))
        );
    }
}