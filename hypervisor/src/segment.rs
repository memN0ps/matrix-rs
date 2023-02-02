use bitfield::{BitMut, BitRangeMut};

#[allow(dead_code)]
#[repr(packed)]
pub struct SegmentDescriptor {
    limit_15_0: u16,
    base_15_0: u16,
    base_23_16: u8,
    flags: u8,
    limit_19_16_flags: u8,
    base_31_24: u8,
}

pub fn get_segment_base(gdtbase: u32, ldt: u16, selector: u16) -> u32 {
    if selector == 0 {
        return 0;
    }

    let ldt_bit = 4;
    let selector_mask = 0xfff8;

    if (selector & ldt_bit) > 0 {
        let ldt = (gdtbase + (ldt as u32 & selector_mask)) as *mut SegmentDescriptor;
        let ldtbase = unsafe { (*ldt).get_base() };

        let segment = (ldtbase + (selector as u32 & selector_mask)) as *mut SegmentDescriptor;
        let segment_base = unsafe { (*segment).get_base() };
        return segment_base;
    } else {
        let segment = (gdtbase + (selector as u32 & selector_mask)) as *mut SegmentDescriptor;
        let segment_base = unsafe { (*segment).get_base() };
        return segment_base;
    }
}

impl SegmentDescriptor {
    pub fn get_base(&self) -> u32 {
        ((self.base_31_24 as u32) << 24) | ((self.base_23_16 as u32) << 16) | self.base_15_0 as u32
    }
}

pub fn load_segment_limit(selector: u16) -> u32 {
    let limit: u32;
    unsafe {
        core::arch::asm!("lsl {0:e}, {1:x}", out(reg) limit, in(reg) selector, options(nostack, nomem));
    }
    limit
}

pub fn load_segment_access_rights(selector: u16) -> u32 {
    let limit: u32;
    unsafe {
        core::arch::asm!("lar {0:e}, {1:x}", out(reg) limit, in(reg) selector, options(nostack, nomem));
    }
    limit
}

pub fn read_access_rights(selector: u16) -> u64 {
    let mut access_rights = 0;

    if selector == 0 {
        access_rights.set_bit(16, true);
        return access_rights;
    }

    access_rights = (load_segment_access_rights(selector) >> 8) as u64;
    // unusable
    access_rights.set_bit(16, false);
    // reserved0
    access_rights.set_bit_range(8, 11, 0);
    // reserved1
    access_rights.set_bit_range(17, 31, 0);

    access_rights
}

