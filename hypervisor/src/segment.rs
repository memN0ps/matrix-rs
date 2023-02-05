use bitfield::bitfield;
use bitflags::bitflags;
use x86::{segmentation::Descriptor};

bitfield! {
    pub struct SegmentDescriptor(u64);
    impl Debug;
    pub get_limit_low, set_limit_low: 15, 0;            // [0-15]
    pub get_base_low, set_base_low: 31, 16;             // [16-31]
    pub get_base_middle, set_base_middle: 39, 32;       // [32-39]
    pub get_type, set_type: 43, 40;                     // [40-43]
    pub get_system, set_system: 44, 44;                 // [44]
    pub get_dpl, set_dpl: 46, 45;                       // [45-46]
    pub get_present, set_present: 47, 47;               // [47]
    pub get_limit_high, set_limit_high: 51, 48;         // [48-51]
    pub get_avl, set_avl: 52, 52;                       // [52]
    pub get_long_mode, set_long_mode: 53, 53;           // [53]
    pub get_default_bit, set_default_bit: 54, 54;       // [54]
    pub get_granularity, set_granularity: 55, 55;       // [55]
    pub get_base_high, set_base_high: 63, 56;           // [56-63]
}

bitfield! {
    pub struct SegmentAttribute(u16);
    impl Debug;
    pub get_type, set_type: 3, 0;                       // [0-4]
    pub get_system, set_system: 4, 4;                   // [4]
    pub get_dpl, set_dpl: 6, 5;                         // [5-6]
    pub get_present, set_present: 7, 7;                 // [7]
    pub get_avl, set_avl: 8, 8;                         // [8]
    pub get_long_mode, set_long_mode: 9, 9;             // [9]
    pub get_default_bit, set_default_bit: 10, 10;       // [10]
    pub get_grunularity, set_granularity: 11, 11;       // [11]
    // reserved                                     // [12-15]
}

pub fn get_segment_base(gdt_base: *const usize, segment_selector: u16) -> u64 {
    const RPL_MASK: u16 = 3;

    let mut segment_base = 0u64;

    if segment_selector == 0 {
        return segment_base;
    }

    let descriptor = gdt_base as u64 + ((segment_selector & !RPL_MASK) * 8) as u64;

    let descriptor = descriptor as *mut u64 as *mut SegmentDescriptor;
    let descriptor = unsafe { descriptor.read_volatile() };

    segment_base |= descriptor.get_base_low() as u64;
    segment_base |= descriptor.get_base_middle() << 16;
    segment_base |= descriptor.get_base_high() << 24;

    if descriptor.get_system() == 0 {
        let expanded_descriptor = unsafe {
            (gdt_base.wrapping_add((segment_selector & !RPL_MASK) as usize) as *const Descriptor)
                .read_volatile()
        };
        segment_base |= (expanded_descriptor.lower as u64) << 32;
    }

    segment_base
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

bitflags! {
    struct SegmentSelector: u16 {
        const RPL = 0b11;
        const TABLE = 0b100;
        const INDEX = 0b1111111000;
    }
}

bitflags! {
    struct SegmentAccessRights: u32 {
        const TYPE = 0b1111;
        const DESCRIPTOR_TYPE = 0b10000;
        const DPL = 0b110000;
        const PRESENT = 0b1000000;
        const RESERVED0 = 0b1111000000;
        const AVAILABLE = 0b100000000;
        const LONG_MODE = 0b1000000000;
        const DEFAULT_BIG = 0b10000000000;
        const GRANULARITY = 0b100000000000;
        const UNUSABLE = 0b1000000000000;
        const RESERVED1 = 0b11111111111111000000000;
    }
}

pub fn read_access_rights(segment_selector: u16) -> u64 {
    let selector = SegmentSelector::from_bits_truncate(segment_selector);
    let mut vmx_access_rights = SegmentAccessRights::empty();

    if selector.contains(SegmentSelector::TABLE) && selector.contains(SegmentSelector::INDEX) {
        vmx_access_rights = SegmentAccessRights::from_bits_truncate(load_segment_access_rights(segment_selector) >> 8);
        vmx_access_rights.remove(SegmentAccessRights::UNUSABLE | SegmentAccessRights::RESERVED0 | SegmentAccessRights::RESERVED1);
    } 
    else {
        vmx_access_rights.insert(SegmentAccessRights::UNUSABLE);
    }

    vmx_access_rights.bits() as u64
}


