use bit_field::BitField;
use bitflags::bitflags;
use x86::segmentation::SegmentSelector;
use x86_64::structures::gdt::DescriptorFlags;
use x86_64::structures::DescriptorTablePointer;

use super::tables::GdtStruct;

bitflags! {
    /// Access rights for VMCS guest register states.
    ///
    /// The low 16 bits correspond to bits 23:8 of the upper 32 bits of a 64-bit
    /// segment descriptor. See Volume 3, Section 24.4.1 for access rights format,
    /// Volume 3, Section 3.4.5.1 for valid non-system selector types, Volume 3,
    /// Section 3.5 for valid system selectors types.
    pub struct SegmentAccessRights: u32 {
        /// Accessed flag.
        const ACCESSED          = 1 << 0;
        /// For data segments, this flag sets the segment as writable. For code
        /// segments, this flag sets the segment as readable.
        const WRITABLE          = 1 << 1;
        /// For data segments, this flag marks a data segment as “expansion-direction”.
        /// For code segments, this flag marks a code segment as “conforming”.
        const CONFORMING        = 1 << 2;
        /// This flag must be set for code segments.
        const EXECUTABLE        = 1 << 3;
        /// S — Descriptor type (0 = system; 1 = code or data)
        const CODE_DATA         = 1 << 4;
        /// P — Segment present
        const PRESENT           = 1 << 7;
        /// L - Reserved (except for CS) or 64-bit mode active (for CS only)
        const LONG_MODE         = 1 << 13;
        /// D/B — Default operation size (0 = 16-bit segment; 1 = 32-bit segment)
        const DB                = 1 << 14;
        /// G — Granularity
        const GRANULARITY       = 1 << 15;
        /// Segment unusable (0 = usable; 1 = unusable)
        const UNUSABLE          = 1 << 16;

        /// TSS (Available) for 32/64-bit
        const TSS_AVAIL         = 0b1001;
        /// TSS (Busy) for 32/64-bit
        const TSS_BUSY          = 0b1011;

        /// Descriptor privilege level (User)
        const DPL_USER          = 3 << 5;
    }
}

impl SegmentAccessRights {
    #[allow(dead_code)]
    pub fn dpl(&self) -> u8 {
        self.bits().get_bits(5..=6) as _
    }

    pub fn from_descriptor(desc: u64) -> Self {
        Self::from_bits_truncate(desc.get_bits(40..56) as u32 & 0xf0ff)
    }

    pub fn _type_field(&self) -> Self {
        Self::from_bits_truncate(self.bits() & 0xf)
    }

    pub fn set_descriptor_type(desc: &mut u64, type_field: Self) {
        desc.set_bits(40..44, type_field.bits() as u64);
    }

    #[cfg(feature = "amd")]
    pub fn as_svm_segment_attributes(&self) -> u16 {
        let bits = self.bits() as u16;
        (bits & 0xff) | ((bits & 0xf000) >> 4)
    }
}

#[derive(Debug)]
pub struct Segment {
    pub selector: SegmentSelector,
    pub base: u64,
    pub limit: u32,
    pub access_rights: SegmentAccessRights,
}

impl Segment {
    pub const fn invalid() -> Self {
        Self {
            selector: SegmentSelector::empty(),
            base: 0,
            limit: 0,
            access_rights: SegmentAccessRights::UNUSABLE,
        }
    }

    pub fn from_selector(selector: SegmentSelector, gdt: &DescriptorTablePointer) -> Self {
        let index = selector.index() as usize;
        let table = GdtStruct::from_pointer(gdt);

        let entry_value = table[index];
        let entry = DescriptorFlags::from_bits_truncate(entry_value);
        if entry.contains(DescriptorFlags::PRESENT) {
            let mut base = entry_value.get_bits(16..40) | entry_value.get_bits(56..64) << 24;
            let mut limit = entry_value.get_bits(0..16) | entry_value.get_bits(48..52) << 16;
            if !entry.contains(DescriptorFlags::USER_SEGMENT) {
                let high = table[index + 1];
                base += high << 32;
            }
            if entry.contains(DescriptorFlags::GRANULARITY) {
                limit = (limit << 12) | 0xfff;
            }
            Self {
                selector,
                base,
                limit: limit as _,
                access_rights: SegmentAccessRights::from_descriptor(entry_value),
            }
        } else {
            Self::invalid()
        }
    }
}
