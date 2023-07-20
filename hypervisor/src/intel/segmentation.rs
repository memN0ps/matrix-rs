// I did not know how to do this part so I took the help of rcore-os' code but I will reimplement in this in future after understanding it fully
//Credits to rcore-os: https://github.com/rcore-os/RVM1.5/blob/main/src/arch/x86_64/segmentation.rs
//Credits to rcore-os: https://github.com/rcore-os/RVM1.5/blob/main/src/arch/x86_64/tables.rs
use bit_field::BitField;
use bitflags::bitflags;
use core::{
    fmt::{Debug, Formatter, Result},
    mem::size_of,
};
use x86::segmentation::SegmentSelector;
use x86_64::addr::VirtAddr;
use x86_64::structures::gdt::DescriptorFlags;
use x86_64::structures::DescriptorTablePointer;

bitflags! {
    /// Access rights for VMCS guest register states.
    ///
    /// The low 16 bits correspond to bits 23:8 of the upper 32 bits of a 64-bit
    /// segment descriptor. See Volume 3, Section 24.4.1 for access rights format,
    /// Volume 3, Section 3.4.5.1 for valid non-system selector types, Volume 3,
    /// Section 3.5 for valid system selectors types.
    #[derive(Debug)]
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
    pub fn from_descriptor(desc: u64) -> Self {
        Self::from_bits_truncate(desc.get_bits(40..56) as u32 & 0xf0ff)
    }

    pub fn _type_field(&self) -> Self {
        Self::from_bits_truncate(self.bits() & 0xf)
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

pub struct GdtStruct {
    table: &'static mut [u64],
}

impl GdtStruct {
    pub fn from_pointer(pointer: &DescriptorTablePointer) -> Self {
        let entry_count = (pointer.limit as usize + 1) / size_of::<u64>();
        Self {
            table: unsafe {
                core::slice::from_raw_parts_mut(pointer.base.as_mut_ptr(), entry_count)
            },
        }
    }

    pub fn pointer(&self) -> DescriptorTablePointer {
        DescriptorTablePointer {
            base: VirtAddr::new(self.table.as_ptr() as u64),
            limit: (self.table.len() * size_of::<u64>() - 1) as u16,
        }
    }

    pub fn sgdt() -> DescriptorTablePointer {
        let mut gdt_ptr = DescriptorTablePointer {
            limit: 0,
            base: VirtAddr::new(0),
        };
        unsafe {
            core::arch::asm!("sgdt [{0}]", in(reg) &mut gdt_ptr, options(nostack, preserves_flags));
        }
        gdt_ptr
    }
}

impl core::ops::Index<usize> for GdtStruct {
    type Output = u64;
    fn index(&self, idx: usize) -> &Self::Output {
        &self.table[idx]
    }
}

impl core::ops::IndexMut<usize> for GdtStruct {
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        &mut self.table[idx]
    }
}

impl Debug for GdtStruct {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("GdtStruct")
            .field("pointer", &self.pointer())
            .field("table", &self.table)
            .finish()
    }
}
