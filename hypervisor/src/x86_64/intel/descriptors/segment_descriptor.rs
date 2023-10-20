use crate::x86_64::intel::descriptors::descriptor_tables::DescriptorTables;
use bit_field::BitField;
use bitflags::bitflags;
use x86::dtables::DescriptorTablePointer;
use x86::segmentation::SegmentSelector;

bitflags! {
    /// Access rights for VMCS guest register states.
    ///
    /// Represents the segment access rights format as described in
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.4.1 Guest Register State and
    /// Table 24-2. Format of Access Rights.
    pub struct SegmentAccessRights: u32 {
        /// Accessed flag.
        ///
        /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5.1 Code- and Data-Segment Descriptor Types
        const ACCESSED          = 1 << 0;

        /// Readable (for code segments) or Writable (for data segments).
        ///
        /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5.1 Code- and Data-Segment Descriptor Types
        const RW                = 1 << 1;

        /// Conforming bit for code segments.
        ///
        /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5.1 Code- and Data-Segment Descriptor Types
        const CONFORMING        = 1 << 2;

        /// Executable bit. Must be set for code segments.
        ///
        /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5.1 Code- and Data-Segment Descriptor Types
        const EXECUTABLE        = 1 << 3;

        /// Descriptor type (0 = system; 1 = code or data).
        ///
        /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
        const CODE_DATA         = 1 << 4;

        /// Segment present.
        ///
        /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
        const PRESENT           = 1 << 7;

        /// Long mode active (for CS only).
        ///
        /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5.1 Code- and Data-Segment Descriptor Types
        const LONG_MODE         = 1 << 13;

        /// Default operation size (0 = 16-bit segment; 1 = 32-bit segment).
        ///
        /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
        const DB                = 1 << 14;

        /// Granularity.
        ///
        /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
        const GRANULARITY       = 1 << 15;

        /// Segment unusable (0 = usable; 1 = unusable).
        ///
        /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.4.1 Guest Register State
        const UNUSABLE          = 1 << 16;

        /// Privilege level mask (bits 5-6).
        ///
        /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
        const DPL_MASK          = 3 << 5;
    }
}

impl SegmentAccessRights {
    pub fn from_descriptor(desc: u64) -> Self {
        Self::from_bits_truncate(desc.get_bits(40..56) as u32 & 0xf0ff)
    }
}

/// Represents details of a segment descriptor in the GDT or LDT.
/// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
/// - Figure 3-8. Segment Descriptor
pub struct SegmentDescriptor {
    pub selector: SegmentSelector,
    pub base_address: u64,
    pub segment_limit: u32,
    pub access_rights: SegmentAccessRights,
}

impl SegmentDescriptor {
    pub const fn invalid() -> Self {
        Self {
            selector: SegmentSelector::empty(),
            base_address: 0,
            segment_limit: 0,
            access_rights: SegmentAccessRights::UNUSABLE,
        }
    }

    pub fn from_selector(selector: SegmentSelector, gdtr: &DescriptorTablePointer<u64>) -> Self {
        // Index calculation - Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.5.1 Segment Selectors
        let index = selector.index() as usize;

        // Using the GDTR to get the GDT table as an array of descriptors
        let table = DescriptorTables::from_pointer(gdtr);

        // Fetching the descriptor using the index
        let entry_value = table[index];

        // Checking the Present bit - Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
        let is_present = (entry_value >> 47) & 1 == 1;

        // Checking the S (Descriptor type) bit - Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
        let is_user_segment = (entry_value >> 44) & 1 == 1;

        // Checking the G (Granularity) bit - Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
        let is_granularity = (entry_value >> 55) & 1 == 1;

        if is_present {
            // Extracting the base address - Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
            let mut base = entry_value.get_bits(16..40) | entry_value.get_bits(56..64) << 24;

            // Extracting the limit - Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
            let mut limit = entry_value.get_bits(0..16) | entry_value.get_bits(48..52) << 16;

            if !is_user_segment {
                // If it's not a code or data segment (like TSS or LDT), we need to get the high 32-bits from the next entry
                // Intel® 64 and IA-32 Architectures Software Developer's Manual: 7.2.2 TSS Descriptor
                let high = table[index + 1];
                base += high << 32;
            }

            if is_granularity {
                // If granularity bit is set, scale the limit - Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
                limit = (limit << 12) | 0xfff;
            }

            // Construct the SegmentDescriptor
            Self {
                selector,
                base_address: base,
                segment_limit: limit as _,
                access_rights: SegmentAccessRights::from_descriptor(entry_value),
            }
        } else {
            // If the segment is not present, return an invalid segment
            Self::invalid()
        }
    }
}
