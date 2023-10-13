use crate::x86_64::utils::x86_instructions::sgdt;
use x86_64::registers::segmentation::SegmentSelector;

/// Represents details of a segment descriptor in the GDT or LDT.
/// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
/// - Figure 3-8. Segment Descriptor
pub struct SegmentDescriptor {
    /// Base address of the segment.
    pub base_address: u64,

    /// Segment limit defines the size of the segment.
    pub segment_limit: u32,

    /// Access rights and type of the segment.
    pub access_rights: u32,
}

impl SegmentDescriptor {
    /// Constructs a SegmentDescriptor from a given segment selector.
    /// Retrieves the base, limit, and access rights from the specified selector.
    pub fn from(selector: SegmentSelector) -> Self {
        // Fetch the GDTR to locate the GDT in memory.
        let gdtr = sgdt();

        // Calculate the index into the GDT for the given selector.
        let idx = selector.index();

        // Dereference the GDT to get the descriptor for the given index.
        let descriptor = unsafe { *((gdtr.base as u64 as *const u64).add(idx as usize)) };

        // Extract the base address, segment limit, and access rights following the layout specified in the Intel Manual.
        let base_address = ((descriptor >> 16) & 0xFFFFFF) | ((descriptor >> 32) & 0xFF000000);
        let segment_limit = (descriptor & 0xFFFF) | ((descriptor >> 32) & 0xF0000);
        let access_rights = ((descriptor >> 40) & 0xFF) | ((descriptor >> 52) & 0xF00);

        Self {
            base_address,
            segment_limit: segment_limit as u32,
            access_rights: access_rights as u32,
        }
    }
}
