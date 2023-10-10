use alloc::boxed::Box;
use kernel_alloc::PhysicalAllocator;
use x86_64::structures::{
    gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector},
    idt::InterruptDescriptorTable,
    DescriptorTablePointer,
};

use crate::{println, error::HypervisorError};

/// The `DescriptorTables` structure contains the GDT and IDT for either the host or guest.
/// For the host:
/// - The GDT and IDT are already set up and loaded by the operating system. When a VM exit occurs,
///   the processor will use the host's GDT and IDT to continue executing the host code correctly.
///
/// For the guest:
/// - Instead of directly loading the GDT and IDT using the `load()` method, the base and limit
///   of the GDT and IDT are set in the VMCS. The processor will then use these values when it
///   switches to the guest state during a VM entry.
pub struct DescriptorTables {
    pub gdt: Option<GlobalDescriptorTable>,
    pub idt: Option<InterruptDescriptorTable>,
    pub gdtr: DescriptorTablePointer,
    pub idtr: DescriptorTablePointer,
}

impl DescriptorTables {
    /// Retrieves the current GDTR and IDTR without trying to convert them to GDT or IDT objects.
    pub fn current_for_guest() -> Result<Box<Self, PhysicalAllocator>, HypervisorError> {
        let mut descriptor_tables: Box<DescriptorTables, PhysicalAllocator> = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };

        descriptor_tables.gdtr = Self::get_gdtr();
        descriptor_tables.idtr = Self::get_idtr();
        
        Ok(descriptor_tables)
    }

    /// Retrieves the current GDT and IDT for the host.
    pub fn new_for_host() -> Result<Box<Self, PhysicalAllocator>, HypervisorError> {
        let mut descriptor_tables: Box<DescriptorTables, PhysicalAllocator> = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };

        // Initializes a new GDT, which inherently contains the null descriptor as its initial entry.
        println!("Setting up Global Descriptor Table");
        descriptor_tables.gdt = Some(GlobalDescriptorTable::new());

        descriptor_tables.gdt.as_mut().unwrap().add_entry(Descriptor::kernel_code_segment());
        descriptor_tables.gdt.as_mut().unwrap().add_entry(Descriptor::kernel_data_segment());        

        // The user_code_segment and user_data_segment might not be necessary for this specific use case, but they are included here for completeness. Consider uncommenting them if they are needed.
        // descriptor_tables.gdt.add_entry(Descriptor::user_code_segment());
        // descriptor_tables.gdt.add_entry(Descriptor::user_data_segment());

        // For a hypervisor operating as a Windows driver, adding a TSS might not be necessary since Windows already sets up its own TSS. However, if you're working with UEFI, you might need to set up a TSS. Uncomment the following lines if required.
        /*
            let tss = x86_64::structures::tss::TaskStateSegment::new();
            let tss_entry = Descriptor::tss_segment(&tss);
            let tss_selector = descriptor_tables.gdt.add_entry(tss_entry);
        */

        // Creates a new IDT filled with non-present entries.
        println!("Setting up Interrupt Descriptor Table");
        descriptor_tables.idt = Some(InterruptDescriptorTable::new());

        // Set up interrupt handlers here if needed

        // Load the Global Descriptor Table Register (GDTR) using lgdt and the Interrupt Descriptor Table Register (IDTR) using lidt. These can be retrieved later using sgdt and sidt respectively.
        // The host's GDT and IDT are set by the OS. For the guest, the GDT and IDT base and limit are set in the VMCS, used during VM entry.
        // unsafe { descriptor_tables.gdt.load_unsafe() };
        // unsafe { descriptor_tables.idt.load_unsafe() };

        descriptor_tables.gdtr = Self::get_gdtr();
        descriptor_tables.idtr = Self::get_idtr();

        println!("Descriptor Tables successful!");

        Ok(descriptor_tables)
    }

    /// Returns the Global Descriptor Table register (GDTR).
    pub fn get_gdtr() -> DescriptorTablePointer {
        x86_64::instructions::tables::sgdt()
    }

    /// Returns the Interrupt Descriptor Table register (IDTR).
    pub fn get_idtr() -> DescriptorTablePointer {
        x86_64::instructions::tables::sidt()
    }
}

/// A structure to hold the details of a segment.
/// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
/// - Figure 3-8. Segment Descriptor
pub struct SegmentDescriptor {
    pub base: u64,
    pub limit: u32,
    pub access_rights: u32,
}

impl SegmentDescriptor {
    /// Retrieves the base, limit, and access rights of a segment selector.
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.4.5 Segment Descriptors
    /// - Figure 3-8. Segment Descriptor
    pub fn from(selector: SegmentSelector) -> SegmentDescriptor {
        // Get the Global Descriptor Table Register (GDTR)
        let gdtr = DescriptorTables::get_gdtr();

        // Calculate the index into the GDT for the given selector
        let idx = selector.index();

        // Dereference the GDT to get the descriptor
        let desc = unsafe { *((gdtr.base.as_u64() as *const u64).add(idx as usize)) };

        // Extract base, limit, and access rights from the descriptor
        // Refer to the Intel Manual for the exact bit positions and calculations
        let base = ((desc >> 16) & 0xFFFFFF) | ((desc >> 32) & 0xFF000000);
        let limit = (desc & 0xFFFF) | ((desc >> 32) & 0xF0000);
        let access_rights = ((desc >> 40) & 0xFF) | ((desc >> 52) & 0xF00);

        Self {
            base,
            limit: limit as u32,
            access_rights: access_rights as u32,
        }
    }
}
