use alloc::boxed::Box;
use kernel_alloc::KernelAlloc;
use x86_64::structures::{
    gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector},
    idt::InterruptDescriptorTable,
    DescriptorTablePointer,
};

use crate::{error::HypervisorError, println};

#[repr(C, align(4096))]
pub struct DescriptorTable {
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.5.1 Segment Descriptor Tables
    /// - Figure 3-10. Global and Local Descriptor Tables
    pub gdt: GlobalDescriptorTable,

    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 2.4.1 Global Descriptor Table Register (GDTR)
    pub gdtr: DescriptorTablePointer,

    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 6.10 INTERRUPT DESCRIPTOR TABLE (IDT)
    /// - Figure 6-1. Relationship of the IDTR and IDT
    pub idt: InterruptDescriptorTable,

    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 2.4.3 IDTR Interrupt Descriptor Table Register
    pub idtr: DescriptorTablePointer,
}

impl DescriptorTable {
    /// Initializes a new Global Descriptor Table (GDT) and Interrupt Descriptor Table (IDT) for the guest and returns a DescriptorTable object.
    pub fn initialize_gdt_idt_for_guest() -> Result<Box<Self, KernelAlloc>, HypervisorError> {
        println!(
            "Setting up Guest Global Descriptor Table (GDT) and Interrupt Descriptor Table (IDT)"
        );
        let mut descriptor_tables: Box<DescriptorTable, KernelAlloc> =
            unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };

        descriptor_tables.gdt_for_guest();
        descriptor_tables.idt_for_guest();

        println!("Guest Global Descriptor Table (GDT) and Interrupt Descriptor Table (IDT) setup successful!");

        Ok(descriptor_tables)
    }

    /// Initializes a new Global Descriptor Table (GDT) and Interrupt Descriptor Table (IDT) for the host and returns a DescriptorTable object.
    pub fn initialize_gdt_idt_for_host() -> Result<Box<Self, KernelAlloc>, HypervisorError> {
        println!(
            "Setting up Host Global Descriptor Table (GDT) and Interrupt Descriptor Table (IDT)"
        );
        let mut descriptor_tables: Box<DescriptorTable, KernelAlloc> =
            unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };

        descriptor_tables.gdt_for_host();
        descriptor_tables.idt_for_host();

        println!("Host Global Descriptor Table (GDT) and Interrupt Descriptor Table (IDT) setup successful!");

        Ok(descriptor_tables)
    }

    /// Creates a new Global Descriptor Table (GDT) for the guest.
    pub fn gdt_for_guest(&mut self) {
        println!("Creating a new Global Descriptor Table (GDT) for the guest");
        // Get the current  Global Descriptor Table Register (GDTR).
        let current_gdtr = Self::get_gdtr();

        // Get the current Global Descriptor Table (GDT).
        let current_gdt = unsafe {
            core::slice::from_raw_parts(
                current_gdtr.base.as_ptr::<u64>(),
                usize::from(current_gdtr.limit + 1) / 8,
            )
        };

        // Copy the current Global Descriptor Table (GDT) into a new vector.
        let gdt_entires = current_gdt.to_vec();

        // Create a new GDT from the copied entries.
        let gdt = unsafe { GlobalDescriptorTable::from_raw_slice(gdt_entires.as_slice()) };

        // Update the Descriptor Table object.
        self.gdt = gdt;
        self.gdtr = Self::get_gdtr();
        println!("Global Descriptor Table (GDT) for the guest created successfully!");
    }

    /// Creates a new Global Descriptor Table (GDT) for the host.
    pub fn gdt_for_host(&mut self) {
        println!("Creating a new Global Descriptor Table (GDT) for the host");
        // Initializes a new GDT, which inherently contains the null descriptor as its initial entry.
        let mut gdt = GlobalDescriptorTable::new();
        gdt.add_entry(Descriptor::kernel_code_segment());
        gdt.add_entry(Descriptor::kernel_data_segment());

        // Load the new GDT
        unsafe { gdt.load_unsafe() };

        // Update the Descriptor Table object.
        self.gdt = gdt;
        self.gdtr = Self::get_gdtr();
        println!("Global Descriptor Table (GDT) for the host created successfully!");
    }

    /// Creates a new Interrupt Descriptor Table (IDT) for the guest.
    pub fn idt_for_guest(&mut self) {
        println!("Creating a new Interrupt Descriptor Table (IDT) for the guest");
        // Obtain the current IDTR (Interrupt Descriptor Table Register) value.
        // This register contains the base address and limit of the current IDT.
        let current_idtr = Self::get_idtr();

        // Calculate the number of entries in the current IDT.
        // The IDTR limit field contains the maximum offset within the IDT, so dividing by the entry size gives the entry count.
        let entry_count = (usize::from(current_idtr.limit) + 1)
            / core::mem::size_of::<InterruptDescriptorTable>();

        // Obtain a slice to the current IDT.
        // The slice starts at the base address of the IDT and has a length of entry_count.
        let current_idt = unsafe {
            core::slice::from_raw_parts(
                current_idtr.base.as_ptr::<InterruptDescriptorTable>(),
                entry_count,
            )
        };

        // Create a new IDT initialized with non-present entries.
        // This will be our new IDT that we'll eventually replace the current IDT with.
        let mut new_idt = InterruptDescriptorTable::new();

        // Perform a shallow copy of the current IDT to the new IDT.
        // This assumes that the memory layout of InterruptDescriptorTable matches the actual memory layout of the IDT.
        // A shallow copy is performed, so be cautious if the IDT contains any pointers or other resources.
        unsafe {
            core::ptr::copy_nonoverlapping(
                current_idt.as_ptr() as *const u8,
                &mut new_idt as *mut _ as *mut u8,
                usize::from(current_idtr.limit) + 1,
            );
        }

        // Load the new IDT
        unsafe { new_idt.load_unsafe() };

        // Update the idt field in your DescriptorTable object with the new IDT.
        self.idt = new_idt;
        println!("Interrupt Descriptor Table (IDT) for the guest created successfully!");
    }

    /// Creates a new Interrupt Descriptor Table (IDT) for the host.
    pub fn idt_for_host(&mut self) {
        println!("Creating a new Interrupt Descriptor Table (IDT) for the host");
        // Get the current Interrupt Descriptor Table Register (IDTR).
        let current_idtr = Self::get_idtr();

        // Create a new IDT filled with non-present entries.
        let mut new_idt = InterruptDescriptorTable::new();

        // Perform a shallow copy of the current IDT to the new IDT.
        // Note: Ensure the memory layout of InterruptDescriptorTable matches the actual memory layout of the IDT.
        unsafe {
            core::ptr::copy_nonoverlapping(
                current_idtr.base.as_ptr::<u8>(),
                &mut new_idt as *mut _ as *mut u8,
                usize::from(current_idtr.limit) + 1,
            );
        }

        // Update the idt field in your DescriptorTable object with the new IDT.
        self.idt = new_idt;
        println!("Interrupt Descriptor Table (IDT) for the host created successfully!");
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
    pub fn from(selector: SegmentSelector) -> SegmentDescriptor {
        // Get the Global Descriptor Table Register (GDTR)
        let gdtr = DescriptorTable::get_gdtr();

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
