use alloc::boxed::Box;
use kernel_alloc::KernelAlloc;
use x86_64::structures::{
    gdt::GlobalDescriptorTable, idt::InterruptDescriptorTable, DescriptorTablePointer,
};

use crate::x86_64::utils::x86_instructions::{sgdt, sidt};
use crate::{error::HypervisorError, println};

/// Represents the descriptor tables (GDT and IDT) for the host.
/// Contains the GDT and IDT along with their respective register pointers.
pub struct DescriptorTables {
    /// Global Descriptor Table (GDT) for the host.
    /// Reference: Intel Manual, Volume 3A, Chapter 3.5.1
    pub global_descriptor_table: GlobalDescriptorTable,

    /// GDTR holds the address and size of the GDT.
    /// Reference: Intel Manual, Volume 3A, Chapter 2.4.1
    pub gdtr: DescriptorTablePointer,

    /// Interrupt Descriptor Table (IDT) for the host.
    /// Reference: Intel Manual, Volume 3A, Chapter 6.10
    pub interrupt_descriptor_table: InterruptDescriptorTable,

    /// IDTR holds the address and size of the IDT.
    /// Reference: Intel Manual, Volume 3A, Chapter 2.4.3
    pub idtr: DescriptorTablePointer,
}

impl DescriptorTables {
    /// Captures the currently loaded GDT and IDT for the guest.
    pub fn initialize_for_guest() -> Result<Box<Self, KernelAlloc>, HypervisorError> {
        println!("Capturing current Global Descriptor Table (GDT) and Interrupt Descriptor Table (IDT) for guest");

        // Create a DescriptorTables instance with the current GDT and IDT.
        let mut descriptor_tables: Box<DescriptorTables, KernelAlloc> =
            unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };

        // Capture the current GDT and IDT.
        descriptor_tables.gdtr = sgdt();
        descriptor_tables.idtr = sidt();

        // Note: We don't need to create new tables for the guest;
        // we just capture the current ones.

        println!("Captured GDT and IDT for guest successfully!");

        Ok(descriptor_tables)
    }

    /// Initializes and returns the descriptor tables (GDT and IDT) for the host.
    pub fn initialize_for_host() -> Result<Box<Self, KernelAlloc>, HypervisorError> {
        println!("Initializing descriptor tables for host");
        let mut tables: Box<DescriptorTables, KernelAlloc> =
            unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };

        tables.copy_current_gdt();
        tables.copy_current_idt();

        println!("Initialized descriptor tables for host");
        Ok(tables)
    }

    /// Copies the current GDT.
    fn copy_current_gdt(&mut self) {
        println!("Copying current GDT");
        let current_gdtr = sgdt();
        let gdt_size = (current_gdtr.limit + 1) as usize / core::mem::size_of::<u64>();
        let gdt_base = current_gdtr.base.as_ptr::<u64>();

        // Create a slice from the current GDT entries.
        let gdt_slice: &[u64] = unsafe { core::slice::from_raw_parts(gdt_base, gdt_size) };

        // Create a new GDT from the slice.
        let new_gdt = unsafe { GlobalDescriptorTable::from_raw_slice(gdt_slice) };

        println!("Loading new GDT");
        // Load the new GDT
        unsafe { new_gdt.load_unsafe() };

        // Update the DescriptorTables with the new GDT
        self.global_descriptor_table = new_gdt;
        self.gdtr = current_gdtr; // Use the same GDTR as it points to the correct base and limit
        println!("Copied current GDT");
    }

    /// Copies the current IDT.
    fn copy_current_idt(&mut self) {
        println!("Copying current IDT");
        let current_idtr = sidt();
        let idt_size = (current_idtr.limit + 1) as usize / core::mem::size_of::<u64>();
        let idt_base = current_idtr.base.as_ptr::<u64>();

        let mut new_idt = InterruptDescriptorTable::new();

        // Copy entries from the current IDT to the new IDT
        unsafe {
            core::ptr::copy_nonoverlapping(idt_base, &mut new_idt as *mut _ as *mut u64, idt_size);
        }

        // Store the new IDT in the DescriptorTables structure
        self.interrupt_descriptor_table = new_idt;
        self.idtr = current_idtr; // Use the same IDTR as it points to the correct base and limit
        println!("Copied current IDT");
    }
}
