use crate::x86_64::utils::x86_instructions::{sgdt, sidt};
use crate::{error::HypervisorError, println};
use alloc::boxed::Box;
use alloc::vec::Vec;
use kernel_alloc::KernelAlloc;
use x86::dtables::DescriptorTablePointer;

/// Represents the descriptor tables (GDT and IDT) for the host.
/// Contains the GDT and IDT along with their respective register pointers.
#[repr(C, align(4096))]
pub struct DescriptorTables {
    /// Global Descriptor Table (GDT) for the host.
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 3.5.1 Segment Descriptor Tables
    pub global_descriptor_table: Vec<u64>,

    /// GDTR holds the address and size of the GDT.
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 2.4.1 Global Descriptor Table Register (GDTR)
    pub gdtr: DescriptorTablePointer<u64>,

    /// Interrupt Descriptor Table (IDT) for the host.
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 6.10 INTERRUPT DESCRIPTOR TABLE (IDT)
    pub interrupt_descriptor_table: Vec<u64>,

    /// IDTR holds the address and size of the IDT.
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 2.4.3 IDTR Interrupt Descriptor Table Register
    pub idtr: DescriptorTablePointer<u64>,
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

        // Get the current GDTR
        let current_gdtr = sgdt();

        // Create a slice from the current GDT entries.
        let current_gdt = unsafe {
            core::slice::from_raw_parts(
                current_gdtr.base.cast::<u64>(),
                usize::from(current_gdtr.limit + 1) / core::mem::size_of::<u64>(),
            )
        };

        // Create a new GDT from the slice.
        let new_gdt = current_gdt.to_vec();

        // Create a new GDTR from the new GDT.
        let new_gdtr = DescriptorTablePointer::new_from_slice(new_gdt.as_slice());

        // Store the new GDT in the DescriptorTables structure
        self.global_descriptor_table = new_gdt;
        self.gdtr = new_gdtr;
        println!("Copied current GDT");
    }

    /// Copies the current IDT.
    fn copy_current_idt(&mut self) {
        println!("Copying current IDT");

        // Get the current IDTR
        let current_idtr = sidt();

        // Create a slice from the current IDT entries.
        let current_idt: &[u64] = unsafe {
            core::slice::from_raw_parts(
                current_idtr.base.cast::<u64>(),
                (current_idtr.limit + 1) as usize / core::mem::size_of::<u64>(),
            )
        };

        // Create a new IDT from the slice.
        let new_idt = current_idt.to_vec();

        // Create a new IDTR from the new IDT.
        let new_idtr = DescriptorTablePointer::new_from_slice(new_idt.as_slice());

        // Store the new IDT in the DescriptorTables structure
        self.interrupt_descriptor_table = new_idt;
        self.idtr = new_idtr; // Use the same IDTR as it points to the correct base and limit
        println!("Copied current IDT");
    }

    /// Get the table as slice from the pointer.
    pub fn from_pointer(pointer: &DescriptorTablePointer<u64>) -> &[u64] {
        unsafe {
            core::slice::from_raw_parts(
                pointer.base.cast::<u64>(),
                (pointer.limit + 1) as usize / core::mem::size_of::<u64>(),
            )
        }
    }
}
