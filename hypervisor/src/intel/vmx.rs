//! This module provides an implementation for VMX-based virtualization.
//! It encapsulates the necessary components for VMX initialization and setup,
//! including the VMXON, VMCS, MSR Bitmap, and other relevant data structures.

use {
    // Super imports
    super::{msr_bitmap::MsrBitmap, vmcs::Vmcs, vmstack::VmStack, vmxon::Vmxon},
    // Internal crate usages
    crate::{
        error::HypervisorError,
        intel::descriptor::DescriptorTables,
        println,
        utils::alloc::{KernelAlloc, PhysicalAllocator},
    },

    // External crate usages
    alloc::boxed::Box,
    wdk_sys::_CONTEXT,
};

/// Represents the VMX structure which encapsulates the necessary components for VMX virtualization.
///
/// Memory Allocation Considerations:
/// - Boxed pointers for the Vmxon, Vmcs, MsrBitmap, and HostRsp structures are stored within the Vmx struct to ensure they aren't dropped prematurely.
/// - Rust's automatic memory management can be a pitfall; dropping a `Box` at high IRQL might trigger unintended deallocations.
#[repr(C, align(4096))]
pub struct Vmx {
    /// The virtual address of the Vmxon naturally aligned 4-KByte region of memory (MmAllocateContiguousMemorySpecifyCacheNode).
    pub vmxon_region: Box<Vmxon, PhysicalAllocator>,

    /// The virtual address of the Vmcs naturally aligned 4-KByte region of memory (MmAllocateContiguousMemorySpecifyCacheNode).
    pub vmcs_region: Box<Vmcs, PhysicalAllocator>,

    /// The virtual address of the MSR Bitmap naturally aligned 4-KByte region of memory (MmAllocateContiguousMemorySpecifyCacheNode).
    pub msr_bitmap: Box<MsrBitmap, PhysicalAllocator>,

    /// The virtual address of the Guest Descriptor Tables containing the GDT and IDT (ExAllocatePool / ExAllocatePoolWithTag).
    pub guest_descriptor_table: Box<DescriptorTables, KernelAlloc>,

    /// The virtual address of the Host Descriptor Tables containing the GDT and IDT (ExAllocatePool / ExAllocatePoolWithTag).
    pub host_descriptor_table: Box<DescriptorTables, KernelAlloc>,

    /// The virtual address of the VMCS_HOST_RSP naturally aligned 4-KByte region of memory (ExAllocatePool / ExAllocatePoolWithTag).
    pub host_rsp: Box<VmStack, KernelAlloc>,
}

impl Vmx {
    /// Creates a new instance of the `Vmx` struct.
    ///
    /// This function allocates and initializes the necessary structures for VMX virtualization.
    /// It ensures that the memory allocations required for VMX are performed safely and efficiently.
    ///
    /// Returns a `Result` with a boxed `Vmx` instance or an `HypervisorError`.
    pub fn new() -> Result<Box<Self>, HypervisorError> {
        println!("Setting up VMX");

        // Allocate memory for the hypervisor's needs
        let vmxon_region = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };
        let vmcs_region = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };
        let msr_bitmap = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };
        let mut guest_descriptor_table =
            unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };
        let mut host_descriptor_table =
            unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };
        let host_rsp = unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };

        // To capture the current GDT and IDT for the guest the order is important so we can setup up a new GDT and IDT for the host.
        // This is done here instead of `setup_virtualization` because it uses a vec to allocate memory for the new GDT
        DescriptorTables::initialize_for_guest(&mut guest_descriptor_table)?;
        DescriptorTables::initialize_for_host(&mut host_descriptor_table)?;

        println!("Creating Vmx instance");

        let instance = Self {
            vmxon_region,
            vmcs_region,
            msr_bitmap,
            guest_descriptor_table,
            host_descriptor_table,
            host_rsp,
        };

        let instance = Box::new(instance);

        println!("VMX setup successful!");

        Ok(instance)
    }

    /// Sets up the virtualization environment using the VMX capabilities.
    ///
    /// This function orchestrates the setup for VMX virtualization by initializing the VMXON, VMCS,
    /// MSR Bitmap, and other relevant data structures. It also configures the guest and host state
    /// in the VMCS as well as the VMCS control fields.
    ///
    /// # Arguments
    /// * `context` - The current execution context.
    ///
    /// Returns a `Result` indicating the success or failure of the setup process.
    pub fn setup_virtualization(&mut self, context: &_CONTEXT) -> Result<(), HypervisorError> {
        println!("Virtualization setup");

        Vmxon::setup(&mut self.vmxon_region)?;
        Vmcs::setup(&mut self.vmcs_region)?;
        MsrBitmap::setup(&mut self.msr_bitmap)?;
        VmStack::setup(&mut self.host_rsp)?;

        // Set the self_data pointer to the instance. This can be used in the vmexit_handler to retrieve the instance.
        // instance.host_rsp.self_data = &mut *instance as *mut _ as _;

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.4 GUEST-STATE AREA */
        println!("Setting up Guest Registers State");
        Vmcs::setup_guest_registers_state(&context, &self.guest_descriptor_table);
        println!("Guest Registers State successful!");

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.5 HOST-STATE AREA */
        println!("Setting up Host Registers State");
        Vmcs::setup_host_registers_state(&context, &self.host_descriptor_table, &self.host_rsp);
        println!("Host Registers State successful!");

        /*
         * VMX controls:
         * Intel® 64 and IA-32 Architectures Software Developer's Manual references:
         * - 25.6 VM-EXECUTION CONTROL FIELDS
         * - 25.7 VM-EXIT CONTROL FIELDS
         * - 25.8 VM-ENTRY CONTROL FIELDS
         */
        println!("Setting up VMCS Control Fields");
        Vmcs::setup_vmcs_control_fields(&self.msr_bitmap);
        println!("VMCS Control Fields successful!");

        println!("Virtualization setup successful!");
        Ok(())
    }
}
