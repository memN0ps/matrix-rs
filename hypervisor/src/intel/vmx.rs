//! This module provides an implementation for VMX-based virtualization.
//! It encapsulates the necessary components for VMX initialization and setup,
//! including the Vmxon, Vmcs, MsrBitmap, DescriptorTables, and other relevant data structures.

use crate::intel::vmerror::VmInstructionError;
use {
    // Super imports
    super::{msr_bitmap::MsrBitmap, vmcs::Vmcs, vmxon::Vmxon},

    // Internal crate usages
    crate::{
        error::HypervisorError,
        intel::{
            descriptor::DescriptorTables, support::vmread, vmexit::VmExit, vmlaunch::launch_vm,
            vmlaunch::GuestRegisters,
        },
        utils::alloc::{KernelAlloc, PhysicalAllocator},
    },

    // External crate usages
    alloc::boxed::Box,
    wdk_sys::_CONTEXT,
    x86::{current::rflags::RFlags, vmx::vmcs},
};

/// Represents the VMX structure with essential components for VMX virtualization.
///
/// This structure contains the VMXON region, VMCS region, MSR bitmap, descriptor tables, and other vital data required for VMX operations.
///
/// # Memory Allocation Considerations
///
/// The boxed pointers for certain components within the `Vmx` structure ensure that they remain allocated throughout the VMX lifecycle.
/// - `PhysicalAllocator` utilizes `MmAllocateContiguousMemorySpecifyCacheNode` for memory operations.
/// - `KernelAlloc` utilizes `ExAllocatePool` or `ExAllocatePoolWithTag` for memory operations.
///
/// Care is taken to prevent premature deallocations, especially at high IRQLs.
#[repr(C, align(4096))]
pub struct Vmx {
    /// Virtual address of the VMXON region, aligned to a 4-KByte boundary.
    /// Allocated using `MmAllocateContiguousMemorySpecifyCacheNode`.
    pub vmxon_region: Box<Vmxon, PhysicalAllocator>,

    /// Virtual address of the VMCS region, aligned to a 4-KByte boundary.
    /// Allocated using `MmAllocateContiguousMemorySpecifyCacheNode`.
    pub vmcs_region: Box<Vmcs, PhysicalAllocator>,

    /// Virtual address of the MSR bitmap, aligned to a 4-KByte boundary.
    /// Allocated using `MmAllocateContiguousMemorySpecifyCacheNode`.
    pub msr_bitmap: Box<MsrBitmap, PhysicalAllocator>,

    /// Virtual address of the guest's descriptor tables, including GDT and IDT.
    /// Allocated using `ExAllocatePool` or `ExAllocatePoolWithTag`.
    pub guest_descriptor_table: Box<DescriptorTables, KernelAlloc>,

    /// Virtual address of the host's descriptor tables, including GDT and IDT.
    /// Allocated using `ExAllocatePool` or `ExAllocatePoolWithTag`.
    pub host_descriptor_table: Box<DescriptorTables, KernelAlloc>,

    /// Registers capturing the guest's state during a VM exit.
    pub registers: GuestRegisters,

    /// Flag indicating the VM's launch status.
    pub launched: bool,
}

impl Vmx {
    /// Creates a new instance of the `Vmx` struct.
    ///
    /// This function allocates and initializes the necessary structures for VMX virtualization.
    /// It ensures that the memory allocations required for VMX are performed safely and efficiently.
    ///
    /// Returns a `Result` with a boxed `Vmx` instance or an `HypervisorError`.
    pub fn new() -> Result<Box<Self>, HypervisorError> {
        log::info!("Setting up VMX");

        // Allocate memory for the hypervisor's needs
        let vmxon_region = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };
        let vmcs_region = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };
        let msr_bitmap = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };
        let mut guest_descriptor_table =
            unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };
        let mut host_descriptor_table =
            unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };

        // To capture the current GDT and IDT for the guest the order is important so we can setup up a new GDT and IDT for the host.
        // This is done here instead of `setup_virtualization` because it uses a vec to allocate memory for the new GDT
        DescriptorTables::initialize_for_guest(&mut guest_descriptor_table)?;
        DescriptorTables::initialize_for_host(&mut host_descriptor_table)?;

        let registers = GuestRegisters::default();
        let launched = false;

        log::info!("Creating Vmx instance");

        let instance = Self {
            vmxon_region,
            vmcs_region,
            msr_bitmap,
            guest_descriptor_table,
            host_descriptor_table,
            registers,
            launched,
        };

        let instance = Box::new(instance);

        log::info!("VMX setup successful!");

        Ok(instance)
    }

    /// Sets up the virtualization environment using the VMX capabilities.
    ///
    /// This function orchestrates the setup for VMX virtualization by initializing the VMXON, Vmcs,
    /// MsrBitmap, and other relevant data structures. It also configures the guest and host state
    /// in the VMCS as well as the VMCS control fields.
    ///
    /// # Arguments
    /// * `context` - The current execution context.
    ///
    /// Returns a `Result` indicating the success or failure of the setup process.
    pub fn setup_virtualization(&mut self, context: &_CONTEXT) -> Result<(), HypervisorError> {
        log::info!("Virtualization setup");

        Vmxon::setup(&mut self.vmxon_region)?;
        Vmcs::setup(&mut self.vmcs_region)?;
        MsrBitmap::setup(&mut self.msr_bitmap)?;

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.4 GUEST-STATE AREA */
        log::info!("Setting up Guest Registers State");
        Vmcs::setup_guest_registers_state(
            &context,
            &self.guest_descriptor_table,
            &mut self.registers,
        );
        log::info!("Guest Registers State successful!");

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.5 HOST-STATE AREA */
        log::info!("Setting up Host Registers State");
        Vmcs::setup_host_registers_state(&context, &self.host_descriptor_table);
        log::info!("Host Registers State successful!");

        /*
         * VMX controls:
         * Intel® 64 and IA-32 Architectures Software Developer's Manual references:
         * - 25.6 VM-EXECUTION CONTROL FIELDS
         * - 25.7 VM-EXIT CONTROL FIELDS
         * - 25.8 VM-ENTRY CONTROL FIELDS
         */
        log::info!("Setting up VMCS Control Fields");
        Vmcs::setup_vmcs_control_fields(&self.msr_bitmap);
        log::info!("VMCS Control Fields successful!");

        log::info!("Virtualization setup successful!");
        Ok(())
    }

    /// Executes the Virtual Machine (VM) and handles VM-exits.
    ///
    /// This method will continuously execute the VM until a VM-exit event occurs. Upon VM-exit,
    /// it updates the VM state, interprets the VM-exit reason, and handles it appropriately.
    /// The loop continues until an unhandled or error-causing VM-exit is encountered.
    pub fn run(&mut self) {
        log::info!("Executing VMLAUNCH to run the guest until a VM-exit event occurs");

        loop {
            // Run the VM until the VM-exit occurs.
            let flags = unsafe { launch_vm(&mut self.registers, u64::from(self.launched)) };

            // Verify that the `launch_vm` was executed successfully, otherwise panic.
            Self::vm_succeed(RFlags::from_raw(flags));

            self.launched = true;

            // VM-exit occurred. Copy the guest register values from VMCS so that
            // `self.registers` is complete and up to date.
            self.registers.rip = vmread(vmcs::guest::RIP);
            self.registers.rsp = vmread(vmcs::guest::RSP);
            self.registers.rflags = vmread(vmcs::guest::RFLAGS);

            log::info!("VMEXIT occurred at RIP: {:#x}", self.registers.rip);
            log::info!("VMEXIT occurred at RSP: {:#x}", self.registers.rsp);
            log::info!("RFLAGS: {:#x}", self.registers.rflags);

            // Handle VM-exit by translating it to the `VmExitReason` type.
            let vmexit = VmExit::new();

            // Handle the VM exit.
            if let Err(e) = vmexit.handle_vmexit(&mut self.registers) {
                log::error!("Error handling VMEXIT: {:?}", e);
                break;
            }
        }
    }

    /// Verifies that the `launch_vm` function executed successfully.
    ///
    /// This method checks the RFlags for indications of failure from the `launch_vm` function.
    /// If a failure is detected, it will panic with a detailed error message.
    ///
    /// # Arguments
    ///
    /// * `flags`: The RFlags value post-execution of the `launch_vm` function.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual:
    /// - 31.2 CONVENTIONS
    /// - 31.4 VM INSTRUCTION ERROR NUMBERS
    fn vm_succeed(flags: RFlags) {
        if flags.contains(RFlags::FLAGS_ZF) {
            let instruction_error = vmread(vmcs::ro::VM_INSTRUCTION_ERROR) as u32;
            match VmInstructionError::from_u32(instruction_error) {
                Some(error) => panic!("VM instruction failed due to error: {}", error),
                None => panic!("Unknown VM instruction error: {:#x}", instruction_error),
            };
        } else if flags.contains(RFlags::FLAGS_CF) {
            panic!("VM instruction failed due to carry flag being set");
        }
    }
}
