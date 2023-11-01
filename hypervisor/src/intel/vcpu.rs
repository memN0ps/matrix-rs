//! Module for handling Virtual CPU (VCPU) operations.
//! This module provides functionality to manage and control a virtualized CPU.
//! It provides mechanisms to virtualize a CPU, manage its state, and interact with its context.

extern crate alloc;

use {
    super::vmx::Vmx,
    crate::{error::HypervisorError, intel::support, utils::processor::current_processor_index},
    alloc::boxed::Box,
    wdk_sys::{ntddk::RtlCaptureContext, _CONTEXT},
};

/// Atomic bitset used to track which processors have been virtualized.
static VIRTUALIZED_BITSET: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Represents a Virtual CPU (VCPU) and its associated operations.
pub struct Vcpu {
    /// The processor's unique identifier.
    index: u32,

    /// The VMX instance associated with this VCPU.
    vmx: Box<Vmx>,
}

impl Vcpu {
    /// Creates and initializes a new VCPU instance for the specified processor index.
    ///
    /// # Arguments
    ///
    /// * `index` - Processor's unique identifier.
    ///
    /// # Returns
    ///
    /// A `Result` containing the initialized VCPU instance or a `HypervisorError`.
    pub fn new(index: u32) -> Result<Self, HypervisorError> {
        log::info!("Creating processor {}", index);

        let vmx = Vmx::new()?;

        Ok(Self { index, vmx })
    }

    /// Virtualizes the current CPU.
    ///
    /// Captures the CPU's context, initializes VMX operation, adjusts control registers, and
    /// executes VMXON, VMCLEAR, VMPTRLD, and VMLAUNCH.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the success or failure of the virtualization process.
    pub fn virtualize_cpu(&mut self) -> Result<(), HypervisorError> {
        //log::info!("Virtualizing processor {}", self.index);

        // Capture the current processor's context. The Guest will resume from this point since we capture and write this context to the guest state for each vcpu.
        //log::info!("Capturing context");
        let mut context = unsafe { core::mem::zeroed::<_CONTEXT>() };

        unsafe { RtlCaptureContext(&mut context) };

        // Determine if we're operating as the Host (root) or Guest (non-root). Only proceed with system virtualization if operating as the Host.
        if !Self::is_virtualized() {
            // If we are here as Guest (non-root) then that will lead to undefined behavior (UB).
            log::info!("Preparing for virtualization");

            Self::set_virtualized();
            self.vmx.setup_virtualization(&context)?;
            log::info!("Virtualization complete for processor {}", self.index);

            log::info!("Dumping VMCS: {:#x?}", self.vmx.vmcs_region);
            log::info!("Dumping _CONTEXT: ");
            Self::print_context(&context);

            self.vmx.run();

            // if we are here then something has failed and we want to gracefully exit;
            self.devirtualize_cpu()?;
        }

        Ok(())
    }

    /// Devirtualizes the current CPU.
    ///
    /// Attempts to turn off VMX operation for the processor on which it's called. If the processor is
    /// already in a non-root operation (devirtualized), the function will return early without performing
    /// the devirtualization again.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the success or failure of the operation. Returns `Ok(())` if the processor
    /// was successfully devirtualized or was already in a devirtualized state. Returns an `Err` if the
    /// `vmxoff` operation fails.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 30.3 VMXOFF—Leave VMX Operation.
    /// - Describes the `VMXOFF` instruction which is used to devirtualize a processor.
    pub fn devirtualize_cpu(&self) -> Result<(), HypervisorError> {
        // Determine if the processor is already devirtualized.
        if !Self::is_virtualized() {
            log::info!("Processor {} is already devirtualized", self.index);
            return Ok(());
        }

        // Attempt to devirtualize the processor using the VMXOFF instruction.
        support::vmxoff()?;
        log::info!("Processor {} has been devirtualized", self.index);

        Ok(())
    }

    /// Retrieves the processor's unique identifier.
    ///
    /// # Returns
    ///
    /// The processor's unique identifier.
    pub fn id(&self) -> u32 {
        self.index
    }

    /// Determines if the current processor is already virtualized.
    ///
    /// # Returns
    ///
    /// `true` if the processor is virtualized, otherwise `false`.
    pub fn is_virtualized() -> bool {
        let bit = 1 << current_processor_index();

        VIRTUALIZED_BITSET.load(core::sync::atomic::Ordering::Relaxed) & bit != 0
    }

    /// Marks the current processor as virtualized.
    pub fn set_virtualized() {
        let bit = 1 << current_processor_index();

        VIRTUALIZED_BITSET.fetch_or(bit, core::sync::atomic::Ordering::Relaxed);
    }

    /// Outputs the processor's context for debugging purposes.
    ///
    /// # Arguments
    ///
    /// * `context` - The context of the processor to be printed.
    fn print_context(context: &_CONTEXT) {
        /*
        log::info!("P1Home: {:#x}", context.P1Home);
        log::info!("P2Home: {:#x}", context.P2Home);
        log::info!("P3Home: {:#x}", context.P3Home);
        log::info!("P4Home: {:#x}", context.P4Home);
        log::info!("P5Home: {:#x}", context.P5Home);
        log::info!("P6Home: {:#x}", context.P6Home);
        log::info!("ContextFlags: {:#x}", context.ContextFlags);
        log::info!("MxCsr: {:#x}", context.MxCsr);
        */

        log::info!("SegCs: {:#x}", context.SegCs);
        log::info!("SegDs: {:#x}", context.SegDs);
        log::info!("SegEs: {:#x}", context.SegEs);
        log::info!("SegFs: {:#x}", context.SegFs);
        log::info!("SegGs: {:#x}", context.SegGs);
        log::info!("SegSs: {:#x}", context.SegSs);
        log::info!("EFlags: {:#x}", context.EFlags);
        log::info!("Dr0: {:#x}", context.Dr0);
        log::info!("Dr1: {:#x}", context.Dr1);
        log::info!("Dr2: {:#x}", context.Dr2);
        log::info!("Dr3: {:#x}", context.Dr3);
        log::info!("Dr6: {:#x}", context.Dr6);
        log::info!("Dr7: {:#x}", context.Dr7);
        log::info!("Rax: {:#x}", context.Rax);
        log::info!("Rcx: {:#x}", context.Rcx);
        log::info!("Rdx: {:#x}", context.Rdx);
        log::info!("Rbx: {:#x}", context.Rbx);
        log::info!("Rsp: {:#x}", context.Rsp);
        log::info!("Rbp: {:#x}", context.Rbp);
        log::info!("Rsi: {:#x}", context.Rsi);
        log::info!("Rdi: {:#x}", context.Rdi);
        log::info!("R8: {:#x}", context.R8);
        log::info!("R9: {:#x}", context.R9);
        log::info!("R10: {:#x}", context.R10);
        log::info!("R11: {:#x}", context.R11);
        log::info!("R12: {:#x}", context.R12);
        log::info!("R13: {:#x}", context.R13);
        log::info!("R14: {:#x}", context.R14);
        log::info!("R15: {:#x}", context.R15);
        log::info!("Rip: {:#x}", context.Rip);

        /*
        // Note: I'm skipping the __bindgen_anon_1 field as it might be a complex type.
        // If needed, you can add print statements for its subfields.
        for (i, vec_reg) in context.VectorRegister.iter().enumerate() {
            log::info!(
                "VectorRegister[{}]: Low: {:#x}, High: {:#x}",
                i, vec_reg.Low, vec_reg.High
            );
        }

        log::info!("VectorControl: {:#x}", context.VectorControl);
        log::info!("DebugControl: {:#x}", context.DebugControl);
        log::info!("LastBranchToRip: {:#x}", context.LastBranchToRip);
        log::info!("LastBranchFromRip: {:#x}", context.LastBranchFromRip);
        log::info!("LastExceptionToRip: {:#x}", context.LastExceptionToRip);
        log::info!("LastExceptionFromRip: {:#x}", context.LastExceptionFromRip);
        */
    }
}
