extern crate alloc;

use {
    super::vmx::Vmx,
    crate::{
        error::HypervisorError, intel::vmlaunch::launch_vm, println,
        utils::processor::current_processor_index,
    },
    alloc::boxed::Box,
    wdk_sys::{ntddk::RtlCaptureContext, _CONTEXT},
};

/// Atomic bitset used to track which processors have been virtualized.
static VIRTUALIZED_BITSET: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Represents a Virtual CPU (VCPU).
pub struct Vcpu {
    /// The index of the processor.
    index: u32,

    /// The VMX instance to prevent its premature deallocation.
    vmx: Box<Vmx>,
}

impl Vcpu {
    /// Creates a new VCPU for the given processor index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the processor.
    ///
    /// # Returns
    ///
    /// A result containing the created VCPU or an error if the creation fails.
    pub fn new(index: u32) -> Result<Self, HypervisorError> {
        println!("Creating processor {}", index);

        let vmx = Vmx::new()?;

        Ok(Self { index, vmx })
    }

    /// Virtualizes the CPU by capturing its context, enabling VMX operation, adjusting control registers, and executing VMXON, VMPTRLD, and VMLAUNCH.
    ///
    /// # Returns
    ///
    /// A result indicating success or an error if virtualization fails.
    pub fn virtualize_cpu(&mut self) -> Result<(), HypervisorError> {
        println!("Virtualizing processor {}", self.index);

        // Capture the current processor's context. The Guest will resume from this point since we capture and write this context to the guest state for each vcpu.
        println!("Capturing context");
        let mut context = unsafe { core::mem::zeroed::<_CONTEXT>() };

        unsafe { RtlCaptureContext(&mut context) };

        // Determine if we're operating as the Host (root) or Guest (non-root). Only proceed with system virtualization if operating as the Host.
        if !Self::is_virtualized() {
            // If we are here as Guest (non-root) then that will lead to undefined behavior (UB).
            println!("Preparing for virtualization");

            Self::set_virtualized();
            self.vmx.setup_virtualization(&context)?;
            println!("Virtualization complete for processor {}", self.index);

            println!("Dumping VMCS: {:#x?}", self.vmx.vmcs_region);
            println!("Dumping _CONTEXT: ");
            Self::print_context(&context);

            println!("Executing VMLAUNCH to run the guest until a VM-exit event occurs");
            unsafe { launch_vm() };
            // unreachable code: we should not be here
        }

        Ok(())
    }

    /// Gets the index of the current processor.
    ///
    /// # Returns
    ///
    /// The index of the processor.
    pub fn id(&self) -> u32 {
        self.index
    }

    /* Global Bitmap vs. Instance Variable approach. Which one is better and why? */

    /// Checks whether the current processor is already virtualized.
    ///
    /// # Returns
    ///
    /// A boolean indicating if the current processor is virtualized.
    pub fn is_virtualized() -> bool {
        let bit = 1 << current_processor_index();

        VIRTUALIZED_BITSET.load(core::sync::atomic::Ordering::Relaxed) & bit != 0
    }

    /// Marks the current processor as virtualized.
    pub fn set_virtualized() {
        let bit = 1 << current_processor_index();

        VIRTUALIZED_BITSET.fetch_or(bit, core::sync::atomic::Ordering::Relaxed);
    }

    /// Prints the context of the processor for debugging purposes.
    ///
    /// # Arguments
    ///
    /// * `context` - The context of the processor.
    fn print_context(context: &_CONTEXT) {
        /*
        println!("P1Home: {:#x}", context.P1Home);
        println!("P2Home: {:#x}", context.P2Home);
        println!("P3Home: {:#x}", context.P3Home);
        println!("P4Home: {:#x}", context.P4Home);
        println!("P5Home: {:#x}", context.P5Home);
        println!("P6Home: {:#x}", context.P6Home);
        println!("ContextFlags: {:#x}", context.ContextFlags);
        println!("MxCsr: {:#x}", context.MxCsr);
        */

        println!("SegCs: {:#x}", context.SegCs);
        println!("SegDs: {:#x}", context.SegDs);
        println!("SegEs: {:#x}", context.SegEs);
        println!("SegFs: {:#x}", context.SegFs);
        println!("SegGs: {:#x}", context.SegGs);
        println!("SegSs: {:#x}", context.SegSs);
        println!("EFlags: {:#x}", context.EFlags);
        println!("Dr0: {:#x}", context.Dr0);
        println!("Dr1: {:#x}", context.Dr1);
        println!("Dr2: {:#x}", context.Dr2);
        println!("Dr3: {:#x}", context.Dr3);
        println!("Dr6: {:#x}", context.Dr6);
        println!("Dr7: {:#x}", context.Dr7);
        println!("Rax: {:#x}", context.Rax);
        println!("Rcx: {:#x}", context.Rcx);
        println!("Rdx: {:#x}", context.Rdx);
        println!("Rbx: {:#x}", context.Rbx);
        println!("Rsp: {:#x}", context.Rsp);
        println!("Rbp: {:#x}", context.Rbp);
        println!("Rsi: {:#x}", context.Rsi);
        println!("Rdi: {:#x}", context.Rdi);
        println!("R8: {:#x}", context.R8);
        println!("R9: {:#x}", context.R9);
        println!("R10: {:#x}", context.R10);
        println!("R11: {:#x}", context.R11);
        println!("R12: {:#x}", context.R12);
        println!("R13: {:#x}", context.R13);
        println!("R14: {:#x}", context.R14);
        println!("R15: {:#x}", context.R15);
        println!("Rip: {:#x}", context.Rip);

        /*
        // Note: I'm skipping the __bindgen_anon_1 field as it might be a complex type.
        // If needed, you can add print statements for its subfields.
        for (i, vec_reg) in context.VectorRegister.iter().enumerate() {
            println!(
                "VectorRegister[{}]: Low: {:#x}, High: {:#x}",
                i, vec_reg.Low, vec_reg.High
            );
        }

        println!("VectorControl: {:#x}", context.VectorControl);
        println!("DebugControl: {:#x}", context.DebugControl);
        println!("LastBranchToRip: {:#x}", context.LastBranchToRip);
        println!("LastBranchFromRip: {:#x}", context.LastBranchFromRip);
        println!("LastExceptionToRip: {:#x}", context.LastExceptionToRip);
        println!("LastExceptionFromRip: {:#x}", context.LastExceptionFromRip);
        */
    }
}
