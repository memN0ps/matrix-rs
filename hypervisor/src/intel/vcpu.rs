extern crate alloc;

use {
    super::vmx::Vmx,
    crate::{
        error::HypervisorError, intel::vmlaunch::launch_vm, println,
        utils::processor::current_processor_index,
    },
    alloc::boxed::Box,
    core::cell::OnceCell,
    wdk_sys::{ntddk::RtlCaptureContext, _CONTEXT},
};

pub struct Vcpu {
    /// The index of the processor.
    index: u32,

    /// The bitmap used to track which processor has been virtualized.
    //virtualized_bitset: core::sync::atomic::AtomicU64,

    /// The VMX instance to prevent its premature deallocation.
    vmx: OnceCell<Box<Vmx>>,
}

impl Vcpu {
    pub fn new(index: u32) -> Result<Self, HypervisorError> {
        println!("Creating processor {}", index);

        Ok(Self {
            index,
            //virtualized_bitset: core::sync::atomic::AtomicU64::new(0),
            vmx: OnceCell::new(),
        })
    }

    /// Virtualize the CPU by capturing the context, enabling VMX operation, adjusting control registers, calling VMXON, VMPTRLD and VMLAUNCH
    pub fn virtualize_cpu(&mut self) -> Result<(), HypervisorError> {
        //println!("Virtualizing processor {}", self.index);

        // Capture the current processor's context. The Guest will resume from this point since we capture and write this context to the guest state for each vcpu.
        //println!("Capturing context");
        let mut context = unsafe { core::mem::zeroed::<_CONTEXT>() };

        unsafe { RtlCaptureContext(&mut context) };

        // Determine if we're operating as the Host (root) or Guest (non-root). Only proceed with system virtualization if operating as the Host.
        if !is_virtualized() {
            println!("Preparing for virtualization");

            set_virtualized();

            let vmx_box = Vmx::new(context)?;
            let vmx_ref = self.vmx.get_or_init(|| vmx_box);

            println!("Virtualization complete for processor {}", self.index);

            //vmx_ref.vmcs_region.dump_vmcs();
            println!("{:#x?}", vmx_ref.vmcs_region);
            //println!("{:#x?}", context);

            // Run the VM until the VM-exit occurs.
            println!("Executing VMLAUNCH to run the guest until a VM-exit event occurs");
            unsafe { launch_vm() };
            // unreachable code: we should not be here
        }

        Ok(())
    }

    /// Gets the index of the current processor
    pub fn id(&self) -> u32 {
        self.index
    }

    /*
    /// Checks whether the current process is already virtualized.
    pub fn is_virtualized(&self) -> bool {
        let bit = 1 << self.index;

        self.virtualized_bitset
            .load(core::sync::atomic::Ordering::Relaxed)
            & bit
            != 0
    }

    /// Marks the current processor as virtualized.
    pub fn set_virtualized(&self) {
        let bit = 1 << self.index;

        self.virtualized_bitset
            .fetch_or(bit, core::sync::atomic::Ordering::Relaxed);
    }
    */
}

// Global Bitmap vs. Instance Variable approach. Which one is better and why?
/// The bitmap used to track which processor has been virtualized.
static VIRTUALIZED_BITSET: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Checks whether the current process is already virtualized.
pub fn is_virtualized() -> bool {
    let bit = 1 << current_processor_index();

    VIRTUALIZED_BITSET.load(core::sync::atomic::Ordering::Relaxed) & bit != 0
}

/// Marks the current processor as virtualized.
pub fn set_virtualized() {
    let bit = 1 << current_processor_index();

    VIRTUALIZED_BITSET.fetch_or(bit, core::sync::atomic::Ordering::Relaxed);
}
