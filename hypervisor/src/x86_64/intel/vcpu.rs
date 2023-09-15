use {alloc::boxed::Box, core::cell::OnceCell};
extern crate alloc;

use super::vmx::Vmx;

use crate::{
    error::HypervisorError,
    x86_64::{
        intel::launch::launch_vm,
        utils::nt::{Context, RtlCaptureContext},
    },
};

/// The bitmap used to track which processor has been virtualized.
//static VIRTUALIZED_BITSET: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub struct Vcpu {
    /// The index of the processor.
    index: u32,

    /// The bitmap used to track which processor has been virtualized.
    virtualized_bitset: core::sync::atomic::AtomicU64,

    /// The VMX instance to prevent its premature deallocation.
    vmx: OnceCell<Box<Vmx>>,
}

impl Vcpu {
    pub fn new(index: u32) -> Result<Self, HypervisorError> {
        log::info!("Creating processor {}", index);

        Ok(Self {
            index,
            virtualized_bitset: core::sync::atomic::AtomicU64::new(0),
            vmx: OnceCell::new(),
        })
    }

    /// Virtualize the CPU by capturing the context, enabling VMX operation, adjusting control registers, calling VMXON, VMPTRLD and VMLAUNCH
    pub fn virtualize_cpu(&mut self) -> Result<(), HypervisorError> {
        log::info!("Virtualizing processor {}", self.index);

        // Capture the current processor's context. The Guest will resume from this point since we capture and write this context to the guest state for each vcpu.
        log::info!("Capturing context");
        let context = self.capture_registers();

        // Determine if we're operating as the Host (root) or Guest (non-root). Only proceed with system virtualization if operating as the Host.
        if !self.is_virtualized() {
            log::info!("Preparing for virtualization");

            self.set_virtualized();

            let vmx_box = Vmx::new(context)?;
            self.vmx.get_or_init(|| vmx_box);

            log::info!("Virtualization complete for processor {}", self.index);

            // Run the VM until the VM-exit occurs.
            log::info!("Executing VMLAUNCH to run the guest until a VM-exit event occurs");
            unsafe { launch_vm() };
            // unreachable code: we should not be here
        }

        Ok(())
    }

    /// Gets the index of the current processor
    pub fn id(&self) -> u32 {
        self.index
    }

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

    /// Capture the current processor's context. The Guest will resume from this point since we capture and write this context to the guest state for each vcpu.
    pub fn capture_registers(&self) -> Context {
        let mut context = unsafe { core::mem::zeroed::<Context>() };

        unsafe { RtlCaptureContext(&mut context) };

        context
    }
}
