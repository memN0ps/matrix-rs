extern crate alloc;

use crate::{
    error::HypervisorError,
    intel::{vmexit::launch_vm, vmx::Vmx},
    utils::context::Context,
};

pub struct Vcpu {
    /// The index of the processor.
    index: u32,

    /// Whether the processor is virtualized.
    is_virtualized: bool,

    context: Context,
}

impl Vcpu {
    pub fn new(index: u32, context: Context) -> Result<Self, HypervisorError> {
        log::info!("Creating processor {}", index);

        Ok(Self {
            index,
            is_virtualized: false,
            context,
        })
    }

    /// Virtualize the CPU by capturing the context, enabling VMX operation, adjusting control registers, calling VMXON, VMPTRLD and VMLAUNCH
    pub fn virtualize_cpu(&mut self) -> Result<(), HypervisorError> {
        log::info!("[+] Virtualizing processor {}", self.index);

        // Double check if the processor is already virtualized.
        if !self.is_virtualized {
            log::info!("[+] Preparing for virtualization");

            self.is_virtualized = true;

            log::info!("[+] Initializing VMX");
            let mut vmx = Vmx::new()?;

            vmx.init(self.context)?;

            // Run the VM until the VM-exit occurs.
            log::info!("[+] Running the guest until VM-exit occurs.");
            unsafe { launch_vm() };
        }

        Ok(())
    }

    /// Gets the index of the current logical/virtual processor
    pub fn id(&self) -> u32 {
        self.index
    }
}
