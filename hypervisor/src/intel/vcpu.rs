extern crate alloc;
use alloc::boxed::Box;

use crate::{error::HypervisorError, intel::vmx::Vmx};

pub struct Vcpu {
    /// The index of the processor.
    index: u32,
}

impl Vcpu {
    pub fn new(index: u32) -> Result<Self, HypervisorError> {
        log::trace!("Creating processor {}", index);

        Ok(Self { index })
    }

    /// Virtualize the CPU by capturing the context, enabling VMX operation, adjusting control registers, calling VMXON, VMPTRLD and VMLAUNCH
    pub fn virtualize_cpu(&mut self) -> Result<(), HypervisorError> {
        log::info!("[+] Initializing VMX");
        let vmx = Vmx::new()?;
        let mut vmx_box = Box::new(vmx);

        vmx_box.run()?;

        Ok(())
    }

    /// Gets the index of the current logical/virtual processor
    pub fn id(&self) -> u32 {
        self.index
    }
}
