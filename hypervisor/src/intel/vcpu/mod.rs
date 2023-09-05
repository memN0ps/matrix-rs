extern crate alloc;

use crate::{error::HypervisorError, intel::vmx::Vmx, nt::Context};

pub struct Vcpu {
    /// The index of the processor.
    index: u32,

    /// Whether the processor is virtualized.
    is_virtualized: bool,

    /// The context of the processor.
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
        log::info!("[+] Preparing for virtualization");
        let mut vmx = Vmx::new()?;
        vmx.init(self.context)?;

        log::info!("[+] Virtualization complete for processor {}", self.index);
        self.is_virtualized = true;

        Ok(())
    }

    /// Gets the index of the current logical/virtual processor
    pub fn id(&self) -> u32 {
        self.index
    }

    /// Checks if the processor is virtualized
    pub fn is_virtualized(&self) -> bool {
        self.is_virtualized
    }
}
