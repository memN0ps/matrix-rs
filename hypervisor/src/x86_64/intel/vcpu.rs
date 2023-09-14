use {alloc::boxed::Box, core::cell::OnceCell};
extern crate alloc;

use super::{
    vmexit::{CPUID_VENDOR_AND_MAX_FUNCTIONS, VENDOR_NAME},
    vmx::Vmx,
};

use crate::{
    error::HypervisorError,
    x86_64::{
        intel::launch::launch_vm,
        utils::nt::{Context, RtlCaptureContext},
    },
};

pub struct Vcpu {
    /// The index of the processor.
    index: u32,

    /// Whether the processor is virtualized.
    is_virtualized: bool,

    /// The VMX instance. Store to avoid dropping it.
    vmx: OnceCell<Box<Vmx>>,
}

impl Vcpu {
    pub fn new(index: u32) -> Result<Self, HypervisorError> {
        log::info!("Creating processor {}", index);

        Ok(Self {
            index,
            is_virtualized: false,
            vmx: OnceCell::new(),
        })
    }

    /// Virtualize the CPU by capturing the context, enabling VMX operation, adjusting control registers, calling VMXON, VMPTRLD and VMLAUNCH
    pub fn virtualize_cpu(&mut self) -> Result<(), HypervisorError> {
        log::info!("[+] Virtualizing processor {}", self.index);

        // Capture the context of the current processor. The Guest will start running from here as we capture and vmwrite the context to the guest state per vcpu
        log::info!("[+] Capturing context");
        let context = self.capture_registers();

        // Check if we are running as Host (root operation) or Guest (non-root operation) by checking the vendor name in the cpuid which is set in vmexit_handler -> handle_cpuid
        // Virtualize the system only if the hypervisor is running as Host (root operation)
        if !self.is_virtualized() {
            let vmx_box = Vmx::new(context)?;

            self.vmx.get_or_init(|| vmx_box);

            log::info!("[+] Virtualization complete for processor {}", self.index);

            // Run the VM until the VM-exit occurs.
            log::info!("[+] Running the guest until VM-exit occurs.");
            unsafe { launch_vm() };
            // unreachable code: we should not be here
        }

        Ok(())
    }

    /// Gets the index of the current logical/virtual processor
    pub fn id(&self) -> u32 {
        self.index
    }

    /// Checks if the processor is virtualized by checking the vendor name in the cpuid which is set in vmexit_handler -> handle_cpuid
    pub fn is_virtualized(&mut self) -> bool {
        let regs = x86::cpuid::cpuid!(CPUID_VENDOR_AND_MAX_FUNCTIONS);

        if (regs.ebx == VENDOR_NAME) && (regs.ecx == VENDOR_NAME) && (regs.edx == VENDOR_NAME) {
            self.is_virtualized = true;
        } else {
            self.is_virtualized = false;
        }

        return self.is_virtualized;
    }

    /// Capture the state of the registers (context) for the current processor.
    pub fn capture_registers(&self) -> Context {
        // Contains processor-specific register data. The system uses CONTEXT structures to perform various internal operations.
        // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
        let mut context = unsafe { core::mem::zeroed::<Context>() };

        // The Guest will start running from here as we capture and vmwrite the context to the guest state per vcpu
        unsafe { RtlCaptureContext(&mut context) };

        return context;
    }
}
