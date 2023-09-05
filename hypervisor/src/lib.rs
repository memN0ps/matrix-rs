#![no_std]
#![feature(allocator_api)]
#![feature(new_uninit)]
#![feature(const_trait_impl)]
#![feature(const_mut_refs)]
#![feature(naked_functions)]
#![feature(asm_const)]
#![feature(once_cell_try)]
#![feature(decl_macro)]

extern crate alloc;
use crate::{
    intel::{vcpu::Vcpu, vmexit::launch_vm},
    utils::processor::{processor_count, ProcessorExecutor},
};
use alloc::vec::Vec;
use error::HypervisorError;
use intel::vmexit::{CPUID_VENDOR_AND_MAX_FUNCTIONS, VENDOR_NAME};
use nt::{Context, RtlCaptureContext};
mod error;
mod intel;
mod nt;
mod utils;

pub struct Hypervisor {
    processors: Vec<Vcpu>,
}

impl Hypervisor {
    pub fn new(context: Context) -> Result<Self, HypervisorError> {
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.6 DISCOVERING SUPPORT FOR VMX */
        Self::has_intel_cpu()?;
        log::info!("[+] CPU is Intel");

        Self::has_vmx_support()?;
        log::info!("[+] Virtual Machine Extension (VMX) technology is supported");

        let mut processors: Vec<Vcpu> = Vec::new();

        for i in 0..processor_count() {
            processors.push(Vcpu::new(i, context)?);
        }
        log::info!("[+] Found {} processors", processors.len());

        Ok(Hypervisor { processors })
    }

    pub fn virtualize_system(&mut self) -> Result<(), HypervisorError> {
        log::info!("[+] Virtualizing processors");

        for processor in self.processors.iter_mut() {
            let Some(executor) = ProcessorExecutor::switch_to_processor(processor.id()) else {
                return Err(HypervisorError::ProcessorSwitchFailed);
            };

            if processor.is_virtualized() {
                log::info!("[+] Processor {} is already virtualized", processor.id());
                continue;
            }

            processor.virtualize_cpu()?;

            core::mem::drop(executor);
        }

        Ok(())
    }

    pub fn start_vm() {
        // Run the VM until the VM-exit occurs.
        log::info!("[+] Running the guest until VM-exit occurs.");
        unsafe { launch_vm() };
    }

    pub fn capture_registers() -> Context {
        // Contains processor-specific register data. The system uses CONTEXT structures to perform various internal operations.
        // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
        let mut context = unsafe { core::mem::zeroed::<Context>() };

        // The Guest will start running from here as we capture and vmwrite the context to the guest state per vcpu
        unsafe { RtlCaptureContext(&mut context) };

        return context;
    }

    /// Check if the hypervisor is already installed by checking the vendor name in the cpuid which is set in vmexit_handler -> handle_cpuid
    pub fn is_vendor_name_present() -> bool {
        let regs = x86::cpuid::cpuid!(CPUID_VENDOR_AND_MAX_FUNCTIONS);

        if (regs.ebx == VENDOR_NAME) && (regs.ecx == VENDOR_NAME) && (regs.edx == VENDOR_NAME) {
            return true;
        }

        return false;
    }

    /// Check to see if CPU is Intel (“GenuineIntel”).
    fn has_intel_cpu() -> Result<(), HypervisorError> {
        let cpuid = x86::cpuid::CpuId::new();
        if let Some(vi) = cpuid.get_vendor_info() {
            if vi.as_str() == "GenuineIntel" {
                return Ok(());
            }
        }
        Err(HypervisorError::CPUUnsupported)
    }

    /// Check processor supports for Virtual Machine Extension (VMX) technology - CPUID.1:ECX.VMX\[bit 5] = 1
    fn has_vmx_support() -> Result<(), HypervisorError> {
        let cpuid = x86::cpuid::CpuId::new();
        if let Some(fi) = cpuid.get_feature_info() {
            if fi.has_vmx() {
                return Ok(());
            }
        }
        Err(HypervisorError::VMXUnsupported)
    }

    /*
    pub fn devirtualize(&mut self) -> Result<(), HypervisorError> {
        log::info!("[+] Devirtualizing processors");

        for processor in self.processors.iter_mut() {
            let Some(executor) = ProcessorExecutor::switch_to_processor(processor.id()) else {
                return Err(HypervisorError::ProcessorSwitchFailed);
            };

            processor.devirtualize_cpu()?;

            core::mem::drop(executor);
        }

        Ok(())
    }
    */
}
