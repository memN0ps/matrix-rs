#![no_std]
#![feature(allocator_api)]
#![feature(new_uninit)]
#![feature(const_trait_impl)]
#![feature(const_mut_refs)]

use error::HypervisorError;
use support::Support;

use crate::{processor::{ProcessorExecutor}, vmm::Vmm};

mod msr_bitmap;
mod addresses;
mod ept;
mod vmm;
mod vmcs;
mod vcpu;
mod processor;
mod nt;
mod support;
mod error;


pub struct Hypervisor {
    vmm_context: Vmm,
    support: Support,
}

impl Hypervisor {
    
    pub fn new() -> Self {
        Self {
            vmm_context: Vmm::new(),
            support: Support::new(),
        }
    }

    pub fn vmm_init(&mut self) -> Result<(), HypervisorError> {
        //
        // 1) Intel Manual: 24.6 Discover Support for Virtual Machine Extension (VMX)
        //
        
        self.support.has_intel_cpu()?;
        log::info!("[+] CPU is Intel");
    
        self.support.has_vmx_support()?;
        log::info!("[+] Virtual Machine Extension (VMX) technology is supported");
    
        log::info!("[+] Initializing VMM Context");
    
        for index in 0..self.vmm_context.processor_count {
            log::info!("[+] Switching Processor: {}", index);
            
            let Some(executor) = ProcessorExecutor::switch_to_processor(index) else {
                return Err(HypervisorError::ProcessorSwitchFailed);
            };
    
            self.vmm_context.init_vcpu()?;
    
            //
            // 2) Intel Manual: 24.7 Enable and Enter VMX Operation
            //
            self.init_logical_processor(index as usize)?;
    
            core::mem::drop(executor);
        }
        Ok(())
    }

    /// Enable and Enter VMX Operation via VMXON and load current VMCS pointer via VMPTRLD
    pub fn init_logical_processor(&mut self, index: usize) -> Result<(), HypervisorError> {
        log::info!("[+] Enabling Virtual Machine Extensions (VMX)");
        self.vmm_context.enable_vmx_operation()?;

        log::info!("[+] Adjusting Control Registers");
        self.vmm_context.adjust_control_registers();

        log::info!("[+] init_vmxon");
        self.vmm_context.init_vmxon(index)?;

        log::info!("[+] init_vmclear");
        self.vmm_context.init_vmclear(index)?;

        log::info!("[+] init_vmcs");
        self.vmm_context.init_vmcs(index)?;

        log::info!("[+] init_msr_bitmap");
        self.vmm_context.init_msr_bitmap(index)?;

        Ok(())
    }

    /// Disable VMX operation using VMXOFF on each logical processor
    pub fn devirtualize(&self) -> Result<(), HypervisorError> {
        log::info!("[+] Devirtualizing");
        
        for index in 0..self.vmm_context.processor_count {
            log::info!("[+] Switching Processor: {}", index);

            let Some(executor) = ProcessorExecutor::switch_to_processor(index) else {
                return Err(HypervisorError::ProcessorSwitchFailed);
            };

            Support::vmxoff()?;
    
            core::mem::drop(executor);
        }

        Ok(())
    }


}

/// Call Drop and devirtualize
impl Drop for Hypervisor {
    fn drop(&mut self) {
        match self.devirtualize() {
            Ok(_) => log::info!("[+] Devirtualized successfully!"),
            Err(err) => log::error!("[-] Failed to dervirtualize {}", err),
        }
    }
}