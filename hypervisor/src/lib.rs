#![no_std]
#![feature(allocator_api)]
#![feature(new_uninit)]

use error::HypervisorError;
use vmx::Vmx;

use crate::{processor::{ProcessorExecutor}, vmm::Vmm};

mod vmm;
mod vmcs;
mod vcpu;
mod processor;
mod nt;
mod vmx;
mod error;


pub struct HypervisorBuilder {
    vmm_context: Vmm,
    vmx: Vmx,
}

impl HypervisorBuilder {
    
    pub fn new() -> Self {
        Self {
            vmm_context: Vmm::new(),
            vmx: Vmx::new(),
        }
    }

    pub fn vmm_init(&mut self) -> Result<(), HypervisorError> {
        //
        // 1) Intel Manual: 24.6 Discover Support for Virtual Machine Extension (VMX)
        //
        
        self.vmx.has_intel_cpu()?;
        log::info!("[+] CPU is Intel");
    
        self.vmx.has_vmx_support()?;
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

        log::info!("[+] init_vmcs");
        self.vmm_context.init_vmcs(index)?;

        Ok(())
    }

    /// Disable VMX operation using VMXOFF
    pub fn dervirtualize(&self) -> Result<(), HypervisorError> {
        log::info!("[+] Devirtualizing");
        
        for index in 0..self.vmm_context.processor_count {
            log::info!("[+] Switching Processor: {}", index);

            let Some(executor) = ProcessorExecutor::switch_to_processor(index) else {
                return Err(HypervisorError::ProcessorSwitchFailed);
            };

            self.vmm_context.vmxoff()?;
    
            core::mem::drop(executor);
        }

        Ok(())
    }


}


impl Drop for HypervisorBuilder {
    fn drop(&mut self) {
        match self.dervirtualize() {
            Ok(_) => log::info!("[+] Dervirtualized successfully!"),
            Err(err) => log::error!("[-] Failed to dervirtualize {}", err),
        }
    }
}