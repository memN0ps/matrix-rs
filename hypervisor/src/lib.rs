#![no_std]
#![feature(allocator_api)]
#![feature(new_uninit)]
#![feature(const_trait_impl)]
#![feature(const_mut_refs)]
#![feature(naked_functions)]
#![feature(asm_const)]

use error::HypervisorError;

use crate::{processor::{ProcessorExecutor}, vmm::Vmm};

mod context;
mod vmexit_reason;
mod msr_bitmap;
mod addresses;
mod ept;
mod vmm;
mod vmcs_region;
mod vmxon_region;
mod vcpu;
mod processor;
mod nt;
mod support;
mod error;


pub struct Hypervisor {
    vmm_context: Vmm,
}

impl Hypervisor {
    
    pub fn new() -> Result<Self, HypervisorError> {
        Ok(Self {
            vmm_context: Vmm::new()?,
        })
    }

    pub fn vmm_init(&mut self) -> Result<(), HypervisorError> {
        //
        // 1) Intel Manual: 24.6 Discover Support for Virtual Machine Extension (VMX)
        //
        
        support::has_intel_cpu()?;
        log::info!("[+] CPU is Intel");
    
        support::has_vmx_support()?;
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
        support::enable_vmx_operation()?;

        log::info!("[+] Adjusting Control Registers");
        support::adjust_control_registers();

        log::info!("[+] init_vmxon");
        self.vmm_context.init_vmxon(index)?;

        log::info!("[+] init_vmclear");
        self.vmm_context.init_vmclear(index)?;

        log::info!("[+] init_vmptrld");
        self.vmm_context.init_vmptrld(index)?;

        log::info!("[+] init_vmcs_control_values");
        self.vmm_context.init_vmcs_control_values(index)?;

        log::info!("[+] init_host_register_state");
        self.vmm_context.init_host_register_state(index)?;

        log::info!("[+] init_guest_register_state");
        self.vmm_context.init_guest_register_state(index)?;

        log::info!("[+] init_vmlaunch");
        debug_vmlaunch()?;
        log::info!("[+] VMLAUNCH successful!");

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

            support::vmxoff()?;
    
            core::mem::drop(executor);
        }

        Ok(())
    }
}

pub fn debug_vmlaunch() -> Result<(), HypervisorError> {

    match support::vmlaunch() {
        Ok(_) => {
            log::info!("[+] VMLAUNCH successful!");
            Ok(())
        }
        Err(e) => {        
            log::info!("VM exit: {:#x}", support::vmread(x86::vmx::vmcs::ro::EXIT_REASON)?);
            log::info!("VM instruction error: {:#x}", support::vmread(x86::vmx::vmcs::ro::VM_INSTRUCTION_ERROR)?);
            Err(e)
        }
    }
}