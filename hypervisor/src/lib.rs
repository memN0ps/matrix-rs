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

pub fn vmm_init() -> Result<(), HypervisorError> {
    //
    // 1) Intel Manual: 24.6 Discover Support for Virtual Machine Extension (VMX)
    //

    let vmx = Vmx::new();

    vmx.has_intel_cpu()?;
    log::info!("[+] CPU is Intel");

    vmx.has_vmx_support()?;
    log::info!("[+] Virtual Machine Extension (VMX) technology is supported");

    log::info!("[+] Initializing VMM Context");
    let mut vmm_context = Vmm::new();

    for index in 0..vmm_context.processor_count {
        log::info!("[+] Switching Processor");
        
        let Some(_old_affinity) = ProcessorExecutor::switch_to_processor(index) else {
            return Err(HypervisorError::ProcessorSwitchFailed);
        };

        log::info!("[+] Processor: {}", index);

        vmm_context.init_vcpu()?;

        //
        // 2) Intel Manual: 24.7 Enable and Enter VMX Operation
        //
        init_logical_processor(&mut vmm_context, index as usize)?;
    }
    Ok(())
}


/// Enable and Enter VMX Operation via VMXON and load current VMCS pointer via VMPTRLD
pub fn init_logical_processor(vmm_context: &mut Vmm, index: usize) -> Result<(), HypervisorError> {
    log::info!("[+] Enabling Virtual Machine Extensions (VMX)");
    vmm_context.enable_vmx_operation()?;

    log::info!("[+] Adjusting Control Registers");
    vmm_context.adjust_control_registers();

    log::info!("[+] init_vmxon");
    vmm_context.init_vmxon(index)?;

    log::info!("[+] init_vmcs");
    vmm_context.init_vmcs(index)?;

    Ok(())
}