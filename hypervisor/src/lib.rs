#![no_std]
#![feature(allocator_api)]
#![feature(new_uninit)]

//extern crate alloc;
//use alloc::vec::Vec;
use error::HypervisorError;
use vmx::VMX;

use crate::{processor::{processor_count, ProcessorExecutor}, vcpu::Vcpu};

mod vmcs;
mod vcpu;
mod processor;
mod nt;
mod vmx;
mod error;

pub fn init_vmx() -> Result<(), HypervisorError> {
    //
    // 1) Intel Manual: 24.6 Discover Support for Virtual Machine Extension (VMX)
    //

    let vmx = VMX::new();

    vmx.has_intel_cpu()?;
    log::info!("[+] CPU is Intel");

    vmx.has_vmx_support()?;
    log::info!("[+] Virtual Machine Extension (VMX) technology is supported");

    //
    // 2) Intel Manual: 24.7 Enable and Enter VMX Operation
    //

    //let mut vcpus_list: Vec<Vcpu> = Vec::new();

    for i in 0..processor_count() {
        log::info!("[+] Processor: {}", i);
        
        if let Some(_old_affinity) = ProcessorExecutor::switch_to_processor(i) {

            log::info!("[+] Calling VCPU::new()");

            let mut vcpus = Vcpu::new(i);
            log::info!("[+] Created a new VCPU");

            vmx.enable_vmx_operation()?;
            log::info!("[+] Virtual Machine Extensions (VMX) enabled");
        
            vmx.adjust_control_registers();
            log::info!("[+] Control registers adjusted");

            vmx.allocate_vmxon_memory(&mut vcpus)?;
            vmx.vmxon(vcpus.vmxon_physical_address)?;
            log::info!("[+] VMXON successful!");

            vmx.allocate_vmcs_memory(&mut vcpus)?;
            vmx.vmptrld(vcpus.vmcs_physical_address)?;
            log::info!("[+] VMPTRLD successful!");
            
            //vcpus_list.push(vcpus);

        } else {
            return Err(HypervisorError::ProcessorSwitchFailed);
        }
    }

    return Ok(());
}

//pub fn init_logical_processor() {}
