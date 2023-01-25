#![no_std]
#![feature(allocator_api)]
#![feature(new_uninit)]

extern crate alloc;
use alloc::vec::Vec;
use error::HypervisorError;
use vmx::VMX;

use crate::{processor::{processor_count, ProcessorExecutor}, vcpu::Vcpu};

mod vcpu;
mod processor;
mod nt;
mod vmx;
mod error;

use kernel_alloc::KernelAlloc;

#[global_allocator]
static GLOBAL: KernelAlloc = KernelAlloc;

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

    let mut vcpus_list: Vec<Vcpu> = Vec::new();

    for i in 0..processor_count() {
        log::info!("[+] Processor: {}", i);
        
        ProcessorExecutor::switch_to_processor(i);

        let mut vcpus = Vcpu::new(i);

        vmx.enable_vmx_operation()?;
        log::info!("[+] Virtual Machine Extensions (VMX) enabled");
    
        vmx.adjust_control_registers();
        log::info!("[+] Control registers adjusted");

        vcpus.vmxon_physical_address = vmx.allocate_vmm_context()?;
        vmx.vmxon(vcpus.vmxon_physical_address)?;
        log::info!("[+] VMXON successful!");

        vcpus.vmcs_physical_address = vmx.allocate_vmm_context()?;
        vmx.vmptrld(vcpus.vmcs_physical_address)?;
        log::info!("[+] VMPTRLD successful!");

        vcpus_list.push(vcpus);

    }

    return Ok(());
}

//pub fn init_logical_processor() {}
