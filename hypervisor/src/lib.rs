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
        let mut vcpus = Vcpu::new(i);

        vmx.enable_vmx_operation()?;
        log::info!("[+] Virtual Machine Extensions (VMX) enabled");
    
        vmx.adjust_control_registers();
        log::info!("[+] Control registers adjusted");

        vmx.allocate_vmm_context(&mut vcpus)?;
        vmx.vmxon(vcpus.vmcs_physical)?;
        log::info!("[+] VMXON successful!");

        vmx.allocate_vmm_context(&mut vcpus)?;
        vmx.vmptrld(vcpus.vmcs_physical)?;
        log::info!("[+] VMPTRLD successful!");

        vcpus_list.push(vcpus);

        ProcessorExecutor::switch_to_processor(i);
    }

    return Ok(());
}

//pub fn init_logical_processor() {}
