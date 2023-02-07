extern crate alloc;
use core::cell::OnceCell;

use alloc::boxed::Box;


use crate::{error::HypervisorError, context::Context, support, vcpu_data::VcpuData};

pub struct Vcpu {
    /// The index of the processor.
    index: u32,
    
    data: OnceCell<Box<VcpuData>>,
}

impl Vcpu {
    pub fn new(index: u32) -> Result<Self, HypervisorError> {
        log::trace!("Creating processor {}", index);

        Ok (Self {
            index,
            data: OnceCell::new(),
        })
    }

    /// Virtualize the CPU by capturing the context, enabling VMX operation, adjusting control registers, calling VMXON, VMPTRLD and VMLAUNCH
    pub fn virtualize_cpu(&mut self) -> Result<(), HypervisorError> {
        log::info!("Capturing context");
        let context = Context::capture();

        //Check if already virtualized or not, then do it otherwise don't.

        //
        // 2) Intel Manual: 24.7 Enable and Enter VMX Operation
        //
        log::info!("[+] Enabling Virtual Machine Extensions (VMX)");
        support::enable_vmx_operation()?;

        log::info!("[+] Adjusting Control Registers");
        support::adjust_control_registers();

        log::info!("[+] Attempting to create new VCPU data");
        let mut vcpu_data = VcpuData::new(context)?;

        log::info!("[+] init_vmxon_region");
        vcpu_data.init_vmxon_region()?;

        log::info!("[+] init_vmxon_region");
        vcpu_data.init_vmcs_region()?;

        log::info!("[+] init_vmclear");
        vcpu_data.init_vmclear()?;

        log::info!("[+] init_vmptrld");
        support::vmptrld(vcpu_data.vmcs_region_physical_address)?;
        log::info!("[+] VMPTRLD successful!");

        //log::info!("[+] init_vmcs_control_values");
        //init_vmcs_control_values(index)?;

        //log::info!("[+] init_host_register_state");
        //init_host_register_state(index)?;

        //log::info!("[+] init_guest_register_state");
        //init_guest_register_state(index)?;

        //log::info!("[+] init_vmlaunch");
        //debug_vmlaunch()?;
        //log::info!("[+] VMLAUNCH successful!");
        Ok(())
    }

    /// Devirtualize the CPU using vmxoff
    pub fn devirtualize_cpu(&self) -> Result<(), HypervisorError> {
        support::vmxoff()?;
        Ok(())
    }

    /// Gets the index of the current logical/virtual processor
    pub fn id(&self) -> u32 {
        self.index
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

