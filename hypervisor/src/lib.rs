#![no_std]
#![feature(allocator_api)]
#![feature(new_uninit)]
#![feature(const_trait_impl)]
#![feature(const_mut_refs)]
#![feature(naked_functions)]
#![feature(asm_const)]
#![feature(once_cell)]

extern crate alloc;
use alloc::vec::Vec;
use error::HypervisorError;

use crate::{processor::{ProcessorExecutor, processor_count}, vcpu::Vcpu};

mod vmexit_reason;
mod addresses;
mod ept;
mod vmcs_region;
mod vmxon_region;
mod vcpu;
mod vcpu_data;
mod context;
mod segmentation;
mod processor;
mod nt;
mod support;
mod error;

#[derive(Default)]
pub struct HypervisorBuilder;

impl HypervisorBuilder {
    pub fn build(self) -> Result<Hypervisor, HypervisorError> {
        //
        // 1) Intel Manual: 24.6 Discover Support for Virtual Machine Extension (VMX)
        //
        support::has_intel_cpu()?;
        log::info!("[+] CPU is Intel");
    
        support::has_vmx_support()?;
        log::info!("[+] Virtual Machine Extension (VMX) technology is supported");

        let mut processors: Vec<Vcpu> = Vec::new();
        
        for i in 0..processor_count() {
            processors.push(Vcpu::new(i)?);
        }
        log::info!("Found {} processors", processors.len());

        Ok(Hypervisor { processors })
    }
}

pub struct Hypervisor {
    processors: Vec<Vcpu>,
}

impl Hypervisor {
    
    pub fn builder() -> HypervisorBuilder {
        HypervisorBuilder::default()
    }

    pub fn virtualize(&mut self) -> Result<(), HypervisorError> {
        log::info!("Virtualizing processors");

        for processor in self.processors.iter_mut() {
            
            let Some(executor) = ProcessorExecutor::switch_to_processor(processor.id()) else {
                return Err(HypervisorError::ProcessorSwitchFailed);
            };

            processor.virtualize_cpu()?;
                
            core::mem::drop(executor);
        }
        Ok(())
    }

    pub fn devirtualize(&mut self) -> Result<(), HypervisorError> {
        log::info!("Devirtualizing processors");

        for processor in self.processors.iter_mut() {
            
            let Some(executor) = ProcessorExecutor::switch_to_processor(processor.id()) else {
                return Err(HypervisorError::ProcessorSwitchFailed);
            };

            processor.devirtualize_cpu()?;
                
            core::mem::drop(executor);
        }

        Ok(())
    }
}