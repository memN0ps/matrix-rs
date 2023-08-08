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
use alloc::vec::Vec;
use error::HypervisorError;

use crate::{
    intel::{vcpu::Vcpu, vmx::Vmx},
    utils::{
        context::Context,
        processor::{processor_count, ProcessorExecutor},
    },
};
mod error;
mod intel;
mod nt;
mod utils;

#[derive(Default)]
pub struct HypervisorBuilder;

impl HypervisorBuilder {
    pub fn build(self) -> Result<Hypervisor, HypervisorError> {
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.6 DISCOVERING SUPPORT FOR VMX */
        Vmx::has_intel_cpu()?;
        log::info!("[+] CPU is Intel");

        Vmx::has_vmx_support()?;
        log::info!("[+] Virtual Machine Extension (VMX) technology is supported");

        let mut processors: Vec<Vcpu> = Vec::new();

        for i in 0..processor_count() {
            processors.push(Vcpu::new(i)?);
        }
        log::info!("[+] Found {} processors", processors.len());

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
        log::info!("[+] Virtualizing processors");

        for processor in self.processors.iter_mut() {
            log::info!("[+] Capturing context");
            let context = Context::capture();

            if processor.is_virtualized() {
                continue;
            }

            let Some(executor) = ProcessorExecutor::switch_to_processor(processor.id()) else {
                return Err(HypervisorError::ProcessorSwitchFailed);
            };

            processor.virtualize_cpu(context)?;

            core::mem::drop(executor);
        }
        Ok(())
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
