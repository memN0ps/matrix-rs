#![no_std]
#![feature(allocator_api)]
#![feature(new_uninit)]
#![feature(const_trait_impl)]
#![feature(const_mut_refs)]
#![feature(naked_functions)]
#![feature(asm_const)]
#![feature(once_cell_try)]
#![feature(decl_macro)]

#[macro_use]
extern crate static_assertions;

use alloc::vec::Vec;
use error::HypervisorError;
use x86_64::intel::vcpu::Vcpu;

use crate::x86_64::utils::processor::{processor_count, ProcessorExecutor};
extern crate alloc;

pub mod error;
pub mod serial;
pub mod x86_64;

pub struct Hypervisor {
    processors: Vec<Vcpu>,
}

impl Hypervisor {
    pub fn new() -> Result<Self, HypervisorError> {
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.6 DISCOVERING SUPPORT FOR VMX */
        Self::has_intel_cpu()?;
        println!("CPU is Intel");

        Self::has_vmx_support()?;
        println!("Virtual Machine Extension (VMX) technology is supported");

        let mut processors: Vec<Vcpu> = Vec::new();

        for i in 0..processor_count() {
            processors.push(Vcpu::new(i)?);
        }
        println!("Found {} processors", processors.len());

        Ok(Hypervisor { processors })
    }

    pub fn virtualize_system(&mut self) -> Result<(), HypervisorError> {
        println!("Virtualizing processors");

        for processor in self.processors.iter_mut() {
            let Some(executor) = ProcessorExecutor::switch_to_processor(processor.id()) else {
                return Err(HypervisorError::ProcessorSwitchFailed);
            };

            processor.virtualize_cpu()?;

            core::mem::drop(executor);
        }

        Ok(())
    }

    /// Check to see if CPU is Intel (“GenuineIntel”).
    fn has_intel_cpu() -> Result<(), HypervisorError> {
        let cpuid = x86::cpuid::CpuId::new();
        if let Some(vi) = cpuid.get_vendor_info() {
            if vi.as_str() == "GenuineIntel" {
                return Ok(());
            }
        }
        Err(HypervisorError::CPUUnsupported)
    }

    /// Check processor supports for Virtual Machine Extension (VMX) technology - CPUID.1:ECX.VMX\[bit 5] = 1
    fn has_vmx_support() -> Result<(), HypervisorError> {
        let cpuid = x86::cpuid::CpuId::new();
        if let Some(fi) = cpuid.get_feature_info() {
            if fi.has_vmx() {
                return Ok(());
            }
        }
        Err(HypervisorError::VMXUnsupported)
    }

    /*
    pub fn devirtualize(&mut self) -> Result<(), HypervisorError> {
        println!("Devirtualizing processors");

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
