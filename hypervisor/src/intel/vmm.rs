//! The main module for the hypervisor.

use {
    crate::{
        error::HypervisorError,
        intel::{ept::paging::Ept, shared_data::SharedData, vcpu::Vcpu},
        utils::{
            alloc::PhysicalAllocator,
            processor::{processor_count, ProcessorExecutor},
        },
    },
    alloc::{boxed::Box, vec::Vec},
};

#[derive(Default)]
pub struct HypervisorBuilder {
    /// The primary extended page table.
    primary_ept: Option<Box<Ept, PhysicalAllocator>>,

    #[cfg(feature = "secondary-ept")]
    /// The secondary extended page table.
    secondary_ept: Option<Box<Ept, PhysicalAllocator>>,
}

impl HypervisorBuilder {
    /// Creates a new HypervisorBuilder instance.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if hypervisor initialization was successful, or `Err` if there was an error.
    pub fn build(self) -> Result<Hypervisor, HypervisorError> {
        log::info!("Initializing hypervisor");

        Hypervisor::check_supported_cpu()?;

        let mut processors: Vec<Vcpu> = Vec::new();

        for i in 0..processor_count() {
            processors.push(Vcpu::new(i)?);
        }

        log::info!("Found {} processors", processors.len());

        let primary_ept = self
            .primary_ept
            .ok_or(HypervisorError::PrimaryEPTNotProvided)?;

        #[cfg(not(feature = "secondary-ept"))]
        let mut shared_data = SharedData::new(primary_ept);

        #[cfg(feature = "secondary-ept")]
        let shared_data = {
            let secondary_ept = self
                .secondary_ept
                .ok_or(HypervisorError::SecondaryEPTNotProvided)?;

            SharedData::new(primary_ept, secondary_ept)
        };

        Ok(Hypervisor {
            processors,
            shared_data,
        })
    }

    pub fn primary_ept(mut self, ept: Box<Ept, PhysicalAllocator>) -> Self {
        self.primary_ept = Some(ept);
        self
    }

    #[cfg(feature = "secondary-ept")]
    pub fn secondary_ept(mut self, ept: Box<Ept, PhysicalAllocator>) -> Self {
        self.secondary_ept = Some(ept);
        self
    }
}

/// The main struct representing the hypervisor.
pub struct Hypervisor {
    /// The processors to virtualize.
    processors: Vec<Vcpu>,

    /// The shared data between processors.
    shared_data: Box<SharedData>,
}

impl Hypervisor {
    /// Creates a new HypervisorBuilder instance.
    pub fn builder() -> HypervisorBuilder {
        HypervisorBuilder::default()
    }

    /// Virtualizes the system's processors.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the virtualization was successful, or `Err` if there was an error.
    pub fn virtualize_system(&mut self) -> Result<(), HypervisorError> {
        log::info!("Virtualizing processors");

        for processor in self.processors.iter_mut() {
            let Some(executor) = ProcessorExecutor::switch_to_processor(processor.id()) else {
                return Err(HypervisorError::ProcessorSwitchFailed);
            };

            processor.virtualize_cpu(self.shared_data.as_mut())?;

            drop(executor);
        }

        Ok(())
    }

    /// Reverts the virtualization of the system's processors.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the devirtualization was successful, or `Err` if there was an error.
    pub fn devirtualize_system(&mut self) -> Result<(), HypervisorError> {
        log::info!("Devirtualizing processors");

        for processor in self.processors.iter_mut() {
            let Some(executor) = ProcessorExecutor::switch_to_processor(processor.id()) else {
                return Err(HypervisorError::ProcessorSwitchFailed);
            };

            processor.devirtualize_cpu()?;

            drop(executor);
        }

        Ok(())
    }

    /// Check if the CPU is supported.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the CPU is supported, or `Err` if it's not.
    fn check_supported_cpu() -> Result<(), HypervisorError> {
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.6 DISCOVERING SUPPORT FOR VMX */
        Self::has_intel_cpu()?;
        log::info!("CPU is Intel");

        Self::has_vmx_support()?;
        log::info!("Virtual Machine Extension (VMX) technology is supported");

        Self::has_mtrr()?;
        log::info!("Memory Type Range Registers (MTRRs) are supported");

        Ok(())
    }

    /// Check to see if CPU is Intel (“GenuineIntel”).
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the CPU is Intel, or `Err` if it's not.
    fn has_intel_cpu() -> Result<(), HypervisorError> {
        let cpuid = x86::cpuid::CpuId::new();
        if let Some(vi) = cpuid.get_vendor_info() {
            if vi.as_str() == "GenuineIntel" {
                return Ok(());
            }
        }
        Err(HypervisorError::CPUUnsupported)
    }

    /// Check processor support for Virtual Machine Extension (VMX) technology.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if VMX technology is supported, or `Err` if it's not.
    fn has_vmx_support() -> Result<(), HypervisorError> {
        let cpuid = x86::cpuid::CpuId::new();
        if let Some(fi) = cpuid.get_feature_info() {
            if fi.has_vmx() {
                return Ok(());
            }
        }
        Err(HypervisorError::VMXUnsupported)
    }

    /// Check processor support for Memory Type Range Registers (MTRRs).
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if MTRRs are supported, or `Err` if it's not.
    fn has_mtrr() -> Result<(), HypervisorError> {
        let cpuid = x86::cpuid::CpuId::new();
        if let Some(fi) = cpuid.get_feature_info() {
            if fi.has_mtrr() {
                return Ok(());
            }
        }
        Err(HypervisorError::MTRRUnsupported)
    }
}

impl Drop for Hypervisor {
    /// Handles the dropping of the `Hypervisor` instance.
    ///
    /// When a `Hypervisor` instance goes out of scope or is explicitly dropped,
    /// this method attempts to devirtualize the system and logs the result.
    fn drop(&mut self) {
        match self.devirtualize_system() {
            Ok(_) => log::info!("Devirtualized successfully!"),
            Err(err) => log::info!("Failed to devirtualize {}", err),
        }
    }
}
