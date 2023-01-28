extern crate alloc;

use x86::{
    cpuid::CpuId,
};

use crate::{error::HypervisorError};

pub struct Vmx {
    cpuid: CpuId,
}

impl Vmx {
    /// Create a new VMX instance.
    pub fn new() -> Self {
        Self {
            cpuid: CpuId::new(),
        }
    }

    /// Check to see if CPU is Intel (“GenuineIntel”).
    pub fn has_intel_cpu(&self) -> Result<(), HypervisorError> {
        if let Some(vi) = self.cpuid.get_vendor_info() {
            if vi.as_str() == "GenuineIntel" {
                return Ok(());
            }
        }
        Err(HypervisorError::InvalidCPU)
    }

    /// Check processor supports for Virtual Machine Extension (VMX) technology - CPUID.1:ECX.VMX\[bit 5] = 1 (Intel Manual: 24.6 Discovering Support for VMX)
    pub fn has_vmx_support(&self) -> Result<(), HypervisorError> {
        if let Some(fi) = self.cpuid.get_feature_info() {
            if fi.has_vmx() {
                return Ok(());
            }
        }
        Err(HypervisorError::VMXUnsupported)
    }
}
