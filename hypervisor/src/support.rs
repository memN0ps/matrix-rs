extern crate alloc;

use x86::{
    cpuid::CpuId, msr::{rdmsr, IA32_VMX_BASIC},
};

use crate::{error::HypervisorError};

pub struct Support {
    cpuid: CpuId,
}

impl Support {
    /// Create a new Support instance.
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
        Err(HypervisorError::CPUUnsupported)
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

    /// Enable VMX operation.
    pub fn vmxon(vmxon_pa: u64) -> Result<(), HypervisorError> {
        match unsafe { x86::bits64::vmx::vmxon(vmxon_pa) } {
            Ok(_) => Ok(()),
            Err(_) => Err(HypervisorError::VMXONFailed),
        }
    }

    /// Load current VMCS pointer.
    pub fn vmptrld(vmptrld_pa: u64) -> Result<(), HypervisorError> {
        match unsafe { x86::bits64::vmx::vmptrld(vmptrld_pa) } {
            Ok(_) => Ok(()),
            Err(_) => Err(HypervisorError::VMPTRLDFailed),
        }
    }

    #[allow(dead_code)]
    /// Launch virtual machine.
    pub fn vmlaunch() -> Result<(), HypervisorError> {
        match unsafe { x86::bits64::vmx::vmlaunch() } {
            Ok(_) => Ok(()),
            Err(_) => Err(HypervisorError::VMLAUNCHFailed),
        }
    }

    /// Disable VMX operation.
    pub fn vmxoff() -> Result<(), HypervisorError> {
        match unsafe { x86::bits64::vmx::vmxoff() } {
            Ok(_) => Ok(()),
            Err(_) => Err(HypervisorError::VMXOFFFailed),
        }
    }

    /// Get the Virtual Machine Control Structure revision identifier (VMCS revision ID) (Intel Manual: 25.11.5 VMXON Region)
    pub fn get_vmcs_revision_id() -> u32 {
        unsafe { (rdmsr(IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF }
    }
}