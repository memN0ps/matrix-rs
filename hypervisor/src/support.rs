extern crate alloc;


use x86::{
    cpuid::CpuId, msr::{rdmsr, self}, controlregs, bits64,
};

use crate::{error::HypervisorError};

/// Check to see if CPU is Intel (“GenuineIntel”).
pub fn has_intel_cpu() -> Result<(), HypervisorError> {
    let cpuid = CpuId::new();
    if let Some(vi) = cpuid.get_vendor_info() {
        if vi.as_str() == "GenuineIntel" {
            return Ok(());
        }
    }
    Err(HypervisorError::CPUUnsupported)
}

/// Check processor supports for Virtual Machine Extension (VMX) technology - CPUID.1:ECX.VMX\[bit 5] = 1 (Intel Manual: 24.6 Discovering Support for VMX)
pub fn has_vmx_support() -> Result<(), HypervisorError> {
    let cpuid = CpuId::new();
    if let Some(fi) = cpuid.get_feature_info() {
        if fi.has_vmx() {
            return Ok(());
        }
    }
    Err(HypervisorError::VMXUnsupported)
}

/// Enables Virtual Machine Extensions - CR4.VMXE\[bit 13] = 1 (Intel Manual: 24.7 Enabling and Entering VMX Operation)
pub fn enable_vmx_operation() -> Result<(), HypervisorError> {
    let mut cr4 = unsafe { controlregs::cr4() };
    cr4.set(controlregs::Cr4::CR4_ENABLE_VMX, true);
    unsafe { controlregs::cr4_write(cr4) };

    set_lock_bit()?;
    log::info!("[+] Lock bit set via IA32_FEATURE_CONTROL");

    Ok(())
}

/// Check if we need to set bits in IA32_FEATURE_CONTROL (Intel Manual: 24.7 Enabling and Entering VMX Operation)
fn set_lock_bit() -> Result<(), HypervisorError> {
    const VMX_LOCK_BIT: u64 = 1 << 0;
    const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

    let ia32_feature_control = unsafe { rdmsr(msr::IA32_FEATURE_CONTROL) };

    if (ia32_feature_control & VMX_LOCK_BIT) == 0 {
        unsafe {
            msr::wrmsr(
                msr::IA32_FEATURE_CONTROL,
                VMXON_OUTSIDE_SMX | VMX_LOCK_BIT | ia32_feature_control,
            )
        };
    } else if (ia32_feature_control & VMXON_OUTSIDE_SMX) == 0 {
        return Err(HypervisorError::VMXBIOSLock);
    }

    Ok(())
}

/// Adjust set and clear the mandatory bits in CR0 and CR4
pub fn adjust_control_registers() {
    set_cr0_bits();
    log::info!("[+] Mandatory bits in CR0 set/cleared");

    set_cr4_bits();
    log::info!("[+] Mandatory bits in CR4 set/cleared");
}

/// Set the mandatory bits in CR0 and clear bits that are mandatory zero (Intel Manual: 24.8 Restrictions on VMX Operation)
fn set_cr0_bits() {
    let ia32_vmx_cr0_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED0) };
    let ia32_vmx_cr0_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED1) };

    let mut cr0 = unsafe { controlregs::cr0() };

    cr0 |= controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed0 as usize);
    cr0 &= controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed1 as usize);

    unsafe { controlregs::cr0_write(cr0) };
}

/// Set the mandatory bits in CR4 and clear bits that are mandatory zero (Intel Manual: 24.8 Restrictions on VMX Operation)
fn set_cr4_bits() {
    let ia32_vmx_cr4_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED0) };
    let ia32_vmx_cr4_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED1) };

    let mut cr4 = unsafe { controlregs::cr4() };

    cr4 |= controlregs::Cr4::from_bits_truncate(ia32_vmx_cr4_fixed0 as usize);
    cr4 &= controlregs::Cr4::from_bits_truncate(ia32_vmx_cr4_fixed1 as usize);

    unsafe { controlregs::cr4_write(cr4) };
}

/// Get the Virtual Machine Control Structure revision identifier (VMCS revision ID) (Intel Manual: 25.11.5 VMXON Region)
pub fn get_vmcs_revision_id() -> u32 {
    unsafe { (msr::rdmsr(msr::IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF }
}

/// Save the current state of the stack (RSP & RBP registers) because after executing the VMLAUNCH instruction,
/// the RIP register is changed to the GUEST_RIP; thus, we need to save the previous system state
/// so we can return to the normal system routines after returning from VM functions
/// There is no need to save the RIP register as the stack’s return address is always available
#[allow(dead_code)]
pub fn save_state_for_vmxoff() -> (u64, u64) {
    let rsp = bits64::registers::rsp();
    let rbp = bits64::registers::rbp();

    (rsp, rbp)
}

/// Enable VMX operation.
pub fn vmxon(vmxon_pa: u64) -> Result<(), HypervisorError> {
    match unsafe { x86::bits64::vmx::vmxon(vmxon_pa) } {
        Ok(_) => Ok(()),
        Err(_) => Err(HypervisorError::VMXONFailed),
    }
}

/// Disable VMX operation.
pub fn vmxoff() -> Result<(), HypervisorError> {
    match unsafe { x86::bits64::vmx::vmxoff() } {
        Ok(_) => Ok(()),
        Err(_) => Err(HypervisorError::VMXOFFFailed),
    }
}

/// Clear VMCS.
pub fn vmclear(addr: u64) -> Result<(), HypervisorError> {
    match unsafe { x86::bits64::vmx::vmclear(addr) } {
        Ok(_) => Ok(()),
        Err(_) => Err(HypervisorError::VMCLEARFailed),
    }
}

/// Load current VMCS pointer.
pub fn vmptrld(vmptrld_pa: u64) -> Result<(), HypervisorError> {
    match unsafe { x86::bits64::vmx::vmptrld(vmptrld_pa) } {
        Ok(_) => Ok(()),
        Err(_) => Err(HypervisorError::VMPTRLDFailed),
    }
}

/// Read a specified field from a VMCS.
pub fn vmread(field: u32) -> Result<u64, HypervisorError> {
    match unsafe { x86::bits64::vmx::vmread(field) } {
        Ok(value) => Ok(value),
        Err(_) => Err(HypervisorError::VMREADFailed),
    }
}

/// Write to a specified field in a VMCS.
pub fn vmwrite(field: u32, value: u64) -> Result<(), HypervisorError> {
    match unsafe { x86::bits64::vmx::vmwrite(field, value) } {
        Ok(_) => Ok(()),
        Err(_) => Err(HypervisorError::VMWRITEFailed),
    }
}

/// Launch virtual machine.
pub fn vmlaunch() -> Result<(), HypervisorError> {
    match unsafe { x86::bits64::vmx::vmlaunch() } {
        Ok(_) => Ok(()),
        Err(_) => Err(HypervisorError::VMLAUNCHFailed),
    }
}

#[allow(dead_code)]
/// Resume virtual machine.
pub fn vmresume() -> Result<(), HypervisorError> {
    match unsafe { x86::bits64::vmx::vmresume() } {
        Ok(_) => Ok(()),
        Err(_) => Err(HypervisorError::VMRESUMEFailed),
    }
}