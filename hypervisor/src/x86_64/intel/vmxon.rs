use crate::{
    error::HypervisorError,
    println,
    x86_64::{intel::support::vmxon, utils::addresses::PhysicalAddress},
};

use {alloc::boxed::Box, bitfield::BitMut, kernel_alloc::PhysicalAllocator};

pub const PAGE_SIZE: usize = 0x1000;

/// Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.11.5 VMXON Region
#[repr(C, align(4096))]
pub struct Vmxon {
    pub revision_id: u32,
    pub data: [u8; PAGE_SIZE - 4],
}

impl Vmxon {
    /// Execute vmxon instruction to enable vmx operation.
    /// # VMXON Region
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.2 FORMAT OF THE VMCS REGION
    pub fn new() -> Result<Box<Self, PhysicalAllocator>, HypervisorError> {
        println!("Setting up VMXON region");

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.7 ENABLING AND ENTERING VMX OPERATION */
        println!("Enabling Virtual Machine Extensions (VMX)");
        Self::enable_vmx_operation()?;

        let mut vmxon_region: Box<Vmxon, PhysicalAllocator> =
            unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };

        let vmxon_region_physical_address =
            PhysicalAddress::pa_from_va(vmxon_region.as_ref() as *const _ as _);

        if vmxon_region_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        println!("VMXON Region Virtual Address: {:p}", vmxon_region);
        println!(
            "VMXON Region Physical Addresss: 0x{:x}",
            vmxon_region_physical_address
        );

        vmxon_region.revision_id = Self::get_vmcs_revision_id();
        vmxon_region.as_mut().revision_id.set_bit(31, false);

        // Enable VMX operation.
        vmxon(vmxon_region_physical_address);
        println!("VMXON successful!");

        Ok(vmxon_region)
    }

    /// Enable and enter VMX operation by setting and clearing the lock bit, adjusting control registers and executing the vmxon instruction.
    fn enable_vmx_operation() -> Result<(), HypervisorError> {
        let mut cr4 = unsafe { x86::controlregs::cr4() };
        cr4.set(x86::controlregs::Cr4::CR4_ENABLE_VMX, true);
        unsafe { x86::controlregs::cr4_write(cr4) };

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.7 ENABLING AND ENTERING VMX OPERATION */
        println!("Setting Lock Bit set via IA32_FEATURE_CONTROL");
        Self::set_lock_bit()?;

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.8 RESTRICTIONS ON VMX OPERATION */
        println!("Adjusting Control Registers");
        Self::adjust_control_registers();

        Ok(())
    }

    /// Check if we need to set bits in IA32_FEATURE_CONTROL
    fn set_lock_bit() -> Result<(), HypervisorError> {
        const VMX_LOCK_BIT: u64 = 1 << 0;
        const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

        let ia32_feature_control = unsafe { x86::msr::rdmsr(x86::msr::IA32_FEATURE_CONTROL) };

        if (ia32_feature_control & VMX_LOCK_BIT) == 0 {
            unsafe {
                x86::msr::wrmsr(
                    x86::msr::IA32_FEATURE_CONTROL,
                    VMXON_OUTSIDE_SMX | VMX_LOCK_BIT | ia32_feature_control,
                )
            };
        } else if (ia32_feature_control & VMXON_OUTSIDE_SMX) == 0 {
            return Err(HypervisorError::VMXBIOSLock);
        }

        Ok(())
    }

    /// Adjust set and clear the mandatory bits in CR0 and CR4
    fn adjust_control_registers() {
        Self::set_cr0_bits();
        Self::set_cr4_bits();
    }

    /// Set the mandatory bits in CR0 and clear bits that are mandatory zero
    fn set_cr0_bits() {
        let ia32_vmx_cr0_fixed0 = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_CR0_FIXED0) };
        let ia32_vmx_cr0_fixed1 = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_CR0_FIXED1) };

        let mut cr0 = unsafe { x86::controlregs::cr0() };

        cr0 |= x86::controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed0 as usize);
        cr0 &= x86::controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed1 as usize);

        unsafe { x86::controlregs::cr0_write(cr0) };
    }

    /// Set the mandatory bits in CR4 and clear bits that are mandatory zero
    fn set_cr4_bits() {
        let ia32_vmx_cr4_fixed0 = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_CR4_FIXED0) };
        let ia32_vmx_cr4_fixed1 = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_CR4_FIXED1) };

        let mut cr4 = unsafe { x86::controlregs::cr4() };

        cr4 |= x86::controlregs::Cr4::from_bits_truncate(ia32_vmx_cr4_fixed0 as usize);
        cr4 &= x86::controlregs::Cr4::from_bits_truncate(ia32_vmx_cr4_fixed1 as usize);

        unsafe { x86::controlregs::cr4_write(cr4) };
    }

    /// Get the Virtual Machine Control Structure revision identifier (VMCS revision ID)
    fn get_vmcs_revision_id() -> u32 {
        unsafe { (x86::msr::rdmsr(x86::msr::IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF }
    }
}
