extern crate alloc;

use alloc::{boxed::Box};
use kernel_alloc::PhysicalAllocator;
use winapi::{shared::ntdef::PHYSICAL_ADDRESS};
use x86::{
    controlregs::{cr0, cr4, cr4_write, Cr0, Cr4},
    cpuid::CpuId,
    current::vmx::{vmptrld, vmxon},
    msr::{
        rdmsr, wrmsr, IA32_FEATURE_CONTROL, IA32_VMX_BASIC, IA32_VMX_CR0_FIXED0,
        IA32_VMX_CR0_FIXED1, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1,
    },
};

use crate::{
    nt::{MmGetPhysicalAddress, MmGetVirtualForPhysical}, error::HypervisorError};

pub struct VMX {
    cpuid: CpuId,
}

impl VMX {
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
        return Err(HypervisorError::InvalidCPU);
    }

    /// Check processor supports for Virtual Machine Extension (VMX) technology - CPUID.1:ECX.VMX\[bit 5] = 1 (Intel Manual: 24.6 Discovering Support for VMX)
    pub fn has_vmx_support(&self) -> Result<(), HypervisorError> {
        if let Some(fi) = self.cpuid.get_feature_info() {
            if fi.has_vmx() {
                return Ok(());
            }
        }
        return Err(HypervisorError::VMXUnsupported);
    }

    /// Enables Virtual Machine Extensions - CR4.VMXE\[bit 13] = 1 (Intel Manual: 24.7 Enabling and Entering VMX Operation)
    pub fn enable_vmx_operation(&self) -> Result<(), HypervisorError> {
        let mut cr4 = unsafe { cr4() };
        cr4.set(Cr4::CR4_ENABLE_VMX, true);
        unsafe { cr4_write(cr4) };

        self.set_lock_bit()?;
        log::info!("[+] Lock bit set via IA32_FEATURE_CONTROL");

        return Ok(());
    }

    /// Check if we need to set bits in IA32_FEATURE_CONTROL (Intel Manual: 24.7 Enabling and Entering VMX Operation)
    fn set_lock_bit(&self) -> Result<(), HypervisorError> {
        const VMX_LOCK_BIT: u64 = 1 << 0;
        const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

        let ia32_feature_control = unsafe { rdmsr(IA32_FEATURE_CONTROL) };

        if (ia32_feature_control & VMX_LOCK_BIT) == 0 {
            unsafe {
                wrmsr(
                    IA32_FEATURE_CONTROL,
                    VMXON_OUTSIDE_SMX | VMX_LOCK_BIT | ia32_feature_control,
                )
            };
        } else if (ia32_feature_control & VMXON_OUTSIDE_SMX) == 0 {
            return Err(HypervisorError::VMXBIOSLock);
        }

        return Ok(());
    }

    /// Adjust set and clear the mandatory bits in CR0 and CR4
    pub fn adjust_control_registers(&self) {
        self.set_cr0_bits();
        log::info!("[+] Mandatory bits in CR0 set/cleared");

        self.set_cr4_bits();
        log::info!("[+] Mandatory bits in CR4 set/cleared");
    }

    /// Set the mandatory bits in CR0 and clear bits that are mandatory zero (Intel Manual: 24.8 Restrictions on VMX Operation)
    fn set_cr0_bits(&self) {
        let ia32_vmx_cr0_fixed0 = unsafe { rdmsr(IA32_VMX_CR0_FIXED0) };
        let ia32_vmx_cr0_fixed1 = unsafe { rdmsr(IA32_VMX_CR0_FIXED1) };

        let mut cr0 = unsafe { cr0() };

        cr0 |= Cr0::from_bits_truncate(ia32_vmx_cr0_fixed0 as usize);
        cr0 &= Cr0::from_bits_truncate(ia32_vmx_cr0_fixed1 as usize);

        unsafe { x86::controlregs::cr0_write(cr0) };
    }

    /// Set the mandatory bits in CR4 and clear bits that are mandatory zero (Intel Manual: 24.8 Restrictions on VMX Operation)
    fn set_cr4_bits(&self) {
        let ia32_vmx_cr4_fixed0 = unsafe { rdmsr(IA32_VMX_CR4_FIXED0) };
        let ia32_vmx_cr4_fixed1 = unsafe { rdmsr(IA32_VMX_CR4_FIXED1) };

        let mut cr4 = unsafe { cr4() };

        cr4 |= Cr4::from_bits_truncate(ia32_vmx_cr4_fixed0 as usize);
        cr4 &= Cr4::from_bits_truncate(ia32_vmx_cr4_fixed1 as usize);

        unsafe { cr4_write(cr4) };
    }

    /// Get the Virtual Machine Control Structure revision identifier (VMCS revision ID) (Intel Manual: 25.11.5 VMXON Region)
    fn get_vmcs_revision_id(&self) -> u32 {
        let vmcs_id = unsafe { (rdmsr(IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF };
        return vmcs_id;
    }

    /// Allocate a naturally aligned 4-KByte region of memory to support enable VMX operation (Intel Manual: 25.11.5 VMXON Region)
    pub fn allocate_vmm_context(&self) -> Result<u64, HypervisorError> {
        let mut virtual_address: Box<u64, PhysicalAllocator> = unsafe {
            match Box::try_new_zeroed_in(PhysicalAllocator) {
                Ok(va) => va,
                Err(_) => return Err(HypervisorError::MemoryAllocationFailed),
            }
            .assume_init()
        };

        log::info!("[+] Allocate a naturally aligned 4-KByte region of memory: {:p}", virtual_address);

        unsafe {
            core::ptr::write(
                virtual_address.as_mut() as *mut u64,
                self.get_vmcs_revision_id() as _,
            )
        };

        log::info!("[+] VMCS Revision Identifier written successfully: {}", self.get_vmcs_revision_id());

        let physical_address = self.pa_from_va(virtual_address.as_mut() as *mut _ as _);
        log::info!("[+] Physical Addresss: 0x{:x}", physical_address);

        //unsafe { core::arch::asm!("int3") };

        if physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        return Ok(physical_address);
    }

    /// Converts from virtual address to physical address
    pub fn pa_from_va(&self, va: u64) -> u64 {
        return unsafe { *MmGetPhysicalAddress(va as _).QuadPart() as u64 };
    }

    #[allow(dead_code)]
    /// Converts from physical address to virtual address
    pub fn va_from_pa(&self, pa: u64) -> u64 {
        let mut physical_address = unsafe { core::mem::zeroed::<PHYSICAL_ADDRESS>() };
        unsafe { *(physical_address.QuadPart_mut()) = pa as i64 };
        return unsafe { MmGetVirtualForPhysical(physical_address) as u64 };
    }

    /// Enable VMX operation.
    pub fn vmxon(&self, vmxon_pa: u64) -> Result<(), HypervisorError> {
        match unsafe { vmxon(vmxon_pa) } {
            Ok(_) => Ok(()),
            Err(_) => return Err(HypervisorError::VMXONFailed),
        }
    }

    /// Load current VMCS pointer.
    pub fn vmptrld(&self, vmptrld_pa: u64) -> Result<(), HypervisorError> {
        match unsafe { vmptrld(vmptrld_pa) } {
            Ok(_) => Ok(()),
            Err(_) => return Err(HypervisorError::VMPTRLDFailed),
        }
    }
}
