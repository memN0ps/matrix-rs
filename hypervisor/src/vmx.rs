use winapi::shared::ntdef::PHYSICAL_ADDRESS;
use x86::{
    controlregs::{cr0, cr4, cr4_write, Cr0, Cr4},
    cpuid::CpuId,
    current::vmx::vmxon,
    msr::{
        rdmsr, wrmsr, IA32_FEATURE_CONTROL, IA32_VMX_BASIC, IA32_VMX_CR0_FIXED0,
        IA32_VMX_CR0_FIXED1, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1,
    },
};

use crate::{
    alloc::PhysicalAllocator,
    nt::{MmGetPhysicalAddress, MmGetVirtualForPhysical},
};

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
    pub fn has_intel_cpu(&self) -> bool {
        if let Some(vi) = self.cpuid.get_vendor_info() {
            if vi.as_str() == "GenuineIntel" {
                return true;
            }
        }
        return false;
    }

    /// Check processor supports for Virtual Machine Extension (VMX) technology - CPUID.1:ECX.VMX\[bit 5] = 1 (Intel Manual: 24.6 Discovering Support for VMX)
    pub fn has_vmx_support(&self) -> bool {
        if let Some(fi) = self.cpuid.get_feature_info() {
            if fi.has_vmx() {
                return true;
            }
        }
        return false;
    }

    /// Enables Virtual Machine Extensions - CR4.VMXE\[bit 13] = 1 (Intel Manual: 24.7 Enabling and Entering VMX Operation)
    pub fn enable_vmx(&self) {
        let mut cr4 = unsafe { cr4() };
        cr4.set(Cr4::CR4_ENABLE_VMX, true);
        unsafe { cr4_write(cr4) };
    }

    /// Check if we need to set bits in IA32_FEATURE_CONTROL (Intel Manual: 24.7 Enabling and Entering VMX Operation)
    pub fn set_feature_control_bits(&self) -> bool {
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
            return false;
        }

        return true;
    }

    /// Set the mandatory bits in CR0 and clear bits that are mandatory zero (Intel Manual: 24.8 Restrictions on VMX Operation)
    pub fn set_cr0_bits(&self) {
        let ia32_vmx_cr0_fixed0 = unsafe { rdmsr(IA32_VMX_CR0_FIXED0) };
        let ia32_vmx_cr0_fixed1 = unsafe { rdmsr(IA32_VMX_CR0_FIXED1) };

        let mut cr0 = unsafe { cr0() };

        cr0 |= Cr0::from_bits_truncate(ia32_vmx_cr0_fixed0 as usize);
        cr0 &= Cr0::from_bits_truncate(ia32_vmx_cr0_fixed1 as usize);

        unsafe { x86::controlregs::cr0_write(cr0) };
    }

    /// Set the mandatory bits in CR4 and clear bits that are mandatory zero (Intel Manual: 24.8 Restrictions on VMX Operation)
    pub fn set_cr4_bits(&self) {
        let ia32_vmx_cr4_fixed0 = unsafe { rdmsr(IA32_VMX_CR4_FIXED0) };
        let ia32_vmx_cr4_fixed1 = unsafe { rdmsr(IA32_VMX_CR4_FIXED1) };

        let mut cr4 = unsafe { cr4() };

        cr4 |= Cr4::from_bits_truncate(ia32_vmx_cr4_fixed0 as usize);
        cr4 &= Cr4::from_bits_truncate(ia32_vmx_cr4_fixed1 as usize);

        unsafe { cr4_write(cr4) };
    }

    /// Get the Virtual Machine Control Structure revision identifier (VMCS revision ID) (Intel Manual: 25.11.5 VMXON Region)
    pub fn get_vmcs_revision_id(&self) -> u32 {
        let vmcs_id = unsafe { (rdmsr(IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF };
        return vmcs_id;
    }

    /// Allocate a naturally aligned 4-KByte region of memory that a logical processor may use to support VMX operation (Intel Manual: 25.11.5 VMXON Region)
    pub fn allocate_vmxon_region(&self) -> bool {
        // Might have to change this value to 4096 x 2 = 8196
        let mut vmx_region_va: Box<u64, PhysicalAllocator> = unsafe {
            match Box::try_new_zeroed_in(PhysicalAllocator) {
                Ok(v) => v,
                Err(err) => {
                    log::error!(
                        "[-] Failed allocate memory via PhysicalAllocator {}",
                        err.to_string()
                    );
                    return false;
                }
            }
            .assume_init()
        };

        let vmx_region_pa = self.pa_from_va(vmx_region_va.as_mut() as *mut _ as _);

        if vmx_region_pa == 0 {
            return false;
        }

        unsafe { core::ptr::write(vmx_region_pa as *mut u64, self.get_vmcs_revision_id() as _) };

        unsafe {
            match vmxon(vmx_region_pa) {
                Ok(()) => return true,
                Err(err) => {
                    log::error!("[-] Failed to execute vmxon {:?}", err);
                    return false;
                }
            }
        }
    }

    /// Converts from virtual address to physical address
    pub fn pa_from_va(&self, va: u64) -> u64 {
        return unsafe { *MmGetPhysicalAddress(va as _).QuadPart() as u64 };
    }

    #[allow(dead_code)]
    /// Converts from physical address to virtual address
    pub fn va_from_pa(&self, pa: u64) -> u64 {
        let mut physical_address = unsafe { std::mem::zeroed::<PHYSICAL_ADDRESS>() };
        unsafe { *(physical_address.QuadPart_mut()) = pa as i64 };
        return unsafe { MmGetVirtualForPhysical(physical_address) as u64 };
    }
}
