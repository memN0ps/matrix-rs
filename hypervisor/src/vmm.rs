extern crate alloc;

use alloc::vec::Vec;
use bitfield::BitMut;

use x86::{msr::{rdmsr, IA32_FEATURE_CONTROL, wrmsr, IA32_VMX_CR0_FIXED0, IA32_VMX_CR0_FIXED1, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1}, controlregs::{cr4, cr4_write, Cr4, cr0, Cr0}};

use crate::{vcpu::Vcpu, error::HypervisorError, processor::processor_count, nt::{MmGetPhysicalAddress}, support};

pub struct Vmm {
    pub vcpu_table: Vec<Vcpu>,
    pub processor_count: u32,
}

impl Vmm { 
    pub fn new() -> Self {
        Self {
            processor_count: processor_count(),
            vcpu_table: Vec::new(),
        }
    }

    pub fn init_vcpu(&mut self) -> Result<(), HypervisorError> {
        log::info!("[+] Vcpu::new()");
        self.vcpu_table.push(Vcpu::new()?);

        Ok(())
    }
    
    /// Allocate a naturally aligned 4-KByte region of memory to enable VMX operation (Intel Manual: 25.11.5 VMXON Region)
    pub fn init_vmxon(&mut self, index: usize) -> Result<(), HypervisorError> {

        self.vcpu_table[index].vmxon_physical_address = unsafe { 
            *MmGetPhysicalAddress(self.vcpu_table[index].vmxon.as_mut() as *mut _ as _).QuadPart() as u64 
        };

        if self.vcpu_table[index].vmxon_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::info!("[+] VCPU: {}, Virtual Address: {:p}", index, self.vcpu_table[index].vmxon);
        log::info!("[+] VCPU: {}, Physical Addresss: 0x{:x}", index, self.vcpu_table[index].vmxon_physical_address);

        self.vcpu_table[index].vmxon.revision_id = support::get_vmcs_revision_id();
        self.vcpu_table[index].vmxon.as_mut().revision_id.set_bit(31, false);

        support::execute_vmxon(self.vcpu_table[index].vmxon_physical_address)?;
        log::info!("[+] VMXON successful!");

        Ok(())
    }

    /// Allocate a naturally aligned 4-KByte region of memory for VMCS region (Intel Manual: 25.2 Format of The VMCS Region)
    pub fn init_vmcs(&mut self, index: usize) -> Result<(), HypervisorError> {

        self.vcpu_table[index].vmcs_physical_address = unsafe { 
            *MmGetPhysicalAddress(self.vcpu_table[index].vmcs.as_mut() as *mut _ as _).QuadPart() as u64
        };

        if self.vcpu_table[index].vmcs_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::info!("[+] VCPU: {}, Virtual Address: {:p}", index, self.vcpu_table[index].vmcs);
        log::info!("[+] VCPU: {}, Physical Addresss: 0x{:x}", index, self.vcpu_table[index].vmcs_physical_address);

        self.vcpu_table[index].vmcs.revision_id = support::get_vmcs_revision_id();
        self.vcpu_table[index].vmcs.as_mut().revision_id.set_bit(31, false);

        support::execute_vmptrld(self.vcpu_table[index].vmcs_physical_address)?;
        log::info!("[+] VMPTRLD successful!");

        Ok(())
    }

    /// Enables Virtual Machine Extensions - CR4.VMXE\[bit 13] = 1 (Intel Manual: 24.7 Enabling and Entering VMX Operation)
    pub fn enable_vmx_operation(&self) -> Result<(), HypervisorError> {
        let mut cr4 = unsafe { cr4() };
        cr4.set(Cr4::CR4_ENABLE_VMX, true);
        unsafe { cr4_write(cr4) };

        self.set_lock_bit()?;
        log::info!("[+] Lock bit set via IA32_FEATURE_CONTROL");

        Ok(())
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

        Ok(())
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

    /*
    /// Get the Virtual Machine Control Structure revision identifier (VMCS revision ID) (Intel Manual: 25.11.5 VMXON Region)
    fn get_vmcs_revision_id() -> u32 {
        unsafe { (rdmsr(IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF }
    }

    /// Enable VMX operation.
    pub fn vmxon(&self, vmxon_pa: u64) -> Result<(), HypervisorError> {
        match unsafe { vmxon(vmxon_pa) } {
            Ok(_) => Ok(()),
            Err(_) => Err(HypervisorError::VMXONFailed),
        }
    }

    /// Load current VMCS pointer.
    pub fn vmptrld(&self, vmptrld_pa: u64) -> Result<(), HypervisorError> {
        match unsafe { vmptrld(vmptrld_pa) } {
            Ok(_) => Ok(()),
            Err(_) => Err(HypervisorError::VMPTRLDFailed),
        }
    }

    /// Launch virtual machine.
    pub fn vmlaunch(&self) -> Result<(), HypervisorError> {
        match unsafe { vmlaunch() } {
            Ok(_) => Ok(()),
            Err(_) => Err(HypervisorError::VMLAUNCHFailed),
        }
    }

    /// Disable VMX operation.
    pub fn vmxoff(&self) -> Result<(), HypervisorError> {
        match unsafe { vmxoff() } {
            Ok(_) => Ok(()),
            Err(_) => Err(HypervisorError::VMXOFFFailed),
        }
    }
    */
}