extern crate alloc;

use alloc::{vec::Vec, boxed::Box};
use bitfield::BitMut;

use kernel_alloc::PhysicalAllocator;
use x86::{msr::{self}, controlregs::{self}, vmx::vmcs::guest, debugregs, bits64};

use crate::{vcpu::Vcpu, error::HypervisorError, processor::processor_count, support::{Support}, addresses::{PhysicalAddress}, msr_bitmap::MsrBitmap};

pub struct Vmm {
    /// The number of logical/virtual processors
    pub processor_count: u32,

    /// A vector of Vcpus
    pub vcpu_table: Vec<Vcpu>,

    /// The virtual address of the MsrBitmap naturally aligned 4-KByte region of memory
    pub msr_bitmap: Box<MsrBitmap, PhysicalAllocator>,

    /// The physical address of the MsrBitmap naturally aligned 4-KByte region of memory
    pub msr_bitmap_physical_address: u64,
}

impl Vmm { 
    pub fn new() -> Result<Self, HypervisorError> {
        Ok(Self {
            processor_count: processor_count(),
            vcpu_table: Vec::new(),
            msr_bitmap: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() }, //maybe move later to the bitmap itself and return here
            msr_bitmap_physical_address: 0,
        })
    }

    pub fn init_vcpu(&mut self) -> Result<(), HypervisorError> {
        log::info!("[+] Vcpu::new()");
        self.vcpu_table.push(Vcpu::new()?);

        Ok(())
    }

    /* 
    CR0, CR3, CR4
    DR7
    RSP, RIP, RFLAGS
    Segment Base Addresses/Selectors/Limits/Access Rights for the items below
        ES, CS, SS, DS, FS, GS, LDTR, GDTR, IDTR, and TR
    And the following MSR’s
        IA32_DEBUGCTL
        IA32_SYSENTER_CS
        IA32_SYSENTER_ESP
        IA32_SYSENTER_EIP
        IA32_PERF_CONTROL_GLOBAL
        IA32_PAT
        IA32_EFER
        IA32_BNDCFS
    */
    pub fn init_guest_register_state(&self, index: usize) -> Result<(), HypervisorError> {
        log::info!("[+] Guest Register State");

        // Control Registers
        unsafe { 
            Support::vmwrite(guest::CR0, controlregs::cr0().bits() as u64)?;
            Support::vmwrite(guest::CR3, controlregs::cr3())?;
            Support::vmwrite(guest::CR4, controlregs::cr4().bits() as u64)?;
            
            // Control Register Shadows
            //Support::vmwrite(x86::vmx::vmcs::control::CR0_READ_SHADOW, controlregs::cr0().bits() as u64)?;
            //Support::vmwrite(x86::vmx::vmcs::control::CR4_READ_SHADOW, controlregs::cr4().bits() as u64)?;
        }
        log::info!("[+] Guest Control Registers initialized!");
    
        // Debug Register
        unsafe { Support::vmwrite(guest::DR7, debugregs::dr7().0 as u64)? };
        log::info!("[+] Guest Debug Registers initialized!");
    
        // Stack Pointer (NEED TO FIX OR WON'T WORK)
        Support::vmwrite(guest::RSP, self.vcpu_table[index].guest_rsp)?;
        Support::vmwrite(guest::RIP, self.vcpu_table[index].guest_rip)?;
        log::info!("[+] Guest STACK and Instruction Registers initialized!");
    
        // RFLAGS
        // In 64-bit mode, EFLAGS is extended to 64 bits and called RFLAGS. 
        // The upper 32 bits of RFLAGS register is reserved. The lower 32 bits of RFLAGS is the same as EFLAGS.
        Support::vmwrite(guest::RFLAGS, bits64::rflags::read().bits())?;
        log::info!("[+] Guest RFLAGS Registers initialized!");

        // MSR's
        unsafe {
            Support::vmwrite(guest::IA32_DEBUGCTL_FULL, msr::rdmsr(msr::IA32_DEBUGCTL))?;
            Support::vmwrite(guest::IA32_DEBUGCTL_HIGH, msr::rdmsr(msr::IA32_DEBUGCTL))?;
            Support::vmwrite(guest::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP))?;
            Support::vmwrite(guest::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP))?;
            Support::vmwrite(guest::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS))?;
            Support::vmwrite(guest::LINK_PTR_FULL, !0)?; //0xffffffffffffffff
            Support::vmwrite(guest::LINK_PTR_HIGH, !0)?; //0xffffffffffffffff
            Support::vmwrite(guest::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE))?;
            Support::vmwrite(guest::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE))?;
        }

        log::info!("[+] Guest MSRs initialized!");
    
        Ok(())
    }
    


    /// Ensures that VMCS data maintained on the processor is copied to the VMCS region located at 4KB-aligned physical address addr and initializes some parts of it. (Intel Manual: 25.11.3 Initializing a VMCS)
    pub fn init_vmclear(&mut self, index: usize) -> Result<(), HypervisorError> {
        Support::vmclear(self.vcpu_table[index].vmcs_physical_address)?;
        Ok(())
    }

    /* 
    /// Allocate a naturally aligned 4-KByte region of memory to avoid VM exits on MSR accesses when using rdmsr or wrmsr (Intel Manual: 25.6.2 Processor-Based VM-Execution Controls)
    pub fn init_msr_bitmap(&mut self, index: usize) -> Result<(), HypervisorError> {
        self.vcpu_table[index].msr_bitmap_physical_address = PhysicalAddress::pa_from_va(self.vcpu_table[index].msr_bitmap.as_mut() as *mut _ as _);

        if self.vcpu_table[index].msr_bitmap_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::info!("[+] VCPU: {}, MSRBitmap Virtual Address: {:p}", index, self.vcpu_table[index].msr_bitmap);
        log::info!("[+] VCPU: {}, MSRBitmap Physical Addresss: 0x{:x}", index, self.vcpu_table[index].msr_bitmap_physical_address);

        Ok(())
    }
    */
    
    /// Allocate a naturally aligned 4-KByte region of memory to enable VMX operation (Intel Manual: 25.11.5 VMXON Region)
    pub fn init_vmxon(&mut self, index: usize) -> Result<(), HypervisorError> {
        self.vcpu_table[index].vmxon_physical_address = PhysicalAddress::pa_from_va(self.vcpu_table[index].vmxon.as_mut() as *mut _ as _);

        if self.vcpu_table[index].vmxon_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::info!("[+] VCPU: {}, VMXON Virtual Address: {:p}", index, self.vcpu_table[index].vmxon);
        log::info!("[+] VCPU: {}, VMXON Physical Addresss: 0x{:x}", index, self.vcpu_table[index].vmxon_physical_address);

        self.vcpu_table[index].vmxon.revision_id = Support::get_vmcs_revision_id();
        self.vcpu_table[index].vmxon.as_mut().revision_id.set_bit(31, false);

        Support::vmxon(self.vcpu_table[index].vmxon_physical_address)?;
        log::info!("[+] VMXON successful!");

        Ok(())
    }

    /// Allocate a naturally aligned 4-KByte region of memory for VMCS region (Intel Manual: 25.2 Format of The VMCS Region)
    pub fn init_vmcs(&mut self, index: usize) -> Result<(), HypervisorError> {
        self.vcpu_table[index].vmcs_physical_address = PhysicalAddress::pa_from_va(self.vcpu_table[index].vmcs.as_mut() as *mut _ as _);

        if self.vcpu_table[index].vmcs_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::info!("[+] VCPU: {}, VMCS Virtual Address: {:p}", index, self.vcpu_table[index].vmcs);
        log::info!("[+] VCPU: {}, VMCS Physical Addresss: 0x{:x}", index, self.vcpu_table[index].vmcs_physical_address);

        self.vcpu_table[index].vmcs.revision_id = Support::get_vmcs_revision_id();
        self.vcpu_table[index].vmcs.as_mut().revision_id.set_bit(31, false);

        Support::vmptrld(self.vcpu_table[index].vmcs_physical_address)?;
        log::info!("[+] VMPTRLD successful!");

        Ok(())
    }
}