extern crate alloc;
use alloc::{vec::Vec};
use bitfield::{BitMut};
use x86::{msr::{self}, controlregs::{self}, vmx::{vmcs::{guest, host}, self}, debugregs, bits64, segmentation, task, dtables};
use crate::{vcpu::Vcpu, error::HypervisorError, processor::processor_count, support::{Support}, addresses::{PhysicalAddress}};

pub struct Vmm {
    /// The number of logical/virtual processors
    pub processor_count: u32,

    /// A vector of Vcpus
    pub vcpu_table: Vec<Vcpu>,
}

impl Vmm { 
    pub fn new() -> Result<Self, HypervisorError> {
        Ok(Self {
            processor_count: processor_count(),
            vcpu_table: Vec::new(),
        })
    }

    pub fn init_vcpu(&mut self) -> Result<(), HypervisorError> {
        log::info!("[+] Vcpu::new()");
        self.vcpu_table.push(Vcpu::new()?);

        Ok(())
    }

    #[allow(dead_code)]
    pub fn init_vmcs_controls() -> Result<(), HypervisorError> {
        // Control Register Shadows
        unsafe { Support::vmwrite(x86::vmx::vmcs::control::CR0_READ_SHADOW, controlregs::cr0().bits() as u64)? };
        unsafe { Support::vmwrite(x86::vmx::vmcs::control::CR4_READ_SHADOW, controlregs::cr4().bits() as u64)? };
        log::info!("VMCS Shadow Registers initialized!");

        /* Time-stamp counter offset */
        Support::vmwrite(vmx::vmcs::control::TSC_OFFSET_FULL, 0)?;
        Support::vmwrite(vmx::vmcs::control::TSC_OFFSET_HIGH, 0)?;
        
        Support::vmwrite(vmx::vmcs::control::PAGE_FAULT_ERR_CODE_MASK, 0)?;
        Support::vmwrite(vmx::vmcs::control::PAGE_FAULT_ERR_CODE_MATCH, 0)?;
        
        Support::vmwrite(vmx::vmcs::control::VMEXIT_MSR_STORE_COUNT, 0)?;
        Support::vmwrite(vmx::vmcs::control::VMEXIT_MSR_LOAD_COUNT, 0)?;
        
        Support::vmwrite(vmx::vmcs::control::VMENTRY_MSR_LOAD_COUNT, 0)?;
        Support::vmwrite(vmx::vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, 0)?;
        log::info!("VMCS Time-stamp counter offset initialized!");

        Ok(())
    }

    /* 
    *Sigh* It's so annoying setting the following values in your Intel hypervisor. Isn't there an easier way?
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
    #[allow(dead_code)]
    /// Initialize the guest state for the currently loaded vmcs.
    pub fn init_guest_register_state(&self, index: usize) -> Result<(), HypervisorError> {
        log::info!("[+] Guest Register State");

        // Guest Control Registers
        unsafe { 
            Support::vmwrite(guest::CR0, controlregs::cr0().bits() as u64)?;
            Support::vmwrite(guest::CR3, controlregs::cr3())?;
            Support::vmwrite(guest::CR4, controlregs::cr4().bits() as u64)?;
        }
        log::info!("[+] Guest Control Registers initialized!");
    
        // Guest Debug Register
        unsafe { Support::vmwrite(guest::DR7, debugregs::dr7().0 as u64)? };
        log::info!("[+] Guest Debug Registers initialized!");
    
        // Guest RSP and RIP (NEED TO FIX OR WON'T WORK ????????????????????????????????????????????????????)
        Support::vmwrite(guest::RSP, self.vcpu_table[index].guest_rsp)?;
        Support::vmwrite(guest::RIP, self.vcpu_table[index].guest_rip)?;
        log::info!("[+] Guest RSP and RIP initialized!");
    
        // Guest RFLAGS
        Support::vmwrite(guest::RFLAGS, bits64::rflags::read().bits())?;
        log::info!("[+] Guest RFLAGS Registers initialized!");

        // Guest Segment Selector
        Support::vmwrite(guest::CS_SELECTOR, segmentation::cs().bits() as u64)?;
        Support::vmwrite(guest::SS_SELECTOR, segmentation::ss().bits() as u64)?;
        Support::vmwrite(guest::DS_SELECTOR, segmentation::ds().bits() as u64)?;
        Support::vmwrite(guest::ES_SELECTOR, segmentation::es().bits() as u64)?;
        Support::vmwrite(guest::FS_SELECTOR, segmentation::fs().bits() as u64)?;
        Support::vmwrite(guest::GS_SELECTOR, segmentation::gs().bits() as u64)?;
        unsafe { Support::vmwrite(guest::LDTR_SELECTOR, dtables::ldtr().bits() as u64)? };
        unsafe { Support::vmwrite(guest::TR_SELECTOR, task::tr().bits() as u64)? };
        log::info!("[+] Guest Segmentation Selector initialized!");

        // Guest Segment Limit
        Support::vmwrite(guest::CS_LIMIT, Support::load_segment_limit(segmentation::cs().bits()) as u64)?;
        Support::vmwrite(guest::SS_LIMIT, Support::load_segment_limit(segmentation::ss().bits()) as u64)?;
        Support::vmwrite(guest::DS_LIMIT, Support::load_segment_limit(segmentation::ds().bits()) as u64)?;
        Support::vmwrite(guest::ES_LIMIT, Support::load_segment_limit(segmentation::es().bits()) as u64)?;
        Support::vmwrite(guest::FS_LIMIT, Support::load_segment_limit(segmentation::fs().bits()) as u64)?;
        Support::vmwrite(guest::GS_LIMIT, Support::load_segment_limit(segmentation::fs().bits()) as u64)?;
        unsafe { Support::vmwrite(guest::LDTR_LIMIT, Support::load_segment_limit(dtables::ldtr().bits()) as u64)? };
        unsafe { Support::vmwrite(guest::TR_LIMIT, Support::load_segment_limit(task::tr().bits()) as u64)? };
        log::info!("[+] Guest Segment Limit initialized!");

        // Guest Segment Access Writes
        Support::vmwrite(guest::CS_ACCESS_RIGHTS, Support::read_access_rights(segmentation::cs().bits()))?;
        Support::vmwrite(guest::SS_ACCESS_RIGHTS, Support::read_access_rights(segmentation::ss().bits()))?;
        Support::vmwrite(guest::DS_ACCESS_RIGHTS, Support::read_access_rights(segmentation::ds().bits()))?;
        Support::vmwrite(guest::ES_ACCESS_RIGHTS, Support::read_access_rights(segmentation::es().bits()))?;
        Support::vmwrite(guest::FS_ACCESS_RIGHTS, Support::read_access_rights(segmentation::fs().bits()))?;
        Support::vmwrite(guest::GS_ACCESS_RIGHTS, Support::read_access_rights(segmentation::gs().bits()))?;
        unsafe { Support::vmwrite(guest::LDTR_ACCESS_RIGHTS, Support::read_access_rights(dtables::ldtr().bits()))? };
        unsafe { Support::vmwrite(guest::TR_ACCESS_RIGHTS, Support::read_access_rights(task::tr().bits()))? };
        log::info!("[+] Guest Segment Access Writes initialized!");
        
        // Guest GDTR and LDTR
        let mut guest_gdtr: dtables::DescriptorTablePointer<u64> = Default::default();
        let mut guest_idtr: dtables::DescriptorTablePointer<u64> = Default::default();
        unsafe { dtables::sgdt(&mut guest_gdtr) };
        unsafe { dtables::sidt(&mut guest_idtr) };
        Support::vmwrite(guest::GDTR_LIMIT, guest_gdtr.limit as u64)?;
        Support::vmwrite(guest::IDTR_LIMIT, guest_idtr.limit as u64)?;
        Support::vmwrite(guest::GDTR_BASE, guest_gdtr.base as u64)?;
        Support::vmwrite(guest::IDTR_BASE, guest_idtr.base as u64)?;
        
        //Support::vmwrite(guest::TR_BASE, guest_gdtr.base)?; //wrong ???
        //Support::vmwrite(guest::LDTR_BASE, guest_gdtr.base)?; //wrong ???
        log::info!("[+] Guest GDTR and LDTR initialized!");

        // Guest MSR's
        unsafe {
            Support::vmwrite(guest::IA32_DEBUGCTL_FULL, msr::rdmsr(msr::IA32_DEBUGCTL))?;
            Support::vmwrite(guest::IA32_DEBUGCTL_HIGH, msr::rdmsr(msr::IA32_DEBUGCTL))?;
            Support::vmwrite(guest::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS))?;
            Support::vmwrite(guest::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP))?;
            Support::vmwrite(guest::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP))?;
            Support::vmwrite(guest::LINK_PTR_FULL, u64::MAX)?;
            Support::vmwrite(guest::LINK_PTR_HIGH, u64::MAX)?;
            
            Support::vmwrite(guest::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE))?;
            Support::vmwrite(guest::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE))?;
                        
            log::info!("[+] Guest MSRs initialized!");
        }
        
        log::info!("[+] Guest initialized!");
    
        Ok(())
    }

    #[allow(dead_code)]
    /// Initialize the host state for the currently loaded vmcs.
    pub fn init_host_register_state(&mut self, index: usize) -> Result<(), HypervisorError> {
        log::info!("[+] Host Register State");
        // Host Control Registers
        unsafe { 
            Support::vmwrite(host::CR0, controlregs::cr0().bits() as u64)?;
            Support::vmwrite(host::CR3, controlregs::cr3())?;
            Support::vmwrite(host::CR4, controlregs::cr4().bits() as u64)?;            
        }
        log::info!("[+] Host Control Registers initialized!");

        // Host RSP/RIP (FIX OR WON'T WORK ????????????????????????????????????????????????????????????)
        Support::vmwrite(host::RSP, &mut self.vcpu_table[index].vmm_stack.vmm_context as *mut _ as _)?;
        //Support::vmwrite(host::RIP, vmm_entrypoint)?;

        // Host Segment Selector
        const SELECTOR_MASK: u16 = 0xF8;
        Support::vmwrite(host::CS_SELECTOR, (segmentation::cs().bits() & SELECTOR_MASK) as u64)?;
        Support::vmwrite(host::SS_SELECTOR, (segmentation::ss().bits() & SELECTOR_MASK) as u64)?;
        Support::vmwrite(host::DS_SELECTOR, (segmentation::ds().bits() & SELECTOR_MASK) as u64)?;
        Support::vmwrite(host::ES_SELECTOR, (segmentation::es().bits() & SELECTOR_MASK) as u64)?;
        Support::vmwrite(host::FS_SELECTOR, (segmentation::fs().bits() & SELECTOR_MASK) as u64)?;
        Support::vmwrite(host::GS_SELECTOR, (segmentation::gs().bits() & SELECTOR_MASK) as u64)?;
        unsafe { Support::vmwrite(host::TR_SELECTOR, (task::tr().bits() & SELECTOR_MASK) as u64)? };
        log::info!("[+] Host Segmentation Registers initialized!");

        // Host GDTR and LDTR
        let mut host_gdtr: dtables::DescriptorTablePointer<u64> = Default::default();
        let mut host_idtr: dtables::DescriptorTablePointer<u64> = Default::default();
        unsafe { dtables::sgdt(&mut host_gdtr) };
        unsafe { dtables::sidt(&mut host_idtr) };
        Support::vmwrite(host::FS_BASE, host_gdtr.base as u64)?;
        Support::vmwrite(host::GS_BASE, host_gdtr.base as u64)?;
        //Support::vmwrite(host::TR_BASE, host_gdtr.base as u64)?; // wrong??????????????????????????????
        Support::vmwrite(host::GDTR_BASE, host_gdtr.base as u64)?;
        Support::vmwrite(host::IDTR_BASE, host_idtr.base as u64)?;
        log::info!("[+] Host TR, GDTR and LDTR initialized!");

        // Host MSR's
        unsafe {
            Support::vmwrite(host::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS))?;
            Support::vmwrite(host::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP))?;
            Support::vmwrite(host::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP))?;
            
            Support::vmwrite(host::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE))?;
            Support::vmwrite(host::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE))?;
            Support::vmwrite(host::TR_BASE, msr::rdmsr(vmx::vmcs::host::TR_BASE))?;
            
            //Maybe more??????????????????????????????????????????????????????????????????????????
            log::info!("[+] Host MSRs initialized!");
        }
        
        log::info!("[+] Host initialized!");

        Ok(())
    }

    

    /// Ensures that VMCS data maintained on the processor is copied to the VMCS region located at 4KB-aligned physical address addr and initializes some parts of it. (Intel Manual: 25.11.3 Initializing a VMCS)
    pub fn init_vmclear(&mut self, index: usize) -> Result<(), HypervisorError> {
        Support::vmclear(self.vcpu_table[index].vmcs_physical_address)?;
        log::info!("[+] VMCLEAR successful!");
        Ok(())
    }

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