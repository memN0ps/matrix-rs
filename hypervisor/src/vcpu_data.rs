use alloc::boxed::Box;
use bitfield::BitMut;
use kernel_alloc::PhysicalAllocator;
use crate::{vmxon_region::VmxonRegion, utils::addresses::{physical_address}, error::HypervisorError, support, vmexit_handler::vmexit_stub, utils::{segmentation::Segment, controls::{adjust_vmx_controls, segment_limit, VmxControl}}, utils::tables::GdtStruct};
use x86::{vmx::{self, vmcs::{control::{PrimaryControls, SecondaryControls, EntryControls, ExitControls}, guest, host}}, msr, controlregs, segmentation::{self}, task, dtables, debugregs, bits64};
use x86_64::instructions::tables::{sgdt, sidt};

pub const KERNEL_STACK_SIZE: usize = 0x6000;
pub const STACK_CONTENTS_SIZE: usize = KERNEL_STACK_SIZE;

#[derive(Clone, Copy)]
#[repr(C, align(4096))]
pub struct HostStackLayout {
    pub stack_contents: [u8; STACK_CONTENTS_SIZE],
    //pub self_data: *mut u64, // A pointer VcpuData
}

pub struct VcpuData {
    /// The virtual and physical address of the Vmcs naturally aligned 4-KByte region of memory
    pub vmcs_region: Box<VmxonRegion, PhysicalAllocator>,
    pub vmcs_region_physical_address: u64,

    /// The virtual and physical address of the Vmxon naturally aligned 4-KByte region of memory
    pub vmxon_region: Box<VmxonRegion, PhysicalAllocator>,
    pub vmxon_region_physical_address: u64,

    pub host_stack_layout: Box<HostStackLayout, PhysicalAllocator>,
}

impl VcpuData {
    pub fn new() -> Result<Box<Self>, HypervisorError> {
        
        let instance = Self {
            vmcs_region: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            vmcs_region_physical_address: 0,
            vmxon_region: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            vmxon_region_physical_address: 0,
            host_stack_layout: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
        };

        let mut instance = Box::new(instance);

        //instance.host_stack_layout.self_data = &mut *instance as *mut _ as _;
                
        log::info!("[+] init_vmxon_region");
        instance.init_vmxon_region()?;

        log::info!("[+] init_vmcs_region");
        instance.init_vmcs_region()?;

        log::info!("[+] init_vmclear");
        instance.init_vmclear()?;

        log::info!("[+] init_vmptrld");
        instance.init_vmptrld()?;

        // Host and Guest Registers
        log::info!("[+] init_vmcs_control_values");
        instance.init_vmcs_control_values()?;

        log::info!("[+] init_guest_register_state");
        instance.init_guest_register_state()?;

        // When a VMEXIT occurs, we want to point our HOST_RIP to our vmexit stub (VMM Entry) to handle the errors and see why it occured
        // When a VMEXIT occurs, we want to point our HOST_RSP to our newly allocated stack (HostStackLayout) as need the space to call functions like vmexit handler
        // We need to ADD the STACK_CONTENTS_SIZE (0x6000) so HOST_RSP points towards the bottom of the stack
        // This is because when things are pushed on top of the stack, RSP is SUBTRACTED so we need space above.
        // This is because if we call a function it pushes the return address to the top of the stack and if we're already at the top, we'll have an kernel stack overflow
        // The - 8 bytes is just padding so we're not competely at the bottom of the stack.
        log::info!("[+] init_host_register_state");
        instance.init_host_register_state()?;

        Ok(instance)
    }

    /// Allocate a naturally aligned 4-KByte VMXON region of memory to enable VMX operation (Intel Manual: 25.11.5 VMXON Region)
    pub fn init_vmxon_region(&mut self) -> Result<(), HypervisorError> {
        self.vmxon_region_physical_address = physical_address(self.vmxon_region.as_ref() as *const _ as _).as_u64();

        if self.vmxon_region_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::info!("[+] VMXON Region Virtual Address: {:p}", self.vmxon_region);
        log::info!("[+] VMXON Region Physical Addresss: 0x{:x}", self.vmxon_region_physical_address);

        self.vmxon_region.revision_id = support::get_vmcs_revision_id();
        self.vmxon_region.as_mut().revision_id.set_bit(31, false);

        support::vmxon(self.vmxon_region_physical_address)?;
        log::info!("[+] VMXON successful!");

        Ok(())
    }

    /// Allocate a naturally aligned 4-KByte VMCS region of memory (Intel Manual: 25.11.5 VMCS Region)
    pub fn init_vmcs_region(&mut self) -> Result<(), HypervisorError> {
        self.vmcs_region_physical_address = physical_address(self.vmcs_region.as_ref() as *const _ as _).as_u64();

        if self.vmcs_region_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::info!("[+] VMCS Region Virtual Address: {:p}", self.vmcs_region);
        log::info!("[+] VMCS Region Physical Addresss: 0x{:x}", self.vmcs_region_physical_address);

        self.vmcs_region.revision_id = support::get_vmcs_revision_id();
        self.vmcs_region.as_mut().revision_id.set_bit(31, false);

        log::info!("[+] VMCS successful!");

        Ok(())
    }

    /// Ensures that VMCS data maintained on the processor is copied to the VMCS region located at 4KB-aligned physical address addr and initializes some parts of it. (Intel Manual: 25.11.3 Initializing a VMCS)
    pub fn init_vmclear(&mut self) -> Result<(), HypervisorError> {
        support::vmclear(self.vmcs_region_physical_address)?;
        log::info!("[+] VMCLEAR successful!");
        Ok(())
    }

    ///Load current VMCS pointer.
    pub fn init_vmptrld(&mut self) -> Result<(), HypervisorError> {
        support::vmptrld(self.vmcs_region_physical_address)?;
        log::info!("[+] VMPTRLD successful!");
        Ok(())
    }

    /// Initialize the VMCS control values for the currently loaded vmcs.
    pub fn init_vmcs_control_values(&mut self) -> Result<(), HypervisorError> {
        const PRIMARY_CTL: u64 = (PrimaryControls::HLT_EXITING.bits() | /*PrimaryControls::USE_MSR_BITMAPS.bits() |*/ PrimaryControls::SECONDARY_CONTROLS.bits()) as u64;
        const SECONDARY_CTL: u64 = (SecondaryControls::ENABLE_RDTSCP.bits() | SecondaryControls::ENABLE_XSAVES_XRSTORS.bits() | SecondaryControls::ENABLE_INVPCID.bits() /* | SecondaryControls::ENABLE_EPT.bits() */) as u64;
        const ENTRY_CTL: u64 = (EntryControls::IA32E_MODE_GUEST.bits()) as u64;
        const EXIT_CTL: u64 = (ExitControls::HOST_ADDRESS_SPACE_SIZE.bits() | ExitControls::ACK_INTERRUPT_ON_EXIT.bits()) as u64;
        const PINBASED_CTL: u64 = 0;

        // PrimaryControls (x86::msr::IA32_VMX_PROCBASED_CTLS)
        support::vmwrite(vmx::vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, 
            adjust_vmx_controls(VmxControl::ProcessorBased, PRIMARY_CTL))?;
        
        // SecondaryControls (x86::msr::IA32_VMX_PROCBASED_CTLS2)
        support::vmwrite(vmx::vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS, 
            adjust_vmx_controls(VmxControl::ProcessorBased2, SECONDARY_CTL))?;
        
        // EntryControls (x86::msr::IA32_VMX_ENTRY_CTLS)
        support::vmwrite(vmx::vmcs::control::VMENTRY_CONTROLS, 
            adjust_vmx_controls(VmxControl::VmEntry, ENTRY_CTL))?;

        // ExitControls (x86::msr::IA32_VMX_EXIT_CTLS)
        support::vmwrite(vmx::vmcs::control::VMEXIT_CONTROLS, 
            adjust_vmx_controls(VmxControl::VmExit, EXIT_CTL))?;

        // PinbasedControls (x86::msr::IA32_VMX_PINBASED_CTLS)
        support::vmwrite(vmx::vmcs::control::PINBASED_EXEC_CONTROLS, 
            adjust_vmx_controls(VmxControl::PinBased, PINBASED_CTL))?;
        
        log::info!("VMCS Primary, Secondary, Entry, Exit and Pinbased, Controls initialized!");

        // Control Register Shadows
        unsafe { support::vmwrite(x86::vmx::vmcs::control::CR0_READ_SHADOW, controlregs::cr0().bits() as u64)? };
        unsafe { support::vmwrite(x86::vmx::vmcs::control::CR4_READ_SHADOW, controlregs::cr4().bits() as u64)? };
        log::info!("VMCS Controls Shadow Registers initialized!");

        /* 
        /* Time-stamp counter offset */
        support::vmwrite(vmx::vmcs::control::TSC_OFFSET_FULL, 0)?;
        support::vmwrite(vmx::vmcs::control::TSC_OFFSET_HIGH, 0)?;
        support::vmwrite(vmx::vmcs::control::PAGE_FAULT_ERR_CODE_MASK, 0)?;
        support::vmwrite(vmx::vmcs::control::PAGE_FAULT_ERR_CODE_MATCH, 0)?;
        support::vmwrite(vmx::vmcs::control::VMEXIT_MSR_STORE_COUNT, 0)?;
        support::vmwrite(vmx::vmcs::control::VMEXIT_MSR_LOAD_COUNT, 0)?;
        support::vmwrite(vmx::vmcs::control::VMENTRY_MSR_LOAD_COUNT, 0)?;
        support::vmwrite(vmx::vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, 0)?;
        log::info!("VMCS Time-stamp counter offset initialized!");
        */

        // VMCS Controls Bitmap
        //support::vmwrite(vmx::vmcs::control::MSR_BITMAPS_ADDR_FULL, msr_bitmap_physical_address)?;
        //support::vmwrite(vmx::vmcs::control::MSR_BITMAPS_ADDR_HIGH, msr_bitmap_physical_address)?;
        //log::info!("VMCS Controls Bitmap initialized!");

        log::info!("[+] VMCS Controls initialized!");

        Ok(())
    }


    /// Initialize the guest state for the currently loaded vmcs.
    pub fn init_guest_register_state(&self) -> Result<(), HypervisorError> {
        log::info!("[+] Guest Register State");

        // Guest Control Registers
        unsafe { 
            support::vmwrite(guest::CR0, controlregs::cr0().bits() as u64)?;
            support::vmwrite(guest::CR3, controlregs::cr3())?;
            support::vmwrite(guest::CR4, controlregs::cr4().bits() as u64)?;
        }
        log::info!("[+] Guest Control Registers initialized!");

        // Guest Debug Register
        unsafe { support::vmwrite(guest::DR7, debugregs::dr7().0 as u64)? };
        log::info!("[+] Guest Debug Registers initialized!");

        // Guest RSP and RIP
        support::vmwrite(guest::RSP, bits64::registers::rsp())?;
        support::vmwrite(guest::RIP, bits64::registers::rip())?;
        log::info!("[+] Guest RSP and RIP initialized!");

        // Guest RFLAGS
        support::vmwrite(guest::RFLAGS, bits64::rflags::read().bits())?;
        log::info!("[+] Guest RFLAGS Registers initialized!");

        // Guest Segment Selector
        support::vmwrite(guest::CS_SELECTOR, segmentation::cs().bits() as u64)?;
        support::vmwrite(guest::SS_SELECTOR, segmentation::ss().bits() as u64)?;
        support::vmwrite(guest::DS_SELECTOR, segmentation::ds().bits() as u64)?;
        support::vmwrite(guest::ES_SELECTOR, segmentation::es().bits() as u64)?;
        support::vmwrite(guest::FS_SELECTOR, segmentation::fs().bits() as u64)?;
        support::vmwrite(guest::GS_SELECTOR, segmentation::gs().bits() as u64)?;
        unsafe { support::vmwrite(guest::LDTR_SELECTOR, dtables::ldtr().bits() as u64)? };
        unsafe { support::vmwrite(guest::TR_SELECTOR, task::tr().bits() as u64)? };
        log::info!("[+] Guest Segmentation Selector initialized!");

        // Guest Segment Limit
        support::vmwrite(guest::CS_LIMIT, segment_limit(segmentation::cs().bits()) as _)?;
        support::vmwrite(guest::SS_LIMIT, segment_limit(segmentation::ss().bits()) as _)?;
        support::vmwrite(guest::DS_LIMIT, segment_limit(segmentation::ds().bits()) as _)?;
        support::vmwrite(guest::ES_LIMIT, segment_limit(segmentation::es().bits()) as _)?;
        support::vmwrite(guest::FS_LIMIT, segment_limit(segmentation::fs().bits()) as _)?;
        support::vmwrite(guest::GS_LIMIT, segment_limit(segmentation::gs().bits()) as _)?;
        unsafe { support::vmwrite(guest::LDTR_LIMIT, segment_limit(dtables::ldtr().bits()) as _)? };
        unsafe { support::vmwrite(guest::TR_LIMIT, segment_limit(task::tr().bits()) as _)? };
        log::info!("[+] Guest Segment Limit initialized!");

        // GDTR and IDTR Limit/Base
        let gdt = GdtStruct::sgdt();
        let idt = sidt();

        let gdtr_base = gdt.base.as_u64();
        let gdtr_limit = gdt.limit as u64;

        let idtr_base = idt.base.as_u64();
        let idtr_limit = idt.limit as u64;

        // Guest Segment Access Writes ?????????????????????????????????????????????????????????????? RIGHTS?
        support::vmwrite(guest::CS_ACCESS_RIGHTS, Segment::from_selector(segmentation::cs(), &gdt).access_rights.bits() as _)?;
        support::vmwrite(guest::SS_ACCESS_RIGHTS, Segment::from_selector(segmentation::ss(), &gdt).access_rights.bits() as _)?;
        support::vmwrite(guest::DS_ACCESS_RIGHTS, Segment::from_selector(segmentation::ds(), &gdt).access_rights.bits() as _)?;
        support::vmwrite(guest::ES_ACCESS_RIGHTS, Segment::from_selector(segmentation::es(), &gdt).access_rights.bits() as _)?;
        support::vmwrite(guest::FS_ACCESS_RIGHTS, Segment::from_selector(segmentation::fs(), &gdt).access_rights.bits() as _)?;
        support::vmwrite(guest::GS_ACCESS_RIGHTS, Segment::from_selector(segmentation::gs(), &gdt).access_rights.bits() as _)?;
        unsafe { support::vmwrite(guest::LDTR_ACCESS_RIGHTS, Segment::from_selector(dtables::ldtr(), &gdt).access_rights.bits() as _)? };
        unsafe { support::vmwrite(guest::TR_ACCESS_RIGHTS, Segment::from_selector(task::tr(), &gdt).access_rights.bits() as _)? };
        log::info!("[+] Guest Segment Access Writes initialized!");
        
        // Guest Segment GDTR and LDTR
        support::vmwrite(guest::GDTR_LIMIT, gdtr_limit as _)?;
        support::vmwrite(guest::IDTR_LIMIT, idtr_limit as _)?;
        support::vmwrite(guest::GDTR_BASE, gdtr_base)?;
        support::vmwrite(guest::IDTR_BASE, idtr_base)?;
        log::info!("[+] Guest GDTR and LDTR Limit and Base initialized!");

        // Guest Segment, CS, SS, DS, ES ??????????????????????????????????????????????? BASE
        support::vmwrite(guest::CS_BASE, Segment::from_selector(segmentation::cs(), &gdt).base)?;
        support::vmwrite(guest::SS_BASE, Segment::from_selector(segmentation::ss(), &gdt).base)?;
        support::vmwrite(guest::DS_BASE, Segment::from_selector(segmentation::ds(), &gdt).base)?;
        support::vmwrite(guest::ES_BASE, Segment::from_selector(segmentation::es(), &gdt).base)?;
        unsafe { support::vmwrite(guest::LDTR_BASE, Segment::from_selector(dtables::ldtr(), &gdt).base)? };
        unsafe { support::vmwrite(guest::TR_BASE, Segment::from_selector(task::tr(), &gdt).base)? };
        
        log::info!("[+] Guest Segment, CS, SS, DS, ES, LDTR and TR initialized!");

        // Guest MSR's
        unsafe {
            support::vmwrite(guest::IA32_DEBUGCTL_FULL, msr::rdmsr(msr::IA32_DEBUGCTL))?;
            support::vmwrite(guest::IA32_DEBUGCTL_HIGH, msr::rdmsr(msr::IA32_DEBUGCTL))?;
            support::vmwrite(guest::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS))?;
            support::vmwrite(guest::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP))?;
            support::vmwrite(guest::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP))?;
            support::vmwrite(guest::LINK_PTR_FULL, u64::MAX)?;
            support::vmwrite(guest::LINK_PTR_HIGH, u64::MAX)?;
            
            support::vmwrite(guest::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE))?;
            support::vmwrite(guest::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE))?;
            log::info!("[+] Guest MSRs initialized!");
        }

        log::info!("[+] Guest initialized!");

        Ok(())
    }

    /// Initialize the host state for the currently loaded vmcs.
    pub fn init_host_register_state(&mut self) -> Result<(), HypervisorError> {
        log::info!("[+] Host Register State");
        
        // Host Control Registers
        unsafe { 
            support::vmwrite(host::CR0, controlregs::cr0().bits() as u64)?;
            support::vmwrite(host::CR3, controlregs::cr3())?;
            support::vmwrite(host::CR4, controlregs::cr4().bits() as u64)?;
        } 
        log::info!("[+] Host Control Registers initialized!");

        // Host RSP/RIP
        let host_rsp = (self.host_stack_layout.as_mut() as *const _ as u64) + STACK_CONTENTS_SIZE as u64 - 8;
        let vmexit_stub = vmexit_stub as u64;
        support::vmwrite(host::RSP, host_rsp)?; //self.host_stack_layout.self_data as _
        support::vmwrite(host::RIP, vmexit_stub)?;

        // Host Segment Selector
        const SELECTOR_MASK: u16 = 0xF8;
        support::vmwrite(host::CS_SELECTOR, (segmentation::cs().bits() & SELECTOR_MASK) as u64)?;
        support::vmwrite(host::SS_SELECTOR, (segmentation::ss().bits() & SELECTOR_MASK) as u64)?;
        support::vmwrite(host::DS_SELECTOR, (segmentation::ds().bits() & SELECTOR_MASK) as u64)?;
        support::vmwrite(host::ES_SELECTOR, (segmentation::es().bits() & SELECTOR_MASK) as u64)?;
        support::vmwrite(host::FS_SELECTOR, (segmentation::fs().bits() & SELECTOR_MASK) as u64)?;
        support::vmwrite(host::GS_SELECTOR, (segmentation::gs().bits() & SELECTOR_MASK) as u64)?;
        unsafe { support::vmwrite(host::TR_SELECTOR, (task::tr().bits() & SELECTOR_MASK) as u64)? };
        log::info!("[+] Host Segmentation Registers initialized!");

        // GDTR and IDTR Limit/Base
        let gdt = sgdt();
        let idt = sidt();

        let gdtr_base = gdt.base.as_u64();
        //let gdtr_limit = gdt.limit as u64;

        let idtr_base = idt.base.as_u64();
        //let idtr_limit = idt.limit as u64;

        // Host Segment TR, GDTR and LDTR ?????????????????????????????????????????????????????????????????????????????????? BASE?
        unsafe { support::vmwrite(host::TR_BASE, Segment::from_selector(task::tr(), &gdt).base)? };
        support::vmwrite(host::GDTR_BASE, gdtr_base)?;
        support::vmwrite(host::IDTR_BASE, idtr_base)?;
        log::info!("[+] Host TR, GDTR and LDTR initialized!");

        // Host MSR's
        unsafe {
            support::vmwrite(host::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS))?;
            support::vmwrite(host::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP))?;
            support::vmwrite(host::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP))?;
            
            support::vmwrite(host::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE))?;
            support::vmwrite(host::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE))?;
            
            log::info!("[+] Host MSRs initialized!");
        }
        
        log::info!("[+] Host initialized!");

        Ok(())
    }
}