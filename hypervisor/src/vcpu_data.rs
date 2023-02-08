use alloc::boxed::Box;
use bitfield::BitMut;
use kernel_alloc::PhysicalAllocator;
use x86::{vmx::{self, vmcs::{control::{PrimaryControls, SecondaryControls, EntryControls, ExitControls}, guest, host}}, msr};
use crate::{vmcs_region::VmcsRegion, vmxon_region::VmxonRegion, addresses::{physical_address}, error::HypervisorError, support, context::Context, vmexit_reason::vmexit_stub};

pub const KERNEL_STACK_SIZE: usize = 0x6000;
pub const STACK_CONTENTS_SIZE: usize = KERNEL_STACK_SIZE - (core::mem::size_of::<*mut u64>());

#[derive(Clone, Copy)]
#[repr(C, align(4096))]
pub struct HostStackLayout {
    pub stack_contents: [u8; STACK_CONTENTS_SIZE],
    //pub guest_vmcs_pa: u64,
    //pub host_vmcs_pa: u64,
    pub vmm_context: *mut u64, // A pointer VcpuData
}

pub struct VcpuData {
    /// The virtual and physical address of the Vmcs naturally aligned 4-KByte region of memory
    pub vmcs_region: Box<VmcsRegion, PhysicalAllocator>,
    pub vmcs_region_physical_address: u64,

    /// The virtual and physical address of the Vmxon naturally aligned 4-KByte region of memory
    pub vmxon_region: Box<VmxonRegion, PhysicalAllocator>,
    pub vmxon_region_physical_address: u64,

    pub host_stack_layout: Box<HostStackLayout, PhysicalAllocator>,
    pub context: Context,
}

impl VcpuData {
    pub fn new(context: Context) -> Result<Box<Self>, HypervisorError> {
        
        let instance = Self {
            vmcs_region: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            vmcs_region_physical_address: 0,
            vmxon_region: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            vmxon_region_physical_address: 0,
            host_stack_layout: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            context,
        };

        log::info!("[+] Box::new(instance)");
        let mut instance = Box::new(instance);

        instance.host_stack_layout.vmm_context = &mut *instance as *mut _ as _;
                
        log::info!("[+] init_vmxon_region");
        instance.init_vmxon_region()?;

        log::info!("[+] init_vmcs_region");
        instance.init_vmcs_region()?;

        log::info!("[+] init_vmclear");
        instance.init_vmclear()?;

        log::info!("[+] init_vmptrld");
        instance.init_vmptrld()?;

        log::info!("[+] init_vmcs_control_values");
        instance.init_vmcs_control_values()?;

        log::info!("[+] init_host_register_state");
        instance.init_host_register_state()?;

        log::info!("[+] init_guest_register_state");
        instance.init_guest_register_state()?;

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
        // PrimaryControls (x86::msr::IA32_VMX_PROCBASED_CTLS)
        support::vmwrite(vmx::vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, 
            vmx_adjust_entry_controls(msr::IA32_VMX_PROCBASED_CTLS, PrimaryControls::HLT_EXITING.bits() | /*PrimaryControls::USE_MSR_BITMAPS.bits() |*/ PrimaryControls::SECONDARY_CONTROLS.bits()) as u64)?;
        
        // SecondaryControls (x86::msr::IA32_VMX_PROCBASED_CTLS2)
        support::vmwrite(vmx::vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS, 
            vmx_adjust_entry_controls(msr::IA32_VMX_PROCBASED_CTLS2, SecondaryControls::ENABLE_RDTSCP.bits() | SecondaryControls::ENABLE_XSAVES_XRSTORS.bits() | SecondaryControls::ENABLE_INVPCID.bits() /* | SecondaryControls::ENABLE_EPT.bits() */) as u64)?;
        
        // EntryControls (x86::msr::IA32_VMX_ENTRY_CTLS)
        support::vmwrite(vmx::vmcs::control::VMENTRY_CONTROLS, 
            vmx_adjust_entry_controls(msr::IA32_VMX_ENTRY_CTLS, EntryControls::IA32E_MODE_GUEST.bits()) as u64)?;

        // ExitControls (x86::msr::IA32_VMX_EXIT_CTLS)
        support::vmwrite(vmx::vmcs::control::VMEXIT_CONTROLS, 
            vmx_adjust_entry_controls(msr::IA32_VMX_EXIT_CTLS, ExitControls::HOST_ADDRESS_SPACE_SIZE.bits() | ExitControls::ACK_INTERRUPT_ON_EXIT.bits()) as u64)?;

        // PinbasedControls (x86::msr::IA32_VMX_PINBASED_CTLS)
        support::vmwrite(vmx::vmcs::control::PINBASED_EXEC_CONTROLS, 
            vmx_adjust_entry_controls(msr::IA32_VMX_PINBASED_CTLS, 0) as u64)?;
        
        log::info!("VMCS Primary, Secondary, Entry, Exit and Pinbased, Controls initialized!");

        // Control Register Shadows
        support::vmwrite(x86::vmx::vmcs::control::CR0_READ_SHADOW, self.context.cr0)?;
        support::vmwrite(x86::vmx::vmcs::control::CR4_READ_SHADOW, self.context.cr4)?;
        log::info!("VMCS Controls Shadow Registers initialized!");

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
        support::vmwrite(guest::CR0, self.context.cr0)?;
        support::vmwrite(guest::CR3, self.context.cr3)?;
        support::vmwrite(guest::CR4, self.context.cr4)?;
        log::info!("[+] Guest Control Registers initialized!");

        // Guest Debug Register
        support::vmwrite(guest::DR7, self.context.dr7)?;
        log::info!("[+] Guest Debug Registers initialized!");

        // Guest RSP and RIP
        support::vmwrite(guest::RSP, self.context.rsp)?;
        support::vmwrite(guest::RIP, self.context.rip)?;
        log::info!("[+] Guest RSP and RIP initialized!");

        // Guest RFLAGS
        support::vmwrite(guest::RFLAGS, self.context.rflags)?;
        log::info!("[+] Guest RFLAGS Registers initialized!");

        // Guest Segment Selector
        support::vmwrite(guest::CS_SELECTOR, self.context.cs_selector as _)?;
        support::vmwrite(guest::SS_SELECTOR, self.context.ss_selector as _)?;
        support::vmwrite(guest::DS_SELECTOR, self.context.ds_selector as _)?;
        support::vmwrite(guest::ES_SELECTOR, self.context.es_selector as _)?;
        support::vmwrite(guest::FS_SELECTOR, self.context.fs_selector as _)?;
        support::vmwrite(guest::GS_SELECTOR, self.context.gs_selector as _)?;
        support::vmwrite(guest::LDTR_SELECTOR, self.context.ldtr_selector as _)?;
        support::vmwrite(guest::TR_SELECTOR, self.context.tr_selector as _)?;
        log::info!("[+] Guest Segmentation Selector initialized!");

        // Guest Segment Limit
        support::vmwrite(guest::CS_LIMIT, self.context.cs_limit as _)?;
        support::vmwrite(guest::SS_LIMIT, self.context.ss_limit as _)?;
        support::vmwrite(guest::DS_LIMIT, self.context.ds_limit as _)?;
        support::vmwrite(guest::ES_LIMIT, self.context.es_limit as _)?;
        support::vmwrite(guest::FS_LIMIT, self.context.fs_limit as _)?;
        support::vmwrite(guest::GS_LIMIT, self.context.gs_limit as _)?;
        support::vmwrite(guest::LDTR_LIMIT, self.context.ldtr_limit as _)?;
        support::vmwrite(guest::TR_LIMIT, self.context.tr_limit as _)?;
        log::info!("[+] Guest Segment Limit initialized!");

        // Guest Segment Access Writes
        support::vmwrite(guest::CS_ACCESS_RIGHTS, self.context.cs_attrib as _)?;
        support::vmwrite(guest::SS_ACCESS_RIGHTS, self.context.ss_attrib as _)?;
        support::vmwrite(guest::DS_ACCESS_RIGHTS, self.context.ds_attrib as _)?;
        support::vmwrite(guest::ES_ACCESS_RIGHTS, self.context.es_attrib as _)?;
        support::vmwrite(guest::FS_ACCESS_RIGHTS, self.context.fs_attrib as _)?;
        support::vmwrite(guest::GS_ACCESS_RIGHTS, self.context.gs_attrib as _)?;
        support::vmwrite(guest::LDTR_ACCESS_RIGHTS, self.context.ldtr_attrib as _)?;
        support::vmwrite(guest::TR_ACCESS_RIGHTS, self.context.tr_attrib as _)?;
        log::info!("[+] Guest Segment Access Writes initialized!");
        
        // Guest Segment GDTR and LDTR
        support::vmwrite(guest::GDTR_LIMIT, self.context.gdtr_limit as _)?;
        support::vmwrite(guest::IDTR_LIMIT, self.context.idtr_limit as _)?;
        support::vmwrite(guest::GDTR_BASE, self.context.gdtr_base)?;
        support::vmwrite(guest::IDTR_BASE, self.context.idtr_base)?;
        log::info!("[+] Guest GDTR and LDTR Limit and Base initialized!");

        // Guest Segment, CS, SS, DS, ES
        support::vmwrite(guest::CS_BASE, self.context.cs_base)?;
        support::vmwrite(guest::SS_BASE, self.context.ss_base)?;
        support::vmwrite(guest::DS_BASE, self.context.ds_base)?;
        support::vmwrite(guest::ES_BASE, self.context.es_base)?;
        support::vmwrite(guest::LDTR_BASE, self.context.ldtr_base)?;
        support::vmwrite(guest::TR_BASE, self.context.tr_base)?;
        log::info!("[+] Guest Segment, CS, SS, DS, ES, LDTR and TR initialized!");

        // Guest MSR's
        support::vmwrite(guest::IA32_DEBUGCTL_FULL, self.context.dbg_ctl)?;
        support::vmwrite(guest::IA32_DEBUGCTL_HIGH, self.context.dbg_ctl)?;
        support::vmwrite(guest::IA32_SYSENTER_CS, self.context.sysenter_cs)?;
        support::vmwrite(guest::IA32_SYSENTER_ESP, self.context.sysenter_esp)?;
        support::vmwrite(guest::IA32_SYSENTER_EIP, self.context.sysenter_eip)?;
        support::vmwrite(guest::LINK_PTR_FULL, u64::MAX)?;
        support::vmwrite(guest::LINK_PTR_HIGH, u64::MAX)?;
        support::vmwrite(guest::FS_BASE, self.context.fs_base)?;
        support::vmwrite(guest::GS_BASE, self.context.gs_base)?;
        log::info!("[+] Guest MSRs initialized!");

        log::info!("[+] Guest initialized!");

        Ok(())
    }

    /// Initialize the host state for the currently loaded vmcs.
    pub fn init_host_register_state(&mut self) -> Result<(), HypervisorError> {
        log::info!("[+] Host Register State");
        
        // Host Control Registers
        support::vmwrite(host::CR0, self.context.cr0)?;
        support::vmwrite(host::CR3, self.context.cr3)?;
        support::vmwrite(host::CR4, self.context.cr4)?;  
        log::info!("[+] Host Control Registers initialized!");

        // Host RSP/RIP ??????????????????????????????????????????????????????????????????????????????????????????????????????????
        let vmexit_stub = vmexit_stub as u64;
        support::vmwrite(host::RSP, self.host_stack_layout.vmm_context as _)?;
        support::vmwrite(host::RIP, vmexit_stub)?;

        // Host Segment Selector
        const SELECTOR_MASK: u16 = 0xF8;
        support::vmwrite(host::CS_SELECTOR, (self.context.cs_selector & SELECTOR_MASK) as u64)?;
        support::vmwrite(host::SS_SELECTOR, (self.context.ss_selector & SELECTOR_MASK) as u64)?;
        support::vmwrite(host::DS_SELECTOR, (self.context.ds_selector & SELECTOR_MASK) as u64)?;
        support::vmwrite(host::ES_SELECTOR, (self.context.es_selector & SELECTOR_MASK) as u64)?;
        support::vmwrite(host::FS_SELECTOR, (self.context.fs_selector & SELECTOR_MASK) as u64)?;
        support::vmwrite(host::GS_SELECTOR, (self.context.gs_selector & SELECTOR_MASK) as u64)?;
        support::vmwrite(host::TR_SELECTOR, (self.context.tr_selector & SELECTOR_MASK) as u64)?;
        log::info!("[+] Host Segmentation Registers initialized!");

        // Host Segment TR, GDTR and LDTR
        support::vmwrite(host::TR_BASE, self.context.tr_base)?;
        support::vmwrite(host::GDTR_BASE, self.context.gdtr_base)?;
        support::vmwrite(host::IDTR_BASE, self.context.idtr_base)?;
        log::info!("[+] Host TR, GDTR and LDTR initialized!");

        // Host MSR's
        support::vmwrite(host::IA32_SYSENTER_CS, self.context.sysenter_cs)?;
        support::vmwrite(host::IA32_SYSENTER_ESP, self.context.sysenter_esp)?;
        support::vmwrite(host::IA32_SYSENTER_EIP, self.context.sysenter_eip)?;
        support::vmwrite(host::FS_BASE, self.context.fs_base)?;
        support::vmwrite(host::GS_BASE, self.context.gs_base)?;
        log::info!("[+] Host MSRs initialized!");
        
        log::info!("[+] Host initialized!");

        Ok(())
    }
}

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct VmxTrueControlSettings {
    pub control: u64,
    pub allowed_0_settings: u32,
    pub allowed_1_settings: u32,
}

pub fn vmx_adjust_entry_controls(msr: u32, value: u32) -> u16 {
    let mut cap = VmxTrueControlSettings::default();
    
    cap.control = unsafe { x86::msr::rdmsr(msr) };
    let mut actual = value;

    actual |= cap.allowed_0_settings;
    actual &= cap.allowed_1_settings;

    actual as u16
}