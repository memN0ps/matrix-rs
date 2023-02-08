use core::arch::asm;

use alloc::boxed::Box;
use bitfield::BitMut;
use kernel_alloc::PhysicalAllocator;
use x86::{vmx::{self, vmcs::{control::{PrimaryControls, SecondaryControls, EntryControls, ExitControls}, guest, host}}, msr, controlregs, segmentation::{self, Descriptor}, task, dtables, debugregs, bits64};
use x86_64::instructions::tables::{sgdt, sidt};
use crate::{vmcs_region::VmcsRegion, vmxon_region::VmxonRegion, addresses::{physical_address}, error::HypervisorError, support, vmexit_reason::vmexit_stub, segmentation::{SegmentDescriptor, SegmentAttribute}};

pub const KERNEL_STACK_SIZE: usize = 0x6000;
pub const STACK_CONTENTS_SIZE: usize = KERNEL_STACK_SIZE - core::mem::size_of::<*mut u64>();

#[derive(Clone, Copy)]
#[repr(C, align(4096))]
pub struct HostStackLayout {
    pub stack_contents: [u8; STACK_CONTENTS_SIZE],
    //pub guest_vmcs_pa: u64,
    //pub host_vmcs_pa: u64,
    pub self_data: *mut u64, // A pointer VcpuData
}

pub struct VcpuData {
    /// The virtual and physical address of the Vmcs naturally aligned 4-KByte region of memory
    pub vmcs_region: Box<VmcsRegion, PhysicalAllocator>,
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

        log::info!("[+] Box::new(instance)");
        let mut instance = Box::new(instance);

        instance.host_stack_layout.self_data = &mut *instance as *mut _ as _;

                
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
        unsafe { support::vmwrite(x86::vmx::vmcs::control::CR0_READ_SHADOW, controlregs::cr0().bits() as u64)? };
        unsafe { support::vmwrite(x86::vmx::vmcs::control::CR4_READ_SHADOW, controlregs::cr4().bits() as u64)? };
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
        let gdt = sgdt();
        let idt = sidt();

        let gdtr_base = gdt.base.as_u64();
        let gdtr_limit = gdt.limit as u64;

        let idtr_base = idt.base.as_u64();
        let idtr_limit = idt.limit as u64;

        // Guest Segment Access Writes
        support::vmwrite(guest::CS_ACCESS_RIGHTS, segment_access_right(segmentation::cs().bits(), gdt.base.as_u64()) as _)?;
        support::vmwrite(guest::SS_ACCESS_RIGHTS, segment_access_right(segmentation::ss().bits(), gdt.base.as_u64()) as _)?;
        support::vmwrite(guest::DS_ACCESS_RIGHTS, segment_access_right(segmentation::ds().bits(), gdt.base.as_u64()) as _)?;
        support::vmwrite(guest::ES_ACCESS_RIGHTS, segment_access_right(segmentation::es().bits(), gdt.base.as_u64()) as _)?;
        support::vmwrite(guest::FS_ACCESS_RIGHTS, segment_access_right(segmentation::fs().bits(), gdt.base.as_u64()) as _)?;
        support::vmwrite(guest::GS_ACCESS_RIGHTS, segment_access_right(segmentation::gs().bits(), gdt.base.as_u64()) as _)?;
        unsafe { support::vmwrite(guest::LDTR_ACCESS_RIGHTS, segment_access_right(dtables::ldtr().bits(), gdt.base.as_u64()) as _)? };
        unsafe { support::vmwrite(guest::TR_ACCESS_RIGHTS, segment_access_right(task::tr().bits(), gdt.base.as_u64()) as _)? };
        log::info!("[+] Guest Segment Access Writes initialized!");
        
        // Guest Segment GDTR and LDTR
        support::vmwrite(guest::GDTR_LIMIT, gdtr_limit as _)?;
        support::vmwrite(guest::IDTR_LIMIT, idtr_limit as _)?;
        support::vmwrite(guest::GDTR_BASE, gdtr_base)?;
        support::vmwrite(guest::IDTR_BASE, idtr_base)?;
        log::info!("[+] Guest GDTR and LDTR Limit and Base initialized!");

        // Guest Segment, CS, SS, DS, ES
        support::vmwrite(guest::CS_BASE, get_segment_base(gdt.base.as_u64() as _, segmentation::cs().bits()))?;
        support::vmwrite(guest::SS_BASE, get_segment_base(gdt.base.as_u64() as _, segmentation::ss().bits()))?;
        support::vmwrite(guest::DS_BASE, get_segment_base(gdt.base.as_u64() as _, segmentation::ds().bits()))?;
        support::vmwrite(guest::ES_BASE, get_segment_base(gdt.base.as_u64() as _, segmentation::es().bits()))?;
        unsafe { support::vmwrite(guest::LDTR_BASE, get_segment_base(gdt.base.as_u64() as _, dtables::ldtr().bits()))? };
        unsafe { support::vmwrite(guest::TR_BASE, get_segment_base(gdt.base.as_u64() as _, task::tr().bits()))? };
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
        let vmexit_stub = vmexit_stub as u64;
        support::vmwrite(host::RSP, self.host_stack_layout.self_data as _)?;
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

        // Host Segment TR, GDTR and LDTR
        unsafe { support::vmwrite(host::TR_BASE, get_segment_base(gdt.base.as_u64() as _, task::tr().bits()))? };
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

fn segment_access_right(segment_selector: u16, gdt_base: u64) -> u16 {
    const RPL_MASK: u16 = 3;
    let descriptor = gdt_base + (segment_selector & !RPL_MASK) as u64;

    let descriptor = descriptor as *mut u64 as *mut SegmentDescriptor;
    let descriptor = unsafe { descriptor.read_volatile() };

    let mut attribute = SegmentAttribute(0);
    attribute.set_type(descriptor.get_type() as u16);
    attribute.set_system(descriptor.get_system() as u16);
    attribute.set_dpl(descriptor.get_dpl() as u16);
    attribute.set_present(descriptor.get_present() as u16);
    attribute.set_avl(descriptor.get_avl() as u16);
    attribute.set_long_mode(descriptor.get_long_mode() as u16);
    attribute.set_default_bit(descriptor.get_default_bit() as u16);
    attribute.set_granularity(descriptor.get_granularity() as u16);

    attribute.0
}

fn segment_limit(selector: u16) -> u32 {
    let limit: u32;
    unsafe {
        asm!("lsl {0:e}, {1:x}", out(reg) limit, in(reg) selector, options(nostack, nomem));
    }
    limit
}

pub fn get_segment_base(gdt_base: *const usize, segment_selector: u16) -> u64 {
    const RPL_MASK: u16 = 3;

    let mut segment_base = 0u64;

    if segment_selector == 0 {
        return segment_base;
    }

    let descriptor = gdt_base as u64 + ((segment_selector & !RPL_MASK) * 8) as u64;

    let descriptor = descriptor as *mut u64 as *mut SegmentDescriptor;
    let descriptor = unsafe { descriptor.read_volatile() };

    segment_base |= descriptor.get_base_low() as u64;
    segment_base |= descriptor.get_base_middle() << 16;
    segment_base |= descriptor.get_base_high() << 24;

    if descriptor.get_system() == 0 {
        let expanded_descriptor = unsafe {
            (gdt_base.wrapping_add((segment_selector & !RPL_MASK) as usize) as *const Descriptor)
                .read_volatile()
        };
        segment_base |= (expanded_descriptor.lower as u64) << 32;
    }

    segment_base
}