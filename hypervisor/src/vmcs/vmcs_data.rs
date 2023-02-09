use core::arch::asm;
use x86::{vmx::{self, vmcs::{control::{PrimaryControls, SecondaryControls, EntryControls, ExitControls}, guest, host}}, msr, controlregs, segmentation::{self}, task, dtables, debugregs, bits64};
use x86_64::instructions::tables::{sgdt, sidt};
use crate::{error::HypervisorError, support, vmexit_reason::vmexit_stub, segmentation::Segment, tables::GdtStruct};

pub struct VmcsData;

impl VmcsData {
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
    pub fn init_host_register_state(&mut self, host_rsp: u64) -> Result<(), HypervisorError> {
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

pub fn vmx_adjust_entry_controls(msr: u32, controls: u32) -> u64 {
    let controls = u32::try_from(controls).expect("Controls should be a 32 bit field"); // 503 953 2390
    let pair = rdmsr(msr);
    let fixed0 = pair.edx;
    let fixed1 = pair.eax;
    if controls & fixed0 != controls {
        log::warn!(
            "Requested unsupported controls for msr {:?}, fixed0 {:x} fixed1 {:x} controls {:x}",
            msr, fixed0, fixed1, controls
        );
    }
    u64::from(fixed1 | (controls & fixed0))
}

/// Represents the value of an Model specific register.
/// rdmsr returns the value with the high bits of the MSR in edx and the low bits in eax.
/// wrmsr recieves the value similarly.
pub struct MsrValuePair {
    pub edx: u32,
    pub eax: u32,
}

/// Read a model specific register as a pair of two values.
pub fn rdmsr(msr: u32) -> MsrValuePair {
    let edx: u32;
    let eax: u32;
    unsafe {
        asm!(
        "rdmsr",
         lateout("eax")(eax),
          lateout("edx")(edx),
          in("ecx")(msr as u32)
        );
    }
    MsrValuePair { edx, eax }
}

fn segment_limit(selector: u16) -> u32 {
    let limit: u32;
    unsafe {
        asm!("lsl {0:e}, {1:x}", out(reg) limit, in(reg) selector, options(nostack, nomem));
    }
    limit
}