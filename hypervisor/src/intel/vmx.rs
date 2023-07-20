use core::arch::global_asm;

use crate::{
    error::HypervisorError,
    intel::{
        controls::{adjust_vmx_controls, VmxControl},
        segmentation::{GdtStruct, Segment},
    },
    nt::MmGetPhysicalAddress,
    utils::x86_instructions::{
        r10, r11, r12, r13, r14, r15, r8, r9, rax, rbp, rbx, rcx, rdi, rdx, rsi, segment_limit,
    },
};
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
};
use bitfield::BitMut;
use kernel_alloc::PhysicalAllocator;
use x86::{
    bits64, controlregs,
    cpuid::CpuId,
    current::rflags::RFlags,
    debugregs,
    dtables::{self},
    msr::{self, rdmsr},
    segmentation, task,
    vmx::{
        self,
        vmcs::{
            self,
            control::{EntryControls, ExitControls, PrimaryControls, SecondaryControls},
            guest, host,
        },
    },
};
use x86_64::instructions::tables::{sgdt, sidt};

use super::{registers::GuestRegisters, vmcs::Vmcs, vmxon::Vmxon};

extern "C" {
    /// Runs the guest until VM-exit occurs.
    fn launch_vm(registers: &mut GuestRegisters, launched: u64) -> u64;
}
global_asm!(include_str!("launch_vm.nasm"));

pub struct Vmx {
    /// The virtual and physical address of the Vmxon naturally aligned 4-KByte region of memory
    pub vmxon_region: Box<Vmxon, PhysicalAllocator>,
    pub vmxon_region_physical_address: u64,

    /// The virtual and physical address of the Vmcs naturally aligned 4-KByte region of memory
    pub vmcs_region: Box<Vmcs, PhysicalAllocator>,
    pub vmcs_region_physical_address: u64,

    /// The guest registers
    pub registers: GuestRegisters,

    /// The launched state.
    pub launched: bool,
}

impl Vmx {
    pub fn new() -> Result<Self, HypervisorError> {
        let vmxon_region = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };
        let vmcs_region = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };

        let registers = GuestRegisters::default();

        Ok(Self {
            vmxon_region: vmxon_region,
            vmxon_region_physical_address: 0,
            vmcs_region: vmcs_region,
            vmcs_region_physical_address: 0,
            registers,
            launched: false,
        })
    }

    pub fn run(&mut self) -> Result<(), HypervisorError> {
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.7 ENABLING AND ENTERING VMX OPERATION */
        /* - 25.11.5 VMXON Region */
        log::info!("[+] Enabling Virtual Machine Extensions (VMX)");
        self.enable_vmx_operation()?;

        log::info!("[+] init_vmxon_region");
        self.init_vmxon_region()?;

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.2 FORMAT OF THE VMCS REGION */
        log::info!("[+] init_vmcs_region");
        self.init_vmcs_region()?;

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.4 GUEST-STATE AREA */
        log::info!("[+] init_guest_register_state");
        self.init_guest_register_state();

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.5 HOST-STATE AREA */
        // Most of it is done in vmx_run_vm.nasm file.
        log::info!("[+] init_host_register_state");
        self.init_host_register_state();

        /* VMX controls */
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: */
        /* - 25.6 VM-EXECUTION CONTROL FIELDS */
        /* - 25.7 VM-EXIT CONTROL FIELDS      */
        /* - 25.8 VM-ENTRY CONTROL FIELDS     */
        /* - 25.6 VM-EXECUTION CONTROL FIELDS */
        log::info!("[+] init_vmcs_control_values");
        self.init_vmcs_control_values();

        //log::info!("[*] Dumping VMCS");

        log::info!("[+] Running the guest until VM-exit occurs.");
        // Run the VM until the VM-exit occurs.
        let flags = unsafe { launch_vm(&mut self.registers, u64::from(self.launched)) };
        vm_succeed(RFlags::from_raw(flags)).expect("[-] run_vm_vmx failed");
        self.launched = true;
        log::info!("[+] VM launched successfully!");

        // VM-exit occurred. Copy the guest register values from VMCS so that
        // `self.registers` is complete and up to date.
        self.registers.rip = vmread(vmcs::guest::RIP);
        self.registers.rsp = vmread(vmcs::guest::RSP);
        self.registers.rflags = vmread(vmcs::guest::RFLAGS);

        /* TODO */
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.9 VM-EXIT INFORMATION FIELDS */
        /* APPENDIX C VMX BASIC EXIT REASONS */
        /* Table C-1. Basic Exit Reasons */
        let exit_reason = vmread(vmcs::ro::EXIT_REASON);
        log::info!("VM-exit occurred: reason = {}", exit_reason);

        Ok(())
    }

    /// Allocate a naturally aligned 4-KByte VMXON region of memory to enable VMX operation (Intel Manual: 25.11.5 VMXON Region)
    pub fn init_vmxon_region(&mut self) -> Result<(), HypervisorError> {
        self.vmxon_region_physical_address =
            virtual_to_physical_address(self.vmxon_region.as_ref() as *const _ as _);

        if self.vmxon_region_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::info!("[+] VMXON Region Virtual Address: {:p}", self.vmxon_region);
        log::info!(
            "[+] VMXON Region Physical Addresss: 0x{:x}",
            self.vmxon_region_physical_address
        );

        self.vmxon_region.revision_id = self.get_vmcs_revision_id();
        self.vmxon_region.as_mut().revision_id.set_bit(31, false);

        vmxon(self.vmxon_region_physical_address);
        log::info!("[+] VMXON successful!");

        Ok(())
    }

    /// Allocate a naturally aligned 4-KByte VMCS region of memory (Intel Manual: 25.11.5 VMCS Region)
    /// Ensures that VMCS data maintained on the processor is copied to the VMCS region located at 4KB-aligned physical address addr and initializes some parts of it. (Intel Manual: 25.11.3 Initializing a VMCS)
    /// Load the VMCS pointer
    pub fn init_vmcs_region(&mut self) -> Result<(), HypervisorError> {
        self.vmcs_region_physical_address =
            virtual_to_physical_address(self.vmcs_region.as_ref() as *const _ as _);

        if self.vmcs_region_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::info!("[+] VMCS Region Virtual Address: {:p}", self.vmcs_region);
        log::info!(
            "[+] VMCS Region Physical Addresss: 0x{:x}",
            self.vmcs_region_physical_address
        );

        self.vmcs_region.revision_id = self.get_vmcs_revision_id();
        self.vmcs_region.as_mut().revision_id.set_bit(31, false);

        log::info!("[+] VMCS successful!");

        // Clear the VMCS region.
        vmclear(self.vmcs_region_physical_address);
        log::info!("[+] VMCLEAR successful!");

        // Load current VMCS pointer.
        vmptrld(self.vmcs_region_physical_address);
        log::info!("[+] VMPTRLD successful!");

        Ok(())
    }

    /// Initialize the VMCS control values for the currently loaded vmcs.
    #[rustfmt::skip]
    pub fn init_vmcs_control_values(&mut self) {
        const PRIMARY_CTL: u64 = (PrimaryControls::HLT_EXITING.bits() | /*PrimaryControls::USE_MSR_BITMAPS.bits() |*/ PrimaryControls::SECONDARY_CONTROLS.bits()) as u64;
        const SECONDARY_CTL: u64 = (SecondaryControls::ENABLE_RDTSCP.bits() | SecondaryControls::ENABLE_XSAVES_XRSTORS.bits() | SecondaryControls::ENABLE_INVPCID.bits()/* SecondaryControls::ENABLE_XSAVES_XRSTORS.bits() | SecondaryControls::ENABLE_EPT.bits() */) as u64;
        const ENTRY_CTL: u64 = (EntryControls::IA32E_MODE_GUEST.bits()) as u64;
        const EXIT_CTL: u64 = ExitControls::HOST_ADDRESS_SPACE_SIZE.bits() as u64; //| ExitControls::ACK_INTERRUPT_ON_EXIT.bits()) as u64;
        const PINBASED_CTL: u64 = 0;

        // PrimaryControls (x86::msr::IA32_VMX_PROCBASED_CTLS)
        vmwrite(vmx::vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased, PRIMARY_CTL));

        // SecondaryControls (x86::msr::IA32_VMX_PROCBASED_CTLS2)
        vmwrite(vmx::vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased2, SECONDARY_CTL));

        // EntryControls (x86::msr::IA32_VMX_ENTRY_CTLS)
        vmwrite(vmx::vmcs::control::VMENTRY_CONTROLS,adjust_vmx_controls(VmxControl::VmEntry, ENTRY_CTL));

        // ExitControls (x86::msr::IA32_VMX_EXIT_CTLS)
        vmwrite(vmx::vmcs::control::VMEXIT_CONTROLS, adjust_vmx_controls(VmxControl::VmExit, EXIT_CTL));

        // PinbasedControls (x86::msr::IA32_VMX_PINBASED_CTLS)
        vmwrite(vmx::vmcs::control::PINBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::PinBased, PINBASED_CTL));

        log::info!("[+] VMCS Primary, Secondary, Entry, Exit and Pinbased, Controls initialized!");

        // Control Register Shadows
        unsafe {
            vmwrite(x86::vmx::vmcs::control::CR0_READ_SHADOW, controlregs::cr0().bits() as u64);
            vmwrite(x86::vmx::vmcs::control::CR4_READ_SHADOW, controlregs::cr4().bits() as u64);
            log::info!("[+] VMCS Controls Shadow Registers initialized!");
        };

        /* Time-stamp counter offset */
        vmwrite(vmx::vmcs::control::TSC_OFFSET_FULL, 0u64);
        vmwrite(vmx::vmcs::control::TSC_OFFSET_HIGH, 0u64);

        /*
        vmwrite(vmx::vmcs::control::PAGE_FAULT_ERR_CODE_MASK, 0);
        vmwrite(vmx::vmcs::control::PAGE_FAULT_ERR_CODE_MATCH, 0);
        vmwrite(vmx::vmcs::control::VMEXIT_MSR_STORE_COUNT, 0);
        vmwrite(vmx::vmcs::control::VMEXIT_MSR_LOAD_COUNT, 0);
        vmwrite(vmx::vmcs::control::VMENTRY_MSR_LOAD_COUNT, 0);
        vmwrite(vmx::vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, 0);
        log::info!("VMCS Time-stamp counter offset initialized!");
        */

        // VMCS Controls Bitmap
        //vmwrite(vmx::vmcs::control::MSR_BITMAPS_ADDR_FULL, msr_bitmap_physical_address);
        //vmwrite(vmx::vmcs::control::MSR_BITMAPS_ADDR_HIGH, msr_bitmap_physical_address);
        //log::info!("VMCS Controls Bitmap initialized!");

        vmwrite(vmx::vmcs::control::PAGE_FAULT_ERR_CODE_MASK, 0u64);
        vmwrite(vmx::vmcs::control::PAGE_FAULT_ERR_CODE_MATCH, 0u64);

        vmwrite(vmx::vmcs::control::VMEXIT_MSR_STORE_COUNT, 0u64);
        vmwrite(vmx::vmcs::control::VMEXIT_MSR_LOAD_COUNT, 0u64);

        vmwrite(vmx::vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, 0u64);
        vmwrite(vmx::vmcs::control::VMENTRY_MSR_LOAD_COUNT, 0u64);

        log::info!("[+] VMCS Controls initialized!");
    }

    /// Initialize the guest state for the currently loaded vmcs.
    #[rustfmt::skip]
    pub fn init_guest_register_state(&mut self) {
        log::info!("[+] Guest Register State");

        // Guest Control Registers
        unsafe { vmwrite(guest::CR0, controlregs::cr0().bits() as u64) };
        unsafe { vmwrite(guest::CR3, controlregs::cr3()) };
        unsafe { vmwrite(guest::CR4, controlregs::cr4().bits() as u64) };
        log::info!("[+] Guest Control Registers initialized!");

        // Guest Debug Register
        unsafe { vmwrite(guest::DR7, debugregs::dr7().0 as u64) };
        log::info!("[+] Guest Debug Registers initialized!");

        // Guest RSP and RIP
        vmwrite(guest::RSP, bits64::registers::rsp());
        vmwrite(guest::RIP, bits64::registers::rip());
        log::info!("[+] Guest RSP and RIP initialized!");

        // Guest RFLAGS
        vmwrite(guest::RFLAGS, bits64::rflags::read().bits());
        log::info!("[+] Guest RFLAGS Registers initialized!");

        // Guest Segment Selector
        vmwrite(guest::CS_SELECTOR, segmentation::cs().bits() as u64);
        vmwrite(guest::SS_SELECTOR, segmentation::ss().bits() as u64);
        vmwrite(guest::DS_SELECTOR, segmentation::ds().bits() as u64);
        vmwrite(guest::ES_SELECTOR, segmentation::es().bits() as u64);
        vmwrite(guest::FS_SELECTOR, segmentation::fs().bits() as u64);
        vmwrite(guest::GS_SELECTOR, segmentation::gs().bits() as u64);
        unsafe { vmwrite(guest::LDTR_SELECTOR, dtables::ldtr().bits() as u64) };
        unsafe { vmwrite(guest::TR_SELECTOR, task::tr().bits() as u64) };
        log::info!("[+] Guest Segmentation Selector initialized!");

        // Guest Segment Limit
        vmwrite(guest::CS_LIMIT, segment_limit(segmentation::cs().bits()) as u32);
        vmwrite(guest::SS_LIMIT, segment_limit(segmentation::ss().bits()) as u32);
        vmwrite(guest::DS_LIMIT, segment_limit(segmentation::ds().bits()) as u32);
        vmwrite(guest::ES_LIMIT, segment_limit(segmentation::es().bits()) as u32);
        vmwrite(guest::FS_LIMIT, segment_limit(segmentation::fs().bits()) as u32);
        vmwrite(guest::GS_LIMIT, segment_limit(segmentation::gs().bits()) as u32);
        unsafe { vmwrite(guest::LDTR_LIMIT, segment_limit(dtables::ldtr().bits()) as u32) };
        unsafe { vmwrite(guest::TR_LIMIT, segment_limit(task::tr().bits()) as u32) };
        log::info!("[+] Guest Segment Limit initialized!");

        // GDTR and IDTR Limit/Base
        let gdt = GdtStruct::sgdt();
        let idt = sidt();

        let gdtr_base = gdt.base.as_u64();
        let gdtr_limit = gdt.limit as u64;

        let idtr_base = idt.base.as_u64();
        let idtr_limit = idt.limit as u64;

        // Guest Segment Access Writes RIGHTS
        vmwrite(guest::CS_ACCESS_RIGHTS, Segment::from_selector(segmentation::cs(), &gdt).access_rights.bits());
        vmwrite(guest::SS_ACCESS_RIGHTS, Segment::from_selector(segmentation::ss(), &gdt).access_rights.bits());
        vmwrite(guest::DS_ACCESS_RIGHTS, Segment::from_selector(segmentation::ds(), &gdt).access_rights.bits());
        vmwrite(guest::ES_ACCESS_RIGHTS, Segment::from_selector(segmentation::es(), &gdt).access_rights.bits());
        vmwrite(guest::FS_ACCESS_RIGHTS, Segment::from_selector(segmentation::fs(), &gdt).access_rights.bits());
        vmwrite(guest::GS_ACCESS_RIGHTS, Segment::from_selector(segmentation::gs(), &gdt).access_rights.bits());
        unsafe { vmwrite(guest::LDTR_ACCESS_RIGHTS, Segment::from_selector(dtables::ldtr(), &gdt).access_rights.bits()) };
        unsafe { vmwrite(guest::TR_ACCESS_RIGHTS, Segment::from_selector(task::tr(), &gdt).access_rights.bits()) };

        log::info!("[+] Guest Segment Access Writes initialized!");

        // Guest Segment GDTR and LDTR
        vmwrite(guest::GDTR_LIMIT, gdtr_limit);
        vmwrite(guest::IDTR_LIMIT, idtr_limit);
        vmwrite(guest::GDTR_BASE, gdtr_base);
        vmwrite(guest::IDTR_BASE, idtr_base);
        log::info!("[+] Guest GDTR and LDTR Limit and Base initialized!");

        // Guest Segment, CS, SS, DS, ES ??????????????????????????????????????????????? BASE
        vmwrite(guest::CS_BASE, Segment::from_selector(segmentation::cs(), &gdt).base);
        vmwrite(guest::SS_BASE, Segment::from_selector(segmentation::ss(), &gdt).base);
        vmwrite(guest::DS_BASE, Segment::from_selector(segmentation::ds(), &gdt).base);
        vmwrite(guest::ES_BASE, Segment::from_selector(segmentation::es(), &gdt).base);
        unsafe { vmwrite(guest::LDTR_BASE, Segment::from_selector(dtables::ldtr(), &gdt).base) };
        unsafe { vmwrite(guest::TR_BASE, Segment::from_selector(task::tr(), &gdt).base) };

        log::info!("[+] Guest Segment, CS, SS, DS, ES, LDTR and TR initialized!");

        // Guest MSR's
        unsafe {
            vmwrite(guest::IA32_DEBUGCTL_FULL, msr::rdmsr(msr::IA32_DEBUGCTL));
            vmwrite(guest::IA32_DEBUGCTL_HIGH, msr::rdmsr(msr::IA32_DEBUGCTL));
            vmwrite(guest::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS));
            vmwrite(guest::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP));
            vmwrite(guest::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP));
            vmwrite(guest::LINK_PTR_FULL, u64::MAX);
            vmwrite(guest::LINK_PTR_HIGH, u64::MAX);

            vmwrite(guest::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE));
            vmwrite(guest::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE));
            log::info!("[+] Guest MSRs initialized!");
        }

        log::info!("[+] Guest initialized!");

        self.registers.rax = rax();
        self.registers.rbx = rbx();
        self.registers.rcx = rcx();
        self.registers.rdx = rdx();
        self.registers.rdi = rdi();
        self.registers.rsi = rsi();
        self.registers.rbp = rbp();
        self.registers.r8 = r8();
        self.registers.r9 = r9();
        self.registers.r10 = r10();
        self.registers.r11 = r11();
        self.registers.r12 = r12();
        self.registers.r13 = r13();
        self.registers.r14 = r14();
        self.registers.r15 = r15();
    }

    /// Initialize the host state for the currently loaded vmcs.
    #[rustfmt::skip]
    pub fn init_host_register_state(&mut self) {
        log::info!("[+] Host Register State");

        // Host Control Registers
        unsafe { vmwrite(host::CR0, controlregs::cr0().bits() as u64) };
        unsafe { vmwrite(host::CR3, controlregs::cr3()) };
        unsafe { vmwrite(host::CR4, controlregs::cr4().bits() as u64) };
        log::info!("[+] Host Control Registers initialized!");

        // Host Segment Selector
        const SELECTOR_MASK: u16 = 0xF8;
        vmwrite(host::CS_SELECTOR, (segmentation::cs().bits() & SELECTOR_MASK) as u64);
        vmwrite(host::SS_SELECTOR, (segmentation::ss().bits() & SELECTOR_MASK) as u64);
        vmwrite(host::DS_SELECTOR, (segmentation::ds().bits() & SELECTOR_MASK) as u64);
        vmwrite(host::ES_SELECTOR, (segmentation::es().bits() & SELECTOR_MASK) as u64);
        vmwrite(host::FS_SELECTOR, (segmentation::fs().bits() & SELECTOR_MASK) as u64);
        vmwrite(host::GS_SELECTOR, (segmentation::gs().bits() & SELECTOR_MASK) as u64);
        unsafe { vmwrite(host::TR_SELECTOR, (task::tr().bits() & SELECTOR_MASK) as u64) };
        log::info!("[+] Host Segmentation Registers initialized!");

        // GDTR and IDTR Limit/Base
        let gdt = sgdt();
        let idt = sidt();

        let gdtr_base = gdt.base.as_u64();
        //let gdtr_limit = gdt.limit as u64;

        let idtr_base = idt.base.as_u64();
        //let idtr_limit = idt.limit as u64;

        // Host Segment TR, GDTR and LDTR  BASE?
        unsafe { vmwrite(host::TR_BASE, Segment::from_selector(task::tr(), &gdt).base) };
        vmwrite(host::GDTR_BASE, gdtr_base);
        vmwrite(host::IDTR_BASE, idtr_base);
        log::info!("[+] Host TR, GDTR and LDTR initialized!");

        // Host MSR's
        unsafe {
            vmwrite(host::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS));
            vmwrite(host::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP));
            vmwrite(host::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP));

            vmwrite(host::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE));
            vmwrite(host::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE));

            log::info!("[+] Host MSRs initialized!");
        }

        log::info!("[+] Host initialized!");
    }

    /// Check to see if CPU is Intel (“GenuineIntel”).
    pub fn has_intel_cpu() -> Result<(), HypervisorError> {
        let cpuid = CpuId::new();
        if let Some(vi) = cpuid.get_vendor_info() {
            if vi.as_str() == "GenuineIntel" {
                return Ok(());
            }
        }
        Err(HypervisorError::CPUUnsupported)
    }

    /// Check processor supports for Virtual Machine Extension (VMX) technology - CPUID.1:ECX.VMX\[bit 5] = 1 (Intel Manual: 24.6 Discovering Support for VMX)
    pub fn has_vmx_support() -> Result<(), HypervisorError> {
        let cpuid = CpuId::new();
        if let Some(fi) = cpuid.get_feature_info() {
            if fi.has_vmx() {
                return Ok(());
            }
        }
        Err(HypervisorError::VMXUnsupported)
    }

    /// Enables Virtual Machine Extensions - CR4.VMXE\[bit 13] = 1 (Intel Manual: 24.7 Enabling and Entering VMX Operation)
    pub fn enable_vmx_operation(&self) -> Result<(), HypervisorError> {
        let mut cr4 = unsafe { controlregs::cr4() };
        cr4.set(controlregs::Cr4::CR4_ENABLE_VMX, true);
        unsafe { controlregs::cr4_write(cr4) };

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.7 ENABLING AND ENTERING VMX OPERATION */
        self.set_lock_bit()?;
        log::info!("[+] Lock bit set via IA32_FEATURE_CONTROL");

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.8 RESTRICTIONS ON VMX OPERATION */
        log::info!("[+] Adjusting Control Registers");
        self.adjust_control_registers();

        Ok(())
    }

    /// Check if we need to set bits in IA32_FEATURE_CONTROL (Intel Manual: 24.7 Enabling and Entering VMX Operation)
    fn set_lock_bit(&self) -> Result<(), HypervisorError> {
        const VMX_LOCK_BIT: u64 = 1 << 0;
        const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

        let ia32_feature_control = unsafe { rdmsr(msr::IA32_FEATURE_CONTROL) };

        if (ia32_feature_control & VMX_LOCK_BIT) == 0 {
            unsafe {
                msr::wrmsr(
                    msr::IA32_FEATURE_CONTROL,
                    VMXON_OUTSIDE_SMX | VMX_LOCK_BIT | ia32_feature_control,
                )
            };
        } else if (ia32_feature_control & VMXON_OUTSIDE_SMX) == 0 {
            return Err(HypervisorError::VMXBIOSLock);
        }

        Ok(())
    }

    /// Adjust set and clear the mandatory bits in CR0 and CR4
    fn adjust_control_registers(&self) {
        self.set_cr0_bits();
        log::info!("[+] Mandatory bits in CR0 set/cleared");

        self.set_cr4_bits();
        log::info!("[+] Mandatory bits in CR4 set/cleared");
    }

    /// Set the mandatory bits in CR0 and clear bits that are mandatory zero (Intel Manual: 24.8 Restrictions on VMX Operation)
    fn set_cr0_bits(&self) {
        let ia32_vmx_cr0_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED0) };
        let ia32_vmx_cr0_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED1) };

        let mut cr0 = unsafe { controlregs::cr0() };

        cr0 |= controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed0 as usize);
        cr0 &= controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed1 as usize);

        unsafe { controlregs::cr0_write(cr0) };
    }

    /// Set the mandatory bits in CR4 and clear bits that are mandatory zero (Intel Manual: 24.8 Restrictions on VMX Operation)
    fn set_cr4_bits(&self) {
        let ia32_vmx_cr4_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED0) };
        let ia32_vmx_cr4_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED1) };

        let mut cr4 = unsafe { controlregs::cr4() };

        cr4 |= controlregs::Cr4::from_bits_truncate(ia32_vmx_cr4_fixed0 as usize);
        cr4 &= controlregs::Cr4::from_bits_truncate(ia32_vmx_cr4_fixed1 as usize);

        unsafe { controlregs::cr4_write(cr4) };
    }

    /// Get the Virtual Machine Control Structure revision identifier (VMCS revision ID) (Intel Manual: 25.11.5 VMXON Region)
    fn get_vmcs_revision_id(&self) -> u32 {
        unsafe { (msr::rdmsr(msr::IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF }
    }
}

/// Enable VMX operation.
fn vmxon(vmxon_region: u64) {
    unsafe { x86::bits64::vmx::vmxon(vmxon_region).unwrap() };
}

/// Clear VMCS.
fn vmclear(vmcs_region: u64) {
    unsafe { x86::bits64::vmx::vmclear(vmcs_region).unwrap() };
}

/// Load current VMCS pointer.
fn vmptrld(vmcs_region: u64) {
    unsafe { x86::bits64::vmx::vmptrld(vmcs_region).unwrap() }
}

#[allow(dead_code)]
/// Return current VMCS pointer.
fn vmptrst() -> *const Vmcs {
    unsafe { x86::bits64::vmx::vmptrst().unwrap() as *const Vmcs }
}

/// Read a specified field from a VMCS.
fn vmread(field: u32) -> u64 {
    unsafe { x86::bits64::vmx::vmread(field) }.unwrap_or(0)
}

/// Write to a specified field in a VMCS.
fn vmwrite<T: Into<u64>>(field: u32, val: T)
where
    u64: From<T>,
{
    unsafe { x86::bits64::vmx::vmwrite(field, u64::from(val)) }.unwrap();
}

/// Checks that the latest VMX instruction succeeded.
fn vm_succeed(flags: RFlags) -> Result<(), String> {
    if flags.contains(RFlags::FLAGS_ZF) {
        // See: 31.4 VM INSTRUCTION ERROR NUMBERS
        Err(format!(
            "VmFailValid with {}",
            vmread(vmcs::ro::VM_INSTRUCTION_ERROR)
        ))
    } else if flags.contains(RFlags::FLAGS_CF) {
        Err("VmFailInvalid".to_string())
    } else {
        Ok(())
    }
}

pub fn virtual_to_physical_address(va: u64) -> u64 {
    unsafe { *MmGetPhysicalAddress(va as _).QuadPart() as u64 }
}
