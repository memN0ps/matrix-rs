use super::{registers::GuestRegisters, vmcs::Vmcs, vmxon::Vmxon};
use crate::{
    error::HypervisorError,
    intel::support::{virtual_to_physical_address, vmclear, vmptrld, vmwrite, vmxon},
    utils::context::Context,
};
use alloc::boxed::Box;
use bitfield::BitMut;
use kernel_alloc::PhysicalAllocator;
use x86::{
    controlregs,
    cpuid::CpuId,
    dtables::{self},
    msr::{self, rdmsr},
    task,
    vmx::{
        self,
        vmcs::{
            control::{EntryControls, ExitControls, PrimaryControls, SecondaryControls},
            guest, host,
        },
    },
};

pub struct Vmx {
    /// The virtual and physical address of the Vmxon naturally aligned 4-KByte region of memory
    pub vmxon_region: Box<Vmxon, PhysicalAllocator>,
    pub vmxon_region_physical_address: u64,

    /// The virtual and physical address of the Vmcs naturally aligned 4-KByte region of memory
    pub vmcs_region: Box<Vmcs, PhysicalAllocator>,
    pub vmcs_region_physical_address: u64,

    /// The guest registers
    pub registers: GuestRegisters,

    /// The context of the hypervisor
    pub context: Context,
}

impl Vmx {
    pub fn new(context: Context) -> Result<Self, HypervisorError> {
        let vmxon_region = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };
        let vmcs_region = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };

        Ok(Self {
            vmxon_region: vmxon_region,
            vmxon_region_physical_address: 0,
            vmcs_region: vmcs_region,
            vmcs_region_physical_address: 0,
            registers: GuestRegisters::default(),
            context,
        })
    }

    pub fn init(&mut self) -> Result<(), HypervisorError> {
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.7 ENABLING AND ENTERING VMX OPERATION */
        log::info!("[+] Enabling Virtual Machine Extensions (VMX)");
        self.enable_vmx_operation()?;

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.2 FORMAT OF THE VMCS REGION */
        log::info!("[+] init_vmcs_region");
        self.init_vmcs_region()?;

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.4 GUEST-STATE AREA */
        log::info!("[+] init_guest_register_state");
        self.init_guest_register_state();

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.5 HOST-STATE AREA */
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

        Ok(())
    }

    /// Execute vmxon instruction to enable vmx operation.
    /// # VMXON Region
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.2 FORMAT OF THE VMCS REGION
    fn init_vmxon_region(&mut self) -> Result<(), HypervisorError> {
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

    /// Clear the VMCS region and load the VMCS pointer
    /// # VMCS Region
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.2 FORMAT OF THE VMCS REGION
    fn init_vmcs_region(&mut self) -> Result<(), HypervisorError> {
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

    /// Initialize the guest state for the currently loaded VMCS.
    /// # Guest state
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual 25.4 GUEST-STATE AREA:
    /// * CR0, CR3, and CR4
    /// * DR7
    /// * RSP, RIP, and RFLAGS
    /// * Segment Selector, Base address, Segment limit, Access rights:
    ///     * CS, SS, DS, ES, FS, GS, LDTR, and TR
    /// * Base, Limit:
    ///     * GDTR and IDTR
    /// * MSRs:
    ///     * IA32_DEBUGCTL
    ///     * IA32_SYSENTER_CS
    ///     * IA32_SYSENTER_ESP
    ///     * IA32_SYSENTER_EIP
    ///     * LINK_PTR_FULL
    #[rustfmt::skip]
    fn init_guest_register_state(&mut self) {
        log::info!("[+] Guest Register State");

        // Guest Control Registers
        unsafe { vmwrite(guest::CR0, controlregs::cr0().bits() as u64) };
        unsafe { vmwrite(guest::CR3, controlregs::cr3()) };
        unsafe { vmwrite(guest::CR4, controlregs::cr4().bits() as u64) };

        // Guest Debug Register
        vmwrite(guest::DR7, self.context.dr7);

        // Guest RSP, RIP and RFLAGS
        vmwrite(guest::RSP, self.context.rsp);
        vmwrite(guest::RIP, self.context.rip);
        vmwrite(guest::RFLAGS, self.context.e_flags);

        // Guest Segment CS, SS, DS, ES, FS, GS, LDTR, and TR Selector
        vmwrite(guest::CS_SELECTOR, self.context.seg_cs);
        vmwrite(guest::SS_SELECTOR, self.context.seg_ss);
        vmwrite(guest::DS_SELECTOR, self.context.seg_ds);
        vmwrite(guest::ES_SELECTOR, self.context.seg_es);
        vmwrite(guest::FS_SELECTOR, self.context.seg_fs);
        vmwrite(guest::GS_SELECTOR, self.context.seg_gs);
        unsafe { vmwrite(guest::LDTR_SELECTOR, dtables::ldtr().bits() as u64) };
        unsafe { vmwrite(guest::TR_SELECTOR, task::tr().bits() as u64) };

        let gdt = get_current_gdt();

        // Guest Segment CS, SS, DS, ES, FS, GS, LDTR, and TR Base Address
        vmwrite(guest::CS_BASE, unpack_gdt_entry(gdt, self.context.seg_cs).base);
        vmwrite(guest::SS_BASE, unpack_gdt_entry(gdt, self.context.seg_ss).base);
        vmwrite(guest::DS_BASE, unpack_gdt_entry(gdt, self.context.seg_ds).base);
        vmwrite(guest::ES_BASE, unpack_gdt_entry(gdt, self.context.seg_es).base);
        unsafe { vmwrite(guest::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE)) };
        unsafe { vmwrite(guest::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE)) };
        unsafe { vmwrite(guest::LDTR_BASE, unpack_gdt_entry(gdt, x86::dtables::ldtr().bits()).base) };
        unsafe { vmwrite(guest::TR_BASE, unpack_gdt_entry(gdt,  x86::task::tr().bits()).base) };

        // Guest Segment CS, SS, DS, ES, FS, GS, LDTR, and TR Limit
        vmwrite(guest::CS_LIMIT, unpack_gdt_entry(gdt, self.context.seg_cs).limit);
        vmwrite(guest::SS_LIMIT, unpack_gdt_entry(gdt, self.context.seg_ss).limit);
        vmwrite(guest::DS_LIMIT, unpack_gdt_entry(gdt, self.context.seg_ds).limit);
        vmwrite(guest::ES_LIMIT, unpack_gdt_entry(gdt, self.context.seg_es).limit);
        vmwrite(guest::FS_LIMIT, unpack_gdt_entry(gdt, self.context.seg_fs).limit);
        vmwrite(guest::GS_LIMIT, unpack_gdt_entry(gdt, self.context.seg_gs).limit);
        unsafe { vmwrite(guest::LDTR_LIMIT, unpack_gdt_entry(gdt, dtables::ldtr().bits()).limit) };
        unsafe { vmwrite(guest::TR_LIMIT, unpack_gdt_entry(gdt, task::tr().bits()).limit) };

        // Guest Segment CS, SS, DS, ES, FS, GS, LDTR, and TR Access Rights
        vmwrite(guest::CS_ACCESS_RIGHTS, unpack_gdt_entry(gdt, self.context.seg_cs).access_rights);
        vmwrite(guest::SS_ACCESS_RIGHTS, unpack_gdt_entry(gdt, self.context.seg_ss).access_rights);
        vmwrite(guest::DS_ACCESS_RIGHTS, unpack_gdt_entry(gdt, self.context.seg_ds).access_rights);
        vmwrite(guest::ES_ACCESS_RIGHTS, unpack_gdt_entry(gdt, self.context.seg_es).access_rights);
        vmwrite(guest::FS_ACCESS_RIGHTS, unpack_gdt_entry(gdt, self.context.seg_fs).access_rights);
        vmwrite(guest::GS_ACCESS_RIGHTS, unpack_gdt_entry(gdt, self.context.seg_gs).access_rights);
        unsafe { vmwrite(guest::LDTR_ACCESS_RIGHTS, unpack_gdt_entry(gdt, dtables::ldtr().bits()).access_rights) };
        unsafe { vmwrite(guest::TR_ACCESS_RIGHTS, unpack_gdt_entry(gdt, task::tr().bits()).access_rights) };

        let mut guest_gdtr: dtables::DescriptorTablePointer<u64> = Default::default();
        unsafe { dtables::sgdt(&mut guest_gdtr); }

        let mut guest_idtr: dtables::DescriptorTablePointer<u64> = Default::default();
        unsafe { dtables::sidt(&mut guest_idtr); }

        // Guest Segment GDTR and LDTR Base Address 
        vmwrite(guest::GDTR_BASE, guest_gdtr.base as u64);
        vmwrite(guest::IDTR_BASE, guest_idtr.base as u64);

        // Guest Segment GDTR and LDTR Limit
        vmwrite(guest::GDTR_LIMIT, guest_gdtr.limit);
        vmwrite(guest::IDTR_LIMIT, guest_idtr.limit);

        // Guest MSRs IA32_DEBUGCTL, IA32_SYSENTER_CS, IA32_SYSENTER_ESP, IA32_SYSENTER_EIP and LINK_PTR_FULL
        unsafe {
            vmwrite(guest::IA32_DEBUGCTL_FULL, msr::rdmsr(msr::IA32_DEBUGCTL));
            vmwrite(guest::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS));
            vmwrite(guest::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP));
            vmwrite(guest::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP));
            vmwrite(guest::LINK_PTR_FULL, u64::MAX);
        }

        // Guest General Purpose Registers
        self.registers.rax = self.context.rax;
        self.registers.rbx = self.context.rbx;
        self.registers.rcx = self.context.rcx;
        self.registers.rdx = self.context.rdx;
        self.registers.rdi = self.context.rdi;
        self.registers.rsi = self.context.rsi;
        self.registers.rbp = self.context.rbp;
        self.registers.r8 = self.context.r8;
        self.registers.r9 = self.context.r9;
        self.registers.r10 = self.context.r10;
        self.registers.r11 = self.context.r11;
        self.registers.r12 = self.context.r12;
        self.registers.r13 = self.context.r13;
        self.registers.r14 = self.context.r14;
        self.registers.r15 = self.context.r15;

        log::info!("[+] Guest initialized!");
    }

    /// Initialize the host state for the currently loaded VMCS.
    /// # Host state
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.5 HOST-STATE AREA
    /// * CR0, CR3, and CR4
    /// * RSP and RIP
    /// * Selector Fields: CS, SS, DS, ES, FS, GS, and TR
    /// * Base Address: FS, GS, TR, GDTR, and IDTR
    /// * MSR's:
    ///     * IA32_SYSENTER_CS
    ///     * IA32_SYSENTER_ESP
    ///     * IA32_SYSENTER_EIP
    #[rustfmt::skip]
    fn init_host_register_state(&mut self) {
        log::info!("[+] Host Register State");

        let mut host_gdtr: dtables::DescriptorTablePointer<u64> = Default::default();
        unsafe { dtables::sgdt(&mut host_gdtr); }

        let mut host_idtr: dtables::DescriptorTablePointer<u64> = Default::default();
        unsafe { dtables::sidt(&mut host_idtr); }

        // Host Control Registers
        unsafe { vmwrite(host::CR0, controlregs::cr0().bits() as u64) };
        unsafe { vmwrite(host::CR3, controlregs::cr3()) };
        unsafe { vmwrite(host::CR4, controlregs::cr4().bits() as u64) };

        // Host Segment CS, SS, DS, ES, FS, GS, and TR Selector
        const SELECTOR_MASK: u16 = 0xF8;
        vmwrite(host::CS_SELECTOR, self.context.seg_cs & SELECTOR_MASK);
        vmwrite(host::SS_SELECTOR, self.context.seg_ss & SELECTOR_MASK);
        vmwrite(host::DS_SELECTOR, self.context.seg_ds & SELECTOR_MASK);
        vmwrite(host::ES_SELECTOR, self.context.seg_es & SELECTOR_MASK);
        vmwrite(host::FS_SELECTOR, self.context.seg_fs & SELECTOR_MASK);
        vmwrite(host::GS_SELECTOR, self.context.seg_gs & SELECTOR_MASK);
        unsafe { vmwrite(host::TR_SELECTOR, task::tr().bits() & SELECTOR_MASK) };

        let gdt = get_current_gdt();
        // Host Segment FS, GS, TR, GDTR, and IDTR Base Address
        unsafe { vmwrite(host::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE)) };
        unsafe { vmwrite(host::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE)) };
        unsafe { vmwrite(host::TR_BASE, unpack_gdt_entry(gdt,  x86::task::tr().bits()).base) };
        vmwrite(host::GDTR_BASE, host_gdtr.base as u64);
        vmwrite(host::IDTR_BASE, host_idtr.base as u64);

        // Host MSRs IA32_SYSENTER_CS, IA32_SYSENTER_ESP, IA32_SYSENTER_EIP
        unsafe {
            vmwrite(host::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS));
            vmwrite(host::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP));
            vmwrite(host::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP));
        }

        log::info!("[+] Host initialized!");
    }

    /// Initialize the VMCS control values for the currently loaded VMCS.
    /// # VMX controls
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual:
    /// * 25.6 VM-EXECUTION CONTROL FIELDS
    /// * 25.7 VM-EXIT CONTROL FIELDS
    /// * 25.8 VM-ENTRY CONTROL FIELDS
    /// * 25.6 VM-EXECUTION CONTROL FIELDS
    #[rustfmt::skip]
    fn init_vmcs_control_values(&mut self) {
        const PRIMARY_CTL: u64 = PrimaryControls::SECONDARY_CONTROLS.bits() as u64;
        const SECONDARY_CTL: u64 = (SecondaryControls::ENABLE_RDTSCP.bits() | SecondaryControls::ENABLE_XSAVES_XRSTORS.bits() | SecondaryControls::ENABLE_INVPCID.bits()) as u64;
        const ENTRY_CTL: u64 = EntryControls::IA32E_MODE_GUEST.bits() as u64;
        const EXIT_CTL: u64 = ExitControls::HOST_ADDRESS_SPACE_SIZE.bits() as u64;
        const PINBASED_CTL: u64 = 0;

        vmwrite(vmx::vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased, PRIMARY_CTL));
        vmwrite(vmx::vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased2, SECONDARY_CTL));
        vmwrite(vmx::vmcs::control::VMENTRY_CONTROLS,adjust_vmx_controls(VmxControl::VmEntry, ENTRY_CTL));
        vmwrite(vmx::vmcs::control::VMEXIT_CONTROLS, adjust_vmx_controls(VmxControl::VmExit, EXIT_CTL));
        vmwrite(vmx::vmcs::control::PINBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::PinBased, PINBASED_CTL));

        log::info!("[+] VMCS Primary, Secondary, Entry, Exit and Pinbased, Controls initialized!");

        // Control Register Shadows
        unsafe {
            vmwrite(x86::vmx::vmcs::control::CR0_READ_SHADOW, controlregs::cr0().bits() as u64);
            vmwrite(x86::vmx::vmcs::control::CR4_READ_SHADOW, controlregs::cr4().bits() as u64);
            log::info!("[+] VMCS Controls Shadow Registers initialized!");
        };
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

    /// Check processor supports for Virtual Machine Extension (VMX) technology - CPUID.1:ECX.VMX\[bit 5] = 1
    pub fn has_vmx_support() -> Result<(), HypervisorError> {
        let cpuid = CpuId::new();
        if let Some(fi) = cpuid.get_feature_info() {
            if fi.has_vmx() {
                return Ok(());
            }
        }
        Err(HypervisorError::VMXUnsupported)
    }

    /// Enable and enter VMX operation by setting and clearing the lock bit, adjusting control registers and executing the vmxon instruction.
    fn enable_vmx_operation(&mut self) -> Result<(), HypervisorError> {
        let mut cr4 = unsafe { controlregs::cr4() };
        cr4.set(controlregs::Cr4::CR4_ENABLE_VMX, true);
        unsafe { controlregs::cr4_write(cr4) };

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.7 ENABLING AND ENTERING VMX OPERATION */
        self.set_lock_bit()?;
        log::info!("[+] Lock bit set via IA32_FEATURE_CONTROL");

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.8 RESTRICTIONS ON VMX OPERATION */
        log::info!("[+] Adjusting Control Registers");
        self.adjust_control_registers();

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 24.7 ENABLING AND ENTERING VMX OPERATION */
        /* - 25.11.5 VMXON Region */
        log::info!("[+] init_vmxon_region");
        self.init_vmxon_region()?;

        Ok(())
    }

    /// Check if we need to set bits in IA32_FEATURE_CONTROL
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

    /// Set the mandatory bits in CR0 and clear bits that are mandatory zero
    fn set_cr0_bits(&self) {
        let ia32_vmx_cr0_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED0) };
        let ia32_vmx_cr0_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED1) };

        let mut cr0 = unsafe { controlregs::cr0() };

        cr0 |= controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed0 as usize);
        cr0 &= controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed1 as usize);

        unsafe { controlregs::cr0_write(cr0) };
    }

    /// Set the mandatory bits in CR4 and clear bits that are mandatory zero
    fn set_cr4_bits(&self) {
        let ia32_vmx_cr4_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED0) };
        let ia32_vmx_cr4_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED1) };

        let mut cr4 = unsafe { controlregs::cr4() };

        cr4 |= controlregs::Cr4::from_bits_truncate(ia32_vmx_cr4_fixed0 as usize);
        cr4 &= controlregs::Cr4::from_bits_truncate(ia32_vmx_cr4_fixed1 as usize);

        unsafe { controlregs::cr4_write(cr4) };
    }

    /// Get the Virtual Machine Control Structure revision identifier (VMCS revision ID)
    fn get_vmcs_revision_id(&self) -> u32 {
        unsafe { (msr::rdmsr(msr::IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF }
    }
}

// I found this part to be the hardest so I've reused the code and will reimplement at a later stage
// Full Credits: https://github.com/iankronquist/rustyvisor/blob/master/hypervisor/src/vmcs.rs
const GDT_ENTRY_ACCESS_PRESENT: u8 = 1 << 7;

// See Intel manual Table 24-2 ch 24-4 vol 3c
const VMX_INFO_SEGMENT_UNUSABLE: u32 = 1 << 16;

/// Given a global descriptor table, and a selector which indexes into the
/// table, unpack the corresponding GDT entry into an UnpackedGdtEntry.
pub fn unpack_gdt_entry(gdt: &[GdtEntry], selector: u16) -> UnpackedGdtEntry {
    let mut unpacked: UnpackedGdtEntry = Default::default();

    let index: usize = usize::from(selector) / core::mem::size_of::<GdtEntry>();
    if index == 0 {
        unpacked.access_rights |= VMX_INFO_SEGMENT_UNUSABLE;
        //trace!("Unpacked {:x?}", unpacked);
        return unpacked;
    }

    unpacked.selector = selector;
    unpacked.limit =
        u64::from(gdt[index].limit_low) | ((u64::from(gdt[index].granularity) & 0x0f) << 16);
    unpacked.base = u64::from(gdt[index].base_low);
    unpacked.base = (u64::from(gdt[index].base_high) << 24)
        | (u64::from(gdt[index].base_middle) << 16)
        | u64::from(gdt[index].base_low);

    unpacked.access_rights = u32::from(gdt[index].access);
    unpacked.access_rights |= u32::from((gdt[index].granularity) & 0xf0) << 8;
    unpacked.access_rights &= 0xf0ff;
    if (gdt[index].access & GDT_ENTRY_ACCESS_PRESENT) == 0 {
        unpacked.access_rights |= VMX_INFO_SEGMENT_UNUSABLE;
    }

    unpacked
}

// 32 bit GDT entry.
/// The layout of this structure is determined by hardware.
/// For more information see the Intel manual, Volume 3, Chapter 5
/// ("Protection"), Section 5.2 "Fields and Flags Used for Segment-Level and
/// Page-Level Protection".
/// See also the OS Dev wiki page on the [GDT](https://wiki.osdev.org/GDT) and
/// the accompanying [tutorial](https://wiki.osdev.org/GDT_Tutorial).
#[derive(Debug, Clone, Copy)]
#[allow(unused)]
#[repr(packed)]
pub struct GdtEntry {
    /// Low 16 bits of the segment limit.
    pub limit_low: u16,
    /// Low 16 bits of the segment base.
    pub base_low: u16,
    /// Middle 8 bits of the segment base.
    pub base_middle: u8,
    /// Various flags used to set segment type and access rights.
    pub access: u8,
    /// The low 4 bits are part of the limit. The high 4 bits are the
    /// granularity of the segment and the size.
    pub granularity: u8,
    /// High 8 bits of the segment base.
    pub base_high: u8,
}

/// GDT entries are packed in a complicated way meant to be backwards
/// compatible since the days of the i286. This represents the component parts
/// of a GDT entry unpacked into a format we can feed into various host and
/// guest VMCS entries.
#[derive(Default, Debug)]
pub struct UnpackedGdtEntry {
    /// The base of the segment.
    pub base: u64,
    /// The limit of the segment.
    pub limit: u64,
    /// The access rights of the segment.
    pub access_rights: u32,
    /// The segment selector.
    pub selector: u16,
}

/// Get a reference to the processor's current GDT.
pub fn get_current_gdt() -> &'static [GdtEntry] {
    let mut gdtr: x86::dtables::DescriptorTablePointer<u64> = Default::default();
    unsafe {
        x86::dtables::sgdt(&mut gdtr);
    }

    let bytes = usize::from(gdtr.limit) + 1;
    unsafe {
        core::slice::from_raw_parts(
            gdtr.base as *const GdtEntry,
            bytes / core::mem::size_of::<GdtEntry>(),
        )
    }
}

/// The types of the control field.
#[derive(Clone, Copy)]
pub enum VmxControl {
    PinBased,
    ProcessorBased,
    ProcessorBased2,
    VmExit,
    VmEntry,
}

// I did not know how to do this part so I took the help of Satoshi Tanda's code but I will reimplement in this in future after understanding it fully
// Full Credits to tandasat for this complicated part: https://github.com/tandasat/Hypervisor-101-in-Rust/blob/main/hypervisor/src/hardware_vt/vmx.rs#L617
pub fn adjust_vmx_controls(control: VmxControl, requested_value: u64) -> u64 {
    const IA32_VMX_BASIC_VMX_CONTROLS_FLAG: u64 = 1 << 55;

    let vmx_basic = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_BASIC) };
    let true_cap_msr_supported = (vmx_basic & IA32_VMX_BASIC_VMX_CONTROLS_FLAG) != 0;

    let cap_msr = match (control, true_cap_msr_supported) {
        (VmxControl::PinBased, true) => x86::msr::IA32_VMX_TRUE_PINBASED_CTLS,
        (VmxControl::PinBased, false) => x86::msr::IA32_VMX_PINBASED_CTLS,
        (VmxControl::ProcessorBased, true) => x86::msr::IA32_VMX_TRUE_PROCBASED_CTLS,
        (VmxControl::ProcessorBased, false) => x86::msr::IA32_VMX_PROCBASED_CTLS,
        (VmxControl::VmExit, true) => x86::msr::IA32_VMX_TRUE_EXIT_CTLS,
        (VmxControl::VmExit, false) => x86::msr::IA32_VMX_EXIT_CTLS,
        (VmxControl::VmEntry, true) => x86::msr::IA32_VMX_TRUE_ENTRY_CTLS,
        (VmxControl::VmEntry, false) => x86::msr::IA32_VMX_ENTRY_CTLS,
        // There is no TRUE MSR for IA32_VMX_PROCBASED_CTLS2. Just use
        // IA32_VMX_PROCBASED_CTLS2 unconditionally.
        (VmxControl::ProcessorBased2, _) => x86::msr::IA32_VMX_PROCBASED_CTLS2,
    };

    let capabilities = unsafe { x86::msr::rdmsr(cap_msr) };
    let allowed0 = capabilities as u32;
    let allowed1 = (capabilities >> 32) as u32;
    let mut effective_value = u32::try_from(requested_value).unwrap();
    effective_value |= allowed0;
    effective_value &= allowed1;
    u64::from(effective_value)
}
