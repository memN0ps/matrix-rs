use {
    alloc::boxed::Box,
    kernel_alloc::{KernelAlloc, PhysicalAllocator},
    x86::{
        controlregs,
        dtables::{self},
        msr::{self},
        task,
        vmx::{
            self,
            vmcs::{
                control::{EntryControls, ExitControls, PrimaryControls, SecondaryControls},
                guest, host,
            },
        },
    },
};

use crate::{
    error::HypervisorError,
    x86_64::{
        intel::{hostrsp::STACK_CONTENTS_SIZE, support::vmwrite, vmexit::vmexit_stub},
        utils::{addresses::PhysicalAddress, nt::Context},
    },
};

use super::{bitmap::MsrBitmap, hostrsp::HostRsp, vmcs::Vmcs, vmxon::Vmxon};

/// Custom memory allocator Boxed pointers for the Vmxon, Vmcs, MsrBitmap and HostRsp structures are stored in the Vmx struct to ensure they are not dropped.
pub struct Vmx {
    /// The virtual address of the Vmxon naturally aligned 4-KByte region of memory (MmAllocateContiguousMemorySpecifyCacheNode)
    pub vmxon_region: Box<Vmxon, PhysicalAllocator>,

    /// The virtual address of the Vmcs naturally aligned 4-KByte region of memory (MmAllocateContiguousMemorySpecifyCacheNode)
    pub vmcs_region: Box<Vmcs, PhysicalAllocator>,

    // The virtual address of the MSR Bitmap naturally aligned 4-KByte region of memory (ExAllocatePool / ExAllocatePoolWithTag)
    pub msr_bitmap: Box<MsrBitmap, KernelAlloc>,

    /// The virtual address of the VMCS_HOST_RSP naturally aligned 4-KByte region of memory (ExAllocatePool / ExAllocatePoolWithTag)
    pub host_rsp: Box<HostRsp, KernelAlloc>,
}

impl Vmx {
    pub fn new(context: Context) -> Result<Box<Self>, HypervisorError> {
        log::info!("Setting up VMXON, VMCS, MSR Bitmap and Host RSP structures");
        let vmxon_region = Vmxon::new()?;
        let vmcs_region = Vmcs::new()?;
        let msr_bitmap = MsrBitmap::new()?;
        let host_rsp = HostRsp::new()?;

        let instance = Self {
            vmxon_region,
            vmcs_region,
            msr_bitmap,
            host_rsp,
        };

        let mut instance = Box::new(instance);

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.4 GUEST-STATE AREA */
        log::info!("Setting up Guest Registers State");
        instance.setup_guest_registers_state(context);
        log::info!("Guest Registers State successful!");

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.5 HOST-STATE AREA */
        log::info!("Setting up Host Registers State");
        instance.setup_host_registers_state(context);
        log::info!("Host Registers State successful!");

        /*
         * VMX controls:
         * Intel® 64 and IA-32 Architectures Software Developer's Manual references:
         * - 25.6 VM-EXECUTION CONTROL FIELDS
         * - 25.7 VM-EXIT CONTROL FIELDS
         * - 25.8 VM-ENTRY CONTROL FIELDS
         */
        log::info!("Setting up VMCS Control Fields");
        instance.setup_vmcs_control_fields();
        log::info!("VMCS Control Fields successful!");

        log::info!("VMXON, VMCS, MSR Bitmap and Host RSP structures successful!");
        Ok(instance)
    }

    /// Initialize the guest state for the currently loaded VMCS.
    /// # Guest state
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual 25.4 GUEST-STATE AREA:
    /// - CR0, CR3, and CR4
    /// - DR7
    /// - RSP, RIP, and RFLAGS
    /// - Segment Selector, Base address, Segment limit, Access rights:
    ///     - CS, SS, DS, ES, FS, GS, LDTR, and TR
    /// - Base, Limit:
    ///     - GDTR and IDTR
    /// - MSRs:
    ///     - IA32_DEBUGCTL
    ///     - IA32_SYSENTER_CS
    ///     - IA32_SYSENTER_ESP
    ///     - IA32_SYSENTER_EIP
    ///     - LINK_PTR_FULL
    #[rustfmt::skip]
    fn setup_guest_registers_state(&mut self, context: Context) {
        unsafe { vmwrite(guest::CR0, controlregs::cr0().bits() as u64) };
        unsafe { vmwrite(guest::CR3, controlregs::cr3()) };
        unsafe { vmwrite(guest::CR4, controlregs::cr4().bits() as u64) };

        vmwrite(guest::DR7, context.Dr7);

        vmwrite(guest::RSP, context.Rsp);
        vmwrite(guest::RIP, context.Rip);
        vmwrite(guest::RFLAGS, context.EFlags);

        vmwrite(guest::CS_SELECTOR, context.SegCs);
        vmwrite(guest::SS_SELECTOR, context.SegSs);
        vmwrite(guest::DS_SELECTOR, context.SegDs);
        vmwrite(guest::ES_SELECTOR, context.SegEs);
        vmwrite(guest::FS_SELECTOR, context.SegFs);
        vmwrite(guest::GS_SELECTOR, context.SegGs);
        unsafe { vmwrite(guest::LDTR_SELECTOR, dtables::ldtr().bits() as u64) };
        unsafe { vmwrite(guest::TR_SELECTOR, task::tr().bits() as u64) };

        let gdt = get_current_gdt();

        vmwrite(guest::CS_BASE, unpack_gdt_entry(gdt, context.SegCs).base);
        vmwrite(guest::SS_BASE, unpack_gdt_entry(gdt, context.SegSs).base);
        vmwrite(guest::DS_BASE, unpack_gdt_entry(gdt, context.SegDs).base);
        vmwrite(guest::ES_BASE, unpack_gdt_entry(gdt, context.SegEs).base);
        unsafe { vmwrite(guest::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE)) };
        unsafe { vmwrite(guest::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE)) };
        unsafe { vmwrite(guest::LDTR_BASE, unpack_gdt_entry(gdt, x86::dtables::ldtr().bits()).base) };
        unsafe { vmwrite(guest::TR_BASE, unpack_gdt_entry(gdt,  x86::task::tr().bits()).base) };

        vmwrite(guest::CS_LIMIT, unpack_gdt_entry(gdt, context.SegCs).limit);
        vmwrite(guest::SS_LIMIT, unpack_gdt_entry(gdt, context.SegSs).limit);
        vmwrite(guest::DS_LIMIT, unpack_gdt_entry(gdt, context.SegDs).limit);
        vmwrite(guest::ES_LIMIT, unpack_gdt_entry(gdt, context.SegEs).limit);
        vmwrite(guest::FS_LIMIT, unpack_gdt_entry(gdt, context.SegFs).limit);
        vmwrite(guest::GS_LIMIT, unpack_gdt_entry(gdt, context.SegGs).limit);
        unsafe { vmwrite(guest::LDTR_LIMIT, unpack_gdt_entry(gdt, dtables::ldtr().bits()).limit) };
        unsafe { vmwrite(guest::TR_LIMIT, unpack_gdt_entry(gdt, task::tr().bits()).limit) };

        vmwrite(guest::CS_ACCESS_RIGHTS, unpack_gdt_entry(gdt, context.SegCs).access_rights);
        vmwrite(guest::SS_ACCESS_RIGHTS, unpack_gdt_entry(gdt, context.SegSs).access_rights);
        vmwrite(guest::DS_ACCESS_RIGHTS, unpack_gdt_entry(gdt, context.SegDs).access_rights);
        vmwrite(guest::ES_ACCESS_RIGHTS, unpack_gdt_entry(gdt, context.SegEs).access_rights);
        vmwrite(guest::FS_ACCESS_RIGHTS, unpack_gdt_entry(gdt, context.SegFs).access_rights);
        vmwrite(guest::GS_ACCESS_RIGHTS, unpack_gdt_entry(gdt, context.SegGs).access_rights);
        unsafe { vmwrite(guest::LDTR_ACCESS_RIGHTS, unpack_gdt_entry(gdt, dtables::ldtr().bits()).access_rights) };
        unsafe { vmwrite(guest::TR_ACCESS_RIGHTS, unpack_gdt_entry(gdt, task::tr().bits()).access_rights) };

        let mut guest_gdtr: dtables::DescriptorTablePointer<u64> = Default::default();
        unsafe { dtables::sgdt(&mut guest_gdtr); }

        let mut guest_idtr: dtables::DescriptorTablePointer<u64> = Default::default();
        unsafe { dtables::sidt(&mut guest_idtr); }

        vmwrite(guest::GDTR_BASE, guest_gdtr.base as u64);
        vmwrite(guest::IDTR_BASE, guest_idtr.base as u64);

        vmwrite(guest::GDTR_LIMIT, guest_gdtr.limit);
        vmwrite(guest::IDTR_LIMIT, guest_idtr.limit);

        unsafe {
            vmwrite(guest::IA32_DEBUGCTL_FULL, msr::rdmsr(msr::IA32_DEBUGCTL));
            vmwrite(guest::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS));
            vmwrite(guest::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP));
            vmwrite(guest::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP));
            vmwrite(guest::LINK_PTR_FULL, u64::MAX);
        }
    }

    /// Initialize the host state for the currently loaded VMCS.
    /// # Host state
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.5 HOST-STATE AREA
    /// - CR0, CR3, and CR4
    /// - RSP and RIP
    /// - Selector Fields: CS, SS, DS, ES, FS, GS, and TR
    /// - Base Address: FS, GS, TR, GDTR, and IDTR
    /// - MSR's:
    ///     - IA32_SYSENTER_CS
    ///     - IA32_SYSENTER_ESP
    ///     - IA32_SYSENTER_EIP
    #[rustfmt::skip]
    fn setup_host_registers_state(&mut self, context: Context) {
        let mut host_gdtr: dtables::DescriptorTablePointer<u64> = Default::default();
        unsafe { dtables::sgdt(&mut host_gdtr); }

        let mut host_idtr: dtables::DescriptorTablePointer<u64> = Default::default();
        unsafe { dtables::sidt(&mut host_idtr); }

        unsafe { vmwrite(host::CR0, controlregs::cr0().bits() as u64) };
        unsafe { vmwrite(host::CR3, controlregs::cr3()) };
        unsafe { vmwrite(host::CR4, controlregs::cr4().bits() as u64) };

        let host_rsp = &mut self.host_rsp.as_ref() as *mut _ as u64;
        vmwrite(host::RIP, vmexit_stub as u64);
        vmwrite(host::RSP, host_rsp + STACK_CONTENTS_SIZE as u64);

        const SELECTOR_MASK: u16 = 0xF8;
        vmwrite(host::CS_SELECTOR, context.SegCs & SELECTOR_MASK);
        vmwrite(host::SS_SELECTOR, context.SegSs & SELECTOR_MASK);
        vmwrite(host::DS_SELECTOR, context.SegDs & SELECTOR_MASK);
        vmwrite(host::ES_SELECTOR, context.SegEs & SELECTOR_MASK);
        vmwrite(host::FS_SELECTOR, context.SegFs & SELECTOR_MASK);
        vmwrite(host::GS_SELECTOR, context.SegGs & SELECTOR_MASK);
        unsafe { vmwrite(host::TR_SELECTOR, task::tr().bits() & SELECTOR_MASK) };

        let gdt = get_current_gdt();

        unsafe { vmwrite(host::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE)) };
        unsafe { vmwrite(host::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE)) };
        unsafe { vmwrite(host::TR_BASE, unpack_gdt_entry(gdt,  x86::task::tr().bits()).base) };
        vmwrite(host::GDTR_BASE, host_gdtr.base as u64);
        vmwrite(host::IDTR_BASE, host_idtr.base as u64);

        unsafe {
            vmwrite(host::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS));
            vmwrite(host::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP));
            vmwrite(host::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP));
        }
    }

    /// Initialize the VMCS control values for the currently loaded VMCS.
    /// # VMX controls
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual:
    /// - 25.6 VM-EXECUTION CONTROL FIELDS
    /// - 25.7 VM-EXIT CONTROL FIELDS
    /// - 25.8 VM-ENTRY CONTROL FIELDS
    /// - 25.6 VM-EXECUTION CONTROL FIELDS
    #[rustfmt::skip]
    fn setup_vmcs_control_fields(&mut self) {
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

        unsafe {
            vmwrite(x86::vmx::vmcs::control::CR0_READ_SHADOW, controlregs::cr0().bits() as u64);
            vmwrite(x86::vmx::vmcs::control::CR4_READ_SHADOW, controlregs::cr4().bits() as u64);
            log::info!("VMCS Controls Shadow Registers initialized!");
        };

        let msr_bitmap_physical_address = PhysicalAddress::pa_from_va(self.msr_bitmap.as_ref() as *const _ as _);

        if msr_bitmap_physical_address == 0 {
            panic!("Failed to get physical address of MSR Bitmap");
        }

        vmwrite(x86::vmx::vmcs::control::MSR_BITMAPS_ADDR_FULL, msr_bitmap_physical_address);
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
