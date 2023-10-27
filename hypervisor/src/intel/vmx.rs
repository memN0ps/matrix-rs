use {
    // Super imports
    super::{msr_bitmap::MsrBitmap, vmcs::Vmcs, vmstack::VmStack, vmxon::Vmxon},
    // Internal crate usages
    crate::{
        error::HypervisorError,
        intel::{
            controls::{adjust_vmx_controls, VmxControl},
            descriptor::DescriptorTables,
            segmentation::SegmentDescriptor,
            support::vmwrite,
            vmlaunch::vmexit_stub,
            vmstack::STACK_CONTENTS_SIZE,
        },
        println,
        utils::addresses::PhysicalAddress,
        utils::alloc::{KernelAlloc, PhysicalAllocator},
    },

    // External crate usages
    alloc::boxed::Box,
    wdk_sys::_CONTEXT,
    x86::{
        controlregs,
        dtables::{self},
        msr::{self},
        segmentation::SegmentSelector,
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

/// Custom memory allocator Boxed pointers for the Vmxon, Vmcs, MsrBitmap and HostRsp structures are stored in the Vmx struct to ensure they are not dropped.
#[repr(C, align(4096))]
pub struct Vmx {
    /// The virtual address of the Vmxon naturally aligned 4-KByte region of memory (MmAllocateContiguousMemorySpecifyCacheNode).
    pub vmxon_region: Box<Vmxon, PhysicalAllocator>,

    /// The virtual address of the Vmcs naturally aligned 4-KByte region of memory (MmAllocateContiguousMemorySpecifyCacheNode).
    pub vmcs_region: Box<Vmcs, PhysicalAllocator>,

    /// The virtual address of the MSR Bitmap naturally aligned 4-KByte region of memory (MmAllocateContiguousMemorySpecifyCacheNode).
    pub msr_bitmap: Box<MsrBitmap, PhysicalAllocator>,

    /// The virtual address of the Guest Descriptor Tables containing the GDT and IDT (ExAllocatePool / ExAllocatePoolWithTag).
    pub guest_descriptor_table: Box<DescriptorTables, KernelAlloc>,

    /// The virtual address of the Host Descriptor Tables containing the GDT and IDT (ExAllocatePool / ExAllocatePoolWithTag).
    pub host_descriptor_table: Box<DescriptorTables, KernelAlloc>,

    /// The virtual address of the VMCS_HOST_RSP naturally aligned 4-KByte region of memory (ExAllocatePool / ExAllocatePoolWithTag).
    pub host_rsp: Box<VmStack, KernelAlloc>,
}

impl Vmx {
    /// The `Vmx` struct encapsulates the structures necessary for VMX virtualization.
    /// Memory Allocation Considerations:
    /// - Boxed pointers for the Vmxon, Vmcs, MsrBitmap, and HostRsp structures are stored within the Vmx struct to ensure they aren't dropped prematurely.
    /// - Avoid using ExAllocatePool at high IRQL, which can lead to heap corruption.
    /// - Initial memory allocation should be done early using ExAllocatePoolWithTag, and direct calls to it should then be avoided.
    /// - For subsequent allocations, a custom allocator that uses the pre-allocated memory should be utilized.
    /// - Rust's automatic memory management can be a pitfall; dropping a `Box` at high IRQL might trigger unintended deallocations.
    pub fn new() -> Result<Box<Self>, HypervisorError> {
        println!("Setting up VMX");

        // Allocate memory for the hypervisor's needs
        let vmxon_region = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };
        let vmcs_region = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };
        let msr_bitmap = unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };
        let mut guest_descriptor_table =
            unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };
        let mut host_descriptor_table =
            unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };
        let host_rsp = unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };

        // To capture the current GDT and IDT for the guest the order is important so we can setup up a new GDT and IDT for the host.
        // This is done here instead of `setup_virtualization` because it uses a vec to allocate memory for the new GDT
        DescriptorTables::initialize_for_guest(&mut guest_descriptor_table)?;
        DescriptorTables::initialize_for_host(&mut host_descriptor_table)?;

        println!("Creating Vmx instance");

        let instance = Self {
            vmxon_region,
            vmcs_region,
            msr_bitmap,
            guest_descriptor_table,
            host_descriptor_table,
            host_rsp,
        };

        let instance = Box::new(instance);

        println!("VMX setup successful!");

        Ok(instance)
    }

    pub fn setup_virtualization(&mut self, context: &_CONTEXT) -> Result<(), HypervisorError> {
        println!("Virtualization setup");

        Vmxon::setup(&mut self.vmxon_region)?;
        Vmcs::setup(&mut self.vmcs_region)?;
        MsrBitmap::setup(&mut self.msr_bitmap)?;
        VmStack::setup(&mut self.host_rsp)?;

        // Set the self_data pointer to the instance. This can be used in the vmexit_handler to retrieve the instance.
        // instance.host_rsp.self_data = &mut *instance as *mut _ as _;

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.4 GUEST-STATE AREA */
        println!("Setting up Guest Registers State");
        self.setup_guest_registers_state(&context);
        println!("Guest Registers State successful!");

        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.5 HOST-STATE AREA */
        println!("Setting up Host Registers State");
        self.setup_host_registers_state(&context);
        println!("Host Registers State successful!");

        /*
         * VMX controls:
         * Intel® 64 and IA-32 Architectures Software Developer's Manual references:
         * - 25.6 VM-EXECUTION CONTROL FIELDS
         * - 25.7 VM-EXIT CONTROL FIELDS
         * - 25.8 VM-ENTRY CONTROL FIELDS
         */
        println!("Setting up VMCS Control Fields");
        self.setup_vmcs_control_fields();
        println!("VMCS Control Fields successful!");

        println!("Virtualization setup successful!");
        Ok(())
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
    fn setup_guest_registers_state(&mut self, context: &_CONTEXT) {
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

        vmwrite(guest::CS_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegCs), &self.guest_descriptor_table.gdtr).base_address);
        vmwrite(guest::SS_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegSs), &self.guest_descriptor_table.gdtr).base_address);
        vmwrite(guest::DS_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegDs), &self.guest_descriptor_table.gdtr).base_address);
        vmwrite(guest::ES_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegEs), &self.guest_descriptor_table.gdtr).base_address);
        unsafe { vmwrite(guest::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE)) };
        unsafe { vmwrite(guest::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE)) };
        unsafe { vmwrite(guest::LDTR_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(dtables::ldtr().bits()), &self.guest_descriptor_table.gdtr).base_address) };
        unsafe { vmwrite(guest::TR_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &self.guest_descriptor_table.gdtr).base_address) };

        vmwrite(guest::CS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegCs), &self.guest_descriptor_table.gdtr).segment_limit);
        vmwrite(guest::SS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegSs), &self.guest_descriptor_table.gdtr).segment_limit);
        vmwrite(guest::DS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegDs), &self.guest_descriptor_table.gdtr).segment_limit);
        vmwrite(guest::ES_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegEs), &self.guest_descriptor_table.gdtr).segment_limit);
        vmwrite(guest::FS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegFs), &self.guest_descriptor_table.gdtr).segment_limit);
        vmwrite(guest::GS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegGs), &self.guest_descriptor_table.gdtr).segment_limit);
        unsafe { vmwrite(guest::LDTR_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(dtables::ldtr().bits()), &self.guest_descriptor_table.gdtr).segment_limit) };
        unsafe { vmwrite(guest::TR_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &self.guest_descriptor_table.gdtr).segment_limit) };

        vmwrite(guest::CS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegCs), &self.guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(guest::SS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegSs), &self.guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(guest::DS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegDs), &self.guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(guest::ES_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegEs), &self.guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(guest::FS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegFs), &self.guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(guest::GS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegGs), &self.guest_descriptor_table.gdtr).access_rights.bits());
        unsafe { vmwrite(guest::LDTR_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(dtables::ldtr().bits()), &self.guest_descriptor_table.gdtr).access_rights.bits()) };
        unsafe { vmwrite(guest::TR_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &self.guest_descriptor_table.gdtr).access_rights.bits()) };

        vmwrite(guest::GDTR_BASE, self.guest_descriptor_table.gdtr.base as u64);
        vmwrite(guest::IDTR_BASE, self.guest_descriptor_table.idtr.base as u64);

        vmwrite(guest::GDTR_LIMIT, self.guest_descriptor_table.gdtr.limit as u64);
        vmwrite(guest::IDTR_LIMIT, self.guest_descriptor_table.idtr.limit as u64);

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
    fn setup_host_registers_state(&mut self, context: &_CONTEXT) {
        unsafe { vmwrite(host::CR0, controlregs::cr0().bits() as u64) };
        unsafe { vmwrite(host::CR3, controlregs::cr3()) };
        unsafe { vmwrite(host::CR4, controlregs::cr4().bits() as u64) };

        let host_rsp_ptr = self.host_rsp.stack_contents.as_mut_ptr();
        let host_rsp = unsafe { host_rsp_ptr.offset(STACK_CONTENTS_SIZE as isize) };
        vmwrite(host::RIP, vmexit_stub as u64);
        vmwrite(host::RSP, host_rsp as u64);

        const SELECTOR_MASK: u16 = 0xF8;
        vmwrite(host::CS_SELECTOR, context.SegCs & SELECTOR_MASK);
        vmwrite(host::SS_SELECTOR, context.SegSs & SELECTOR_MASK);
        vmwrite(host::DS_SELECTOR, context.SegDs & SELECTOR_MASK);
        vmwrite(host::ES_SELECTOR, context.SegEs & SELECTOR_MASK);
        vmwrite(host::FS_SELECTOR, context.SegFs & SELECTOR_MASK);
        vmwrite(host::GS_SELECTOR, context.SegGs & SELECTOR_MASK);
        unsafe { vmwrite(host::TR_SELECTOR, task::tr().bits() & SELECTOR_MASK) };

        unsafe { vmwrite(host::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE)) };
        unsafe { vmwrite(host::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE)) };
        unsafe { vmwrite(host::TR_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &self.host_descriptor_table.gdtr).base_address) };
        vmwrite(host::GDTR_BASE, self.host_descriptor_table.gdtr.base as u64);
        vmwrite(host::IDTR_BASE, self.host_descriptor_table.idtr.base as u64);

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
    #[rustfmt::skip]
    fn setup_vmcs_control_fields(&mut self) {
        const PRIMARY_CTL: u64 = PrimaryControls::SECONDARY_CONTROLS.bits() as u64;
        const SECONDARY_CTL: u64 = (SecondaryControls::ENABLE_RDTSCP.bits() | SecondaryControls::ENABLE_XSAVES_XRSTORS.bits() | SecondaryControls::ENABLE_INVPCID.bits()) as u64;
        const ENTRY_CTL: u64 = EntryControls::IA32E_MODE_GUEST.bits() as u64;
        const EXIT_CTL: u64 = ExitControls::HOST_ADDRESS_SPACE_SIZE.bits() as u64;
        const PINBASED_CTL: u64 = 0;

        vmwrite(vmx::vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased, PRIMARY_CTL));
        vmwrite(vmx::vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased2, SECONDARY_CTL));
        vmwrite(vmx::vmcs::control::VMENTRY_CONTROLS, adjust_vmx_controls(VmxControl::VmEntry, ENTRY_CTL));
        vmwrite(vmx::vmcs::control::VMEXIT_CONTROLS, adjust_vmx_controls(VmxControl::VmExit, EXIT_CTL));
        vmwrite(vmx::vmcs::control::PINBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::PinBased, PINBASED_CTL));

        unsafe {
            vmwrite(vmx::vmcs::control::CR0_READ_SHADOW, controlregs::cr0().bits() as u64);
            vmwrite(vmx::vmcs::control::CR4_READ_SHADOW, controlregs::cr4().bits() as u64);
        };

        let msr_bitmap_physical_address = PhysicalAddress::pa_from_va(self.msr_bitmap.as_ref() as *const _ as _);

        if msr_bitmap_physical_address == 0 {
            panic!("Failed to get physical address of MSR Bitmap");
        }

        vmwrite(vmx::vmcs::control::MSR_BITMAPS_ADDR_FULL, msr_bitmap_physical_address);
    }
}
