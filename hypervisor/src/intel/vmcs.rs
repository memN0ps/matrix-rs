//! A crate responsible for managing the VMCS region for VMX operations.
//!
//! This crate provides functionality to set up the VMCS region in memory, which
//! is vital for VMX operations on the CPU. It also offers utility functions for
//! adjusting VMCS entries and displaying VMCS state for debugging purposes.

use {
    // Internal crate usages
    crate::{
        error::HypervisorError,
        intel::{
            controls::{adjust_vmx_controls, VmxControl},
            descriptor::DescriptorTables,
            msr_bitmap::MsrBitmap,
            segmentation::SegmentDescriptor,
            support::{vmclear, vmptrld, vmread, vmwrite},
            vmlaunch::vmexit_stub,
            vmstack::{VmStack, STACK_CONTENTS_SIZE},
        },
        println,
        utils::{
            addresses::PhysicalAddress,
            alloc::{KernelAlloc, PhysicalAllocator},
        },
    },

    // External crate usages
    alloc::boxed::Box,
    bitfield::BitMut,
    core::fmt,
    wdk_sys::_CONTEXT,
    x86::{
        controlregs,
        dtables::{self},
        msr::{self},
        segmentation::SegmentSelector,
        task,
        vmx::vmcs::{
            control,
            control::{EntryControls, ExitControls, PrimaryControls, SecondaryControls},
            guest, host,
        },
    },
};

pub const PAGE_SIZE: usize = 0x1000;

/// Represents the VMCS region in memory.
///
/// The VMCS region is essential for VMX operations on the CPU.
/// This structure offers methods for setting up the VMCS region, adjusting VMCS entries,
/// and performing related tasks.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.2 FORMAT OF THE VMCS REGION
#[repr(C, align(4096))]
pub struct Vmcs {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub reserved: [u8; PAGE_SIZE - 8],
}

impl Vmcs {
    /// Sets up the VMCS region.
    ///
    /// # Arguments
    /// * `vmcs_region` - A mutable reference to the VMCS region in memory.
    ///
    /// # Returns
    /// A result indicating success or an error.
    pub fn setup(vmcs_region: &mut Box<Vmcs, PhysicalAllocator>) -> Result<(), HypervisorError> {
        println!("Setting up VMCS region");

        let vmcs_region_physical_address =
            PhysicalAddress::pa_from_va(vmcs_region.as_ref() as *const _ as _);

        if vmcs_region_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        println!("VMCS Region Virtual Address: {:p}", vmcs_region);
        println!(
            "VMCS Region Physical Addresss: 0x{:x}",
            vmcs_region_physical_address
        );

        vmcs_region.revision_id = Self::get_vmcs_revision_id();
        vmcs_region.as_mut().revision_id.set_bit(31, false);

        // Clear the VMCS region.
        vmclear(vmcs_region_physical_address);
        println!("VMCLEAR successful!");

        // Load current VMCS pointer.
        vmptrld(vmcs_region_physical_address);
        println!("VMPTRLD successful!");

        println!("VMCS setup successful!");

        Ok(())
    }

    /// Initialize the guest state for the currently loaded VMCS.
    ///
    /// The method sets up various guest state fields in the VMCS as per the
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual 25.4 GUEST-STATE AREA.
    ///
    /// # Arguments
    /// * `context` - Context containing the guest's register states.
    /// * `guest_descriptor_table` - Descriptor tables for the guest.
    #[rustfmt::skip]
    pub fn setup_guest_registers_state(context: &_CONTEXT, guest_descriptor_table: &Box<DescriptorTables, KernelAlloc>) {
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

        vmwrite(guest::CS_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegCs), &guest_descriptor_table.gdtr).base_address);
        vmwrite(guest::SS_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegSs), &guest_descriptor_table.gdtr).base_address);
        vmwrite(guest::DS_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegDs), &guest_descriptor_table.gdtr).base_address);
        vmwrite(guest::ES_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegEs), &guest_descriptor_table.gdtr).base_address);
        unsafe { vmwrite(guest::FS_BASE, msr::rdmsr(msr::IA32_FS_BASE)) };
        unsafe { vmwrite(guest::GS_BASE, msr::rdmsr(msr::IA32_GS_BASE)) };
        unsafe { vmwrite(guest::LDTR_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(dtables::ldtr().bits()), &guest_descriptor_table.gdtr).base_address) };
        unsafe { vmwrite(guest::TR_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &guest_descriptor_table.gdtr).base_address) };

        vmwrite(guest::CS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegCs), &guest_descriptor_table.gdtr).segment_limit);
        vmwrite(guest::SS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegSs), &guest_descriptor_table.gdtr).segment_limit);
        vmwrite(guest::DS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegDs), &guest_descriptor_table.gdtr).segment_limit);
        vmwrite(guest::ES_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegEs), &guest_descriptor_table.gdtr).segment_limit);
        vmwrite(guest::FS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegFs), &guest_descriptor_table.gdtr).segment_limit);
        vmwrite(guest::GS_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegGs), &guest_descriptor_table.gdtr).segment_limit);
        unsafe { vmwrite(guest::LDTR_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(dtables::ldtr().bits()), &guest_descriptor_table.gdtr).segment_limit) };
        unsafe { vmwrite(guest::TR_LIMIT, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &guest_descriptor_table.gdtr).segment_limit) };

        vmwrite(guest::CS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegCs), &guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(guest::SS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegSs), &guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(guest::DS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegDs), &guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(guest::ES_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegEs), &guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(guest::FS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegFs), &guest_descriptor_table.gdtr).access_rights.bits());
        vmwrite(guest::GS_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(context.SegGs), &guest_descriptor_table.gdtr).access_rights.bits());
        unsafe { vmwrite(guest::LDTR_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(dtables::ldtr().bits()), &guest_descriptor_table.gdtr).access_rights.bits()) };
        unsafe { vmwrite(guest::TR_ACCESS_RIGHTS, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &guest_descriptor_table.gdtr).access_rights.bits()) };

        vmwrite(guest::GDTR_BASE, guest_descriptor_table.gdtr.base as u64);
        vmwrite(guest::IDTR_BASE, guest_descriptor_table.idtr.base as u64);

        vmwrite(guest::GDTR_LIMIT, guest_descriptor_table.gdtr.limit as u64);
        vmwrite(guest::IDTR_LIMIT, guest_descriptor_table.idtr.limit as u64);

        unsafe {
            vmwrite(guest::IA32_DEBUGCTL_FULL, msr::rdmsr(msr::IA32_DEBUGCTL));
            vmwrite(guest::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS));
            vmwrite(guest::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP));
            vmwrite(guest::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP));
            vmwrite(guest::LINK_PTR_FULL, u64::MAX);
        }
    }

    /// Initialize the host state for the currently loaded VMCS.
    ///
    /// The method sets up various host state fields in the VMCS as per the
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual 25.5 HOST-STATE AREA.
    ///
    /// # Arguments
    /// * `context` - Context containing the host's register states.
    /// * `host_descriptor_table` - Descriptor tables for the host.
    /// * `host_rsp` - Stack pointer for the host.
    #[rustfmt::skip]
    pub fn setup_host_registers_state(context: &_CONTEXT, host_descriptor_table: &Box<DescriptorTables, KernelAlloc>, host_rsp: &Box<VmStack, KernelAlloc>) {
        unsafe { vmwrite(host::CR0, controlregs::cr0().bits() as u64) };
        unsafe { vmwrite(host::CR3, controlregs::cr3()) };
        unsafe { vmwrite(host::CR4, controlregs::cr4().bits() as u64) };

        let host_rsp_ptr = host_rsp.stack_contents.as_ptr();
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
        unsafe { vmwrite(host::TR_BASE, SegmentDescriptor::from_selector(SegmentSelector::from_raw(task::tr().bits()), &host_descriptor_table.gdtr).base_address) };
        vmwrite(host::GDTR_BASE, host_descriptor_table.gdtr.base as u64);
        vmwrite(host::IDTR_BASE, host_descriptor_table.idtr.base as u64);

        unsafe {
            vmwrite(host::IA32_SYSENTER_CS, msr::rdmsr(msr::IA32_SYSENTER_CS));
            vmwrite(host::IA32_SYSENTER_ESP, msr::rdmsr(msr::IA32_SYSENTER_ESP));
            vmwrite(host::IA32_SYSENTER_EIP, msr::rdmsr(msr::IA32_SYSENTER_EIP));
        }
    }

    /// Initialize the VMCS control values for the currently loaded VMCS.
    ///
    /// The method sets up various VMX control fields in the VMCS as per the
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual sections:
    /// - 25.6 VM-EXECUTION CONTROL FIELDS
    /// - 25.7 VM-EXIT CONTROL FIELDS
    /// - 25.8 VM-ENTRY CONTROL FIELDS
    ///
    /// # Arguments
    /// * `msr_bitmap` - Bitmap for Model-Specific Registers.
    #[rustfmt::skip]
    pub fn setup_vmcs_control_fields(msr_bitmap: &Box<MsrBitmap, PhysicalAllocator>) {
        const PRIMARY_CTL: u64 = PrimaryControls::SECONDARY_CONTROLS.bits() as u64;
        const SECONDARY_CTL: u64 = (SecondaryControls::ENABLE_RDTSCP.bits() | SecondaryControls::ENABLE_XSAVES_XRSTORS.bits() | SecondaryControls::ENABLE_INVPCID.bits()) as u64;
        const ENTRY_CTL: u64 = EntryControls::IA32E_MODE_GUEST.bits() as u64;
        const EXIT_CTL: u64 = ExitControls::HOST_ADDRESS_SPACE_SIZE.bits() as u64;
        const PINBASED_CTL: u64 = 0;

        vmwrite(control::PRIMARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased, PRIMARY_CTL));
        vmwrite(control::SECONDARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased2, SECONDARY_CTL));
        vmwrite(control::VMENTRY_CONTROLS, adjust_vmx_controls(VmxControl::VmEntry, ENTRY_CTL));
        vmwrite(control::VMEXIT_CONTROLS, adjust_vmx_controls(VmxControl::VmExit, EXIT_CTL));
        vmwrite(control::PINBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::PinBased, PINBASED_CTL));

        unsafe {
            vmwrite(control::CR0_READ_SHADOW, controlregs::cr0().bits() as u64);
            vmwrite(control::CR4_READ_SHADOW, controlregs::cr4().bits() as u64);
        };

        vmwrite(control::MSR_BITMAPS_ADDR_FULL, PhysicalAddress::pa_from_va(msr_bitmap.as_ref() as *const _ as _));
    }

    /// Retrieves the VMCS revision ID.
    pub fn get_vmcs_revision_id() -> u32 {
        unsafe { (msr::rdmsr(msr::IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF }
    }
}

/// Debug implementation to dump the VMCS fields.
impl fmt::Debug for Vmcs {
    /// Formats the VMCS for display.
    ///
    /// # Arguments
    /// * `format` - Formatter instance.
    ///
    /// # Returns
    /// Formatting result.
    #[rustfmt::skip]
    fn fmt(&self, format: &mut fmt::Formatter<'_>) -> fmt::Result {

        format.debug_struct("Vmcs")
            .field("Current VMCS: ", &(self as *const _))
            .field("Revision ID: ", &self.revision_id)

            /* VMCS Guest state fields */
            .field("Guest CR0: ", &vmread(guest::CR0))
            .field("Guest CR3: ", &vmread(guest::CR3))
            .field("Guest CR4: ", &vmread(guest::CR4))
            .field("Guest DR7: ", &vmread(guest::DR7))
            .field("Guest RSP: ", &vmread(guest::RSP))
            .field("Guest RIP: ", &vmread(guest::RIP))
            .field("Guest RFLAGS: ", &vmread(guest::RFLAGS))

            .field("Guest CS Selector: ", &vmread(guest::CS_SELECTOR))
            .field("Guest SS Selector: ", &vmread(guest::SS_SELECTOR))
            .field("Guest DS Selector: ", &vmread(guest::DS_SELECTOR))
            .field("Guest ES Selector: ", &vmread(guest::ES_SELECTOR))
            .field("Guest FS Selector: ", &vmread(guest::FS_SELECTOR))
            .field("Guest GS Selector: ", &vmread(guest::GS_SELECTOR))
            .field("Guest LDTR Selector: ", &vmread(guest::LDTR_SELECTOR))
            .field("Guest TR Selector: ", &vmread(guest::TR_SELECTOR))

            .field("Guest CS Base: ", &vmread(guest::CS_BASE))
            .field("Guest SS Base: ", &vmread(guest::SS_BASE))
            .field("Guest DS Base: ", &vmread(guest::DS_BASE))
            .field("Guest ES Base: ", &vmread(guest::ES_BASE))
            .field("Guest FS Base: ", &vmread(guest::FS_BASE))
            .field("Guest GS Base: ", &vmread(guest::GS_BASE))
            .field("Guest LDTR Base: ", &vmread(guest::LDTR_BASE))
            .field("Guest TR Base: ", &vmread(guest::TR_BASE))

            .field("Guest CS Limit: ", &vmread(guest::CS_LIMIT))
            .field("Guest SS Limit: ", &vmread(guest::SS_LIMIT))
            .field("Guest DS Limit: ", &vmread(guest::DS_LIMIT))
            .field("Guest ES Limit: ", &vmread(guest::ES_LIMIT))
            .field("Guest FS Limit: ", &vmread(guest::FS_LIMIT))
            .field("Guest GS Limit: ", &vmread(guest::GS_LIMIT))
            .field("Guest LDTR Limit: ", &vmread(guest::LDTR_LIMIT))
            .field("Guest TR Limit: ", &vmread(guest::TR_LIMIT))

            .field("Guest CS Access Rights: ", &vmread(guest::CS_ACCESS_RIGHTS))
            .field("Guest SS Access Rights: ", &vmread(guest::SS_ACCESS_RIGHTS))
            .field("Guest DS Access Rights: ", &vmread(guest::DS_ACCESS_RIGHTS))
            .field("Guest ES Access Rights: ", &vmread(guest::ES_ACCESS_RIGHTS))
            .field("Guest FS Access Rights: ", &vmread(guest::FS_ACCESS_RIGHTS))
            .field("Guest GS Access Rights: ", &vmread(guest::GS_ACCESS_RIGHTS))
            .field("Guest LDTR Access Rights: ", &vmread(guest::LDTR_ACCESS_RIGHTS))
            .field("Guest TR Access Rights: ", &vmread(guest::TR_ACCESS_RIGHTS))

            .field("Guest GDTR Base: ", &vmread(guest::GDTR_BASE))
            .field("Guest IDTR Base: ", &vmread(guest::IDTR_BASE))
            .field("Guest GDTR Limit: ", &vmread(guest::GDTR_LIMIT))
            .field("Guest IDTR Limit: ", &vmread(guest::IDTR_LIMIT))

            .field("Guest IA32_DEBUGCTL_FULL: ", &vmread(guest::IA32_DEBUGCTL_FULL))
            .field("Guest IA32_SYSENTER_CS: ", &vmread(guest::IA32_SYSENTER_CS))
            .field("Guest IA32_SYSENTER_ESP: ", &vmread(guest::IA32_SYSENTER_ESP))
            .field("Guest IA32_SYSENTER_EIP: ", &vmread(guest::IA32_SYSENTER_EIP))
            .field("Guest VMCS Link Pointer: ", &vmread(guest::LINK_PTR_FULL))

            /* VMCS Host state fields */
            .field("Host CR0: ", &vmread(host::CR0))
            .field("Host CR3: ", &vmread(host::CR3))
            .field("Host CR4: ", &vmread(host::CR4))
            .field("Host RSP: ", &vmread(host::RSP))
            .field("Host RIP: ", &vmread(host::RIP))
            .field("Host CS Selector: ", &vmread(host::CS_SELECTOR))
            .field("Host SS Selector: ", &vmread(host::SS_SELECTOR))
            .field("Host DS Selector: ", &vmread(host::DS_SELECTOR))
            .field("Host ES Selector: ", &vmread(host::ES_SELECTOR))
            .field("Host FS Selector: ", &vmread(host::FS_SELECTOR))
            .field("Host GS Selector: ", &vmread(host::GS_SELECTOR))
            .field("Host TR Selector: ", &vmread(host::TR_SELECTOR))
            .field("Host FS Base: ", &vmread(host::FS_BASE))
            .field("Host GS Base: ", &vmread(host::GS_BASE))
            .field("Host TR Base: ", &vmread(host::TR_BASE))
            .field("Host GDTR Base: ", &vmread(host::GDTR_BASE))
            .field("Host IDTR Base: ", &vmread(host::IDTR_BASE))
            .field("Host IA32_SYSENTER_CS: ", &vmread(host::IA32_SYSENTER_CS))
            .field("Host IA32_SYSENTER_ESP: ", &vmread(host::IA32_SYSENTER_ESP))
            .field("Host IA32_SYSENTER_EIP: ", &vmread(host::IA32_SYSENTER_EIP))

            /* VMCS Control fields */
            .field("Primary Proc Based Execution Controls: ", &vmread(control::PRIMARY_PROCBASED_EXEC_CONTROLS))
            .field("Secondary Proc Based Execution Controls: ", &vmread(control::SECONDARY_PROCBASED_EXEC_CONTROLS))
            .field("VM Entry Controls: ", &vmread(control::VMENTRY_CONTROLS))
            .field("VM Exit Controls: ", &vmread(control::VMEXIT_CONTROLS))
            .field("Pin Based Execution Controls: ", &vmread(control::PINBASED_EXEC_CONTROLS))
            .field("CR0 Read Shadow: ", &vmread(control::CR0_READ_SHADOW))
            .field("CR4 Read Shadow: ", &vmread(control::CR4_READ_SHADOW))
            .field("MSR Bitmaps Address: ", &vmread(control::MSR_BITMAPS_ADDR_FULL))
            .finish_non_exhaustive()
    }
}
