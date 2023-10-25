use {
    crate::{
        error::HypervisorError,
        intel::support::{vmclear, vmptrld, vmread},
        println,
        utils::addresses::PhysicalAddress,
    },
    alloc::boxed::Box,
    bitfield::BitMut,
    core::fmt,
    kernel_alloc::PhysicalAllocator,
    x86::vmx::vmcs,
};

pub const PAGE_SIZE: usize = 0x1000;

/// Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.2 FORMAT OF THE VMCS REGION
#[repr(C, align(4096))]
pub struct Vmcs {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub reserved: [u8; PAGE_SIZE - 8],
}

impl Vmcs {
    /// Clear the VMCS region and load the VMCS pointer
    /// # VMCS Region
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.2 FORMAT OF THE VMCS REGION
    pub fn new() -> Result<Box<Self, PhysicalAllocator>, HypervisorError> {
        println!("Setting up VMCS region");

        let mut vmcs_region: Box<Vmcs, PhysicalAllocator> =
            unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };

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

        println!("VMCS successful!");

        // Clear the VMCS region.
        vmclear(vmcs_region_physical_address);
        println!("VMCLEAR successful!");

        // Load current VMCS pointer.
        vmptrld(vmcs_region_physical_address);
        println!("VMPTRLD successful!");

        Ok(vmcs_region)
    }

    /// Get the Virtual Machine Control Structure revision identifier (VMCS revision ID)
    fn get_vmcs_revision_id() -> u32 {
        unsafe { (x86::msr::rdmsr(x86::msr::IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF }
    }
}

/// Dump the VMCS fields
impl fmt::Debug for Vmcs {
    #[rustfmt::skip]
    /// Debug implementation for Vmcs
    fn fmt(&self, format: &mut fmt::Formatter<'_>) -> fmt::Result {

        format.debug_struct("Vmcs")
            .field("Current VMCS: ", &(self as *const _))
            .field("Revision ID: ", &self.revision_id)

            /* VMCS Guest state fields */
            .field("Guest CR0: ", &vmread(vmcs::guest::CR0))
            .field("Guest CR3: ", &vmread(vmcs::guest::CR3))
            .field("Guest CR4: ", &vmread(vmcs::guest::CR4))
            .field("Guest DR7: ", &vmread(vmcs::guest::DR7))
            .field("Guest RSP: ", &vmread(vmcs::guest::RSP))
            .field("Guest RIP: ", &vmread(vmcs::guest::RIP))
            .field("Guest RFLAGS: ", &vmread(vmcs::guest::RFLAGS))

            .field("Guest CS Selector: ", &vmread(vmcs::guest::CS_SELECTOR))
            .field("Guest SS Selector: ", &vmread(vmcs::guest::SS_SELECTOR))
            .field("Guest DS Selector: ", &vmread(vmcs::guest::DS_SELECTOR))
            .field("Guest ES Selector: ", &vmread(vmcs::guest::ES_SELECTOR))
            .field("Guest FS Selector: ", &vmread(vmcs::guest::FS_SELECTOR))
            .field("Guest GS Selector: ", &vmread(vmcs::guest::GS_SELECTOR))
            .field("Guest LDTR Selector: ", &vmread(vmcs::guest::LDTR_SELECTOR))
            .field("Guest TR Selector: ", &vmread(vmcs::guest::TR_SELECTOR))

            .field("Guest CS Base: ", &vmread(vmcs::guest::CS_BASE))
            .field("Guest SS Base: ", &vmread(vmcs::guest::SS_BASE))
            .field("Guest DS Base: ", &vmread(vmcs::guest::DS_BASE))
            .field("Guest ES Base: ", &vmread(vmcs::guest::ES_BASE))
            .field("Guest FS Base: ", &vmread(vmcs::guest::FS_BASE))
            .field("Guest GS Base: ", &vmread(vmcs::guest::GS_BASE))
            .field("Guest LDTR Base: ", &vmread(vmcs::guest::LDTR_BASE))
            .field("Guest TR Base: ", &vmread(vmcs::guest::TR_BASE))

            .field("Guest CS Limit: ", &vmread(vmcs::guest::CS_LIMIT))
            .field("Guest SS Limit: ", &vmread(vmcs::guest::SS_LIMIT))
            .field("Guest DS Limit: ", &vmread(vmcs::guest::DS_LIMIT))
            .field("Guest ES Limit: ", &vmread(vmcs::guest::ES_LIMIT))
            .field("Guest FS Limit: ", &vmread(vmcs::guest::FS_LIMIT))
            .field("Guest GS Limit: ", &vmread(vmcs::guest::GS_LIMIT))
            .field("Guest LDTR Limit: ", &vmread(vmcs::guest::LDTR_LIMIT))
            .field("Guest TR Limit: ", &vmread(vmcs::guest::TR_LIMIT))

            .field("Guest CS Access Rights: ", &vmread(vmcs::guest::CS_ACCESS_RIGHTS))
            .field("Guest SS Access Rights: ", &vmread(vmcs::guest::SS_ACCESS_RIGHTS))
            .field("Guest DS Access Rights: ", &vmread(vmcs::guest::DS_ACCESS_RIGHTS))
            .field("Guest ES Access Rights: ", &vmread(vmcs::guest::ES_ACCESS_RIGHTS))
            .field("Guest FS Access Rights: ", &vmread(vmcs::guest::FS_ACCESS_RIGHTS))
            .field("Guest GS Access Rights: ", &vmread(vmcs::guest::GS_ACCESS_RIGHTS))
            .field("Guest LDTR Access Rights: ", &vmread(vmcs::guest::LDTR_ACCESS_RIGHTS))
            .field("Guest TR Access Rights: ", &vmread(vmcs::guest::TR_ACCESS_RIGHTS))

            .field("Guest GDTR Base: ", &vmread(vmcs::guest::GDTR_BASE))
            .field("Guest IDTR Base: ", &vmread(vmcs::guest::IDTR_BASE))
            .field("Guest GDTR Limit: ", &vmread(vmcs::guest::GDTR_LIMIT))
            .field("Guest IDTR Limit: ", &vmread(vmcs::guest::IDTR_LIMIT))

            .field("Guest IA32_DEBUGCTL_FULL: ", &vmread(vmcs::guest::IA32_DEBUGCTL_FULL))
            .field("Guest IA32_SYSENTER_CS: ", &vmread(vmcs::guest::IA32_SYSENTER_CS))
            .field("Guest IA32_SYSENTER_ESP: ", &vmread(vmcs::guest::IA32_SYSENTER_ESP))
            .field("Guest IA32_SYSENTER_EIP: ", &vmread(vmcs::guest::IA32_SYSENTER_EIP))
            .field("Guest VMCS Link Pointer: ", &vmread(vmcs::guest::LINK_PTR_FULL))

            /* VMCS Host state fields */
            .field("Host CR0: ", &vmread(vmcs::host::CR0))
            .field("Host CR3: ", &vmread(vmcs::host::CR3))
            .field("Host CR4: ", &vmread(vmcs::host::CR4))
            .field("Host RSP: ", &vmread(vmcs::host::RSP))
            .field("Host RIP: ", &vmread(vmcs::host::RIP))
            .field("Host CS Selector: ", &vmread(vmcs::host::CS_SELECTOR))
            .field("Host SS Selector: ", &vmread(vmcs::host::SS_SELECTOR))
            .field("Host DS Selector: ", &vmread(vmcs::host::DS_SELECTOR))
            .field("Host ES Selector: ", &vmread(vmcs::host::ES_SELECTOR))
            .field("Host FS Selector: ", &vmread(vmcs::host::FS_SELECTOR))
            .field("Host GS Selector: ", &vmread(vmcs::host::GS_SELECTOR))
            .field("Host TR Selector: ", &vmread(vmcs::host::TR_SELECTOR))
            .field("Host FS Base: ", &vmread(vmcs::host::FS_BASE))
            .field("Host GS Base: ", &vmread(vmcs::host::GS_BASE))
            .field("Host TR Base: ", &vmread(vmcs::host::TR_BASE))
            .field("Host GDTR Base: ", &vmread(vmcs::host::GDTR_BASE))
            .field("Host IDTR Base: ", &vmread(vmcs::host::IDTR_BASE))
            .field("Host IA32_SYSENTER_CS: ", &vmread(vmcs::host::IA32_SYSENTER_CS))
            .field("Host IA32_SYSENTER_ESP: ", &vmread(vmcs::host::IA32_SYSENTER_ESP))
            .field("Host IA32_SYSENTER_EIP: ", &vmread(vmcs::host::IA32_SYSENTER_EIP))

            /* VMCS Control fields */
            .field("Primary Proc Based Execution Controls: ", &vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS))
            .field("Secondary Proc Based Execution Controls: ", &vmread(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS))
            .field("VM Entry Controls: ", &vmread(vmcs::control::VMENTRY_CONTROLS))
            .field("VM Exit Controls: ", &vmread(vmcs::control::VMEXIT_CONTROLS))
            .field("Pin Based Execution Controls: ", &vmread(vmcs::control::PINBASED_EXEC_CONTROLS))
            .field("CR0 Read Shadow: ", &vmread(vmcs::control::CR0_READ_SHADOW))
            .field("CR4 Read Shadow: ", &vmread(vmcs::control::CR4_READ_SHADOW))
            .field("MSR Bitmaps Address: ", &vmread(vmcs::control::MSR_BITMAPS_ADDR_FULL))
            .finish_non_exhaustive()
    }
}
