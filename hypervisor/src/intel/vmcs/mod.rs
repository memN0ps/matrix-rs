use crate::{
    error::HypervisorError,
    intel::support::{vmclear, vmptrld},
};
use alloc::boxed::Box;
use bitfield::BitMut;
use kernel_alloc::PhysicalAllocator;

use super::addresses::PhysicalAddress;

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
        log::info!("[*] Setting up VMCS region");

        let mut vmcs_region: Box<Vmcs, PhysicalAllocator> =
            unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };

        let vmcs_region_physical_address =
            PhysicalAddress::pa_from_va(vmcs_region.as_ref() as *const _ as _);

        if vmcs_region_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::info!("[+] VMCS Region Virtual Address: {:p}", vmcs_region);
        log::info!(
            "[+] VMCS Region Physical Addresss: 0x{:x}",
            vmcs_region_physical_address
        );

        vmcs_region.revision_id = Self::get_vmcs_revision_id();
        vmcs_region.as_mut().revision_id.set_bit(31, false);

        log::info!("[+] VMCS successful!");

        // Clear the VMCS region.
        vmclear(vmcs_region_physical_address);
        log::info!("[+] VMCLEAR successful!");

        // Load current VMCS pointer.
        vmptrld(vmcs_region_physical_address);
        log::info!("[+] VMPTRLD successful!");

        Ok(vmcs_region)
    }

    /// Get the Virtual Machine Control Structure revision identifier (VMCS revision ID)
    fn get_vmcs_revision_id() -> u32 {
        unsafe { (x86::msr::rdmsr(x86::msr::IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF }
    }
}
