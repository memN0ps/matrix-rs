extern crate alloc;
use alloc::boxed::Box;
use kernel_alloc::PhysicalAllocator;

use crate::{vmcs_region::{VmxonRegion, VmcsRegion}, error::HypervisorError, msr_bitmap::MsrBitmap, context::Context, vmm::Vmm};

pub struct Vcpu {
    /// The virtual address of the Vmcs naturally aligned 4-KByte region of memory
    pub vmcs_region: Box<VmcsRegion, PhysicalAllocator>,

    /// The physical address of the Vmcs naturally aligned 4-KByte region of memory
    pub vmcs_region_physical_address: u64,

    /// The virtual address of the Vmxon naturally aligned 4-KByte region of memory
    pub vmxon_region: Box<VmxonRegion, PhysicalAllocator>,

    /// The physical address of the Vmxon naturally aligned 4-KByte region of memory
    pub vmxon_region_physical_address: u64,

    /// The virtual address of the MsrBitmap naturally aligned 4-KByte region of memory
    pub msr_bitmap: Box<MsrBitmap, PhysicalAllocator>,

    /// The physical address of the MsrBitmap naturally aligned 4-KByte region of memory
    pub msr_bitmap_physical_address: u64,

    pub context: Context,

    // The Vmm Stack
    pub vmm_stack: Box<VmmStack, PhysicalAllocator>,

    // The VM exit status
    //pub vmexit_status: VmexitStatus
}


pub const KERNEL_STACK_SIZE: usize = 0x6000;
pub struct VmmStack {
    limit: [u8; KERNEL_STACK_SIZE - core::mem::size_of::<Vmm>()],
    pub vmm_context: Vmm,
}


impl Vcpu {
    pub fn new() -> Result<Self, HypervisorError> {
        Ok (Self {
            vmcs_region: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            vmcs_region_physical_address: 0,
            vmxon_region: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            vmxon_region_physical_address: 0,
            msr_bitmap: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            msr_bitmap_physical_address: 0,
            context: Context::capture(),
            vmm_stack: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
        })
    }
}