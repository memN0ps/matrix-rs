extern crate alloc;
use alloc::boxed::Box;
use kernel_alloc::PhysicalAllocator;

use crate::{vmcs::{Vmxon, Vmcs}, error::HypervisorError, vmm_stack::VmmStack, msr_bitmap::MsrBitmap};

pub struct Vcpu {
    
    // The VM exit status
    //pub vmexit_status: VmexitStatus

    /// The guest RSP
    pub guest_rsp: u64,

    /// The guest RSP
    pub guest_rip: u64,

    /// The virtual address of the Vmcs naturally aligned 4-KByte region of memory
    pub vmcs: Box<Vmcs, PhysicalAllocator>,

    /// The physical address of the Vmcs naturally aligned 4-KByte region of memory
    pub vmcs_physical_address: u64,

    /// The virtual address of the Vmxon naturally aligned 4-KByte region of memory
    pub vmxon: Box<Vmxon, PhysicalAllocator>,

    /// The physical address of the Vmxon naturally aligned 4-KByte region of memory
    pub vmxon_physical_address: u64,

    /// The VM stack
    pub vmm_stack: Box<VmmStack, PhysicalAllocator>,

    /// The virtual address of the MsrBitmap naturally aligned 4-KByte region of memory
    pub msr_bitmap: Box<MsrBitmap, PhysicalAllocator>,

    /// The physical address of the MsrBitmap naturally aligned 4-KByte region of memory
    pub msr_bitmap_physical_address: u64,
}

impl Vcpu {
    pub fn new() -> Result<Self, HypervisorError> {
        Ok (Self {
            guest_rsp: 0,
            guest_rip: 0,
            vmcs: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            vmcs_physical_address: 0,
            vmxon: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            vmxon_physical_address: 0,
            vmm_stack: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            msr_bitmap: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            msr_bitmap_physical_address: 0,
        })
    }
}