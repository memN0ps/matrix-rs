extern crate alloc;
use alloc::boxed::Box;
use kernel_alloc::PhysicalAllocator;

use crate::vmcs::{Vmxon, Vmcs};

pub struct Vcpu {
    /// The VMXON region
    pub vmxon: Box<Vmxon, PhysicalAllocator>,

    /// The physical address of the vmxon naturally aligned 4-KByte region of memory
    pub vmxon_physical_address: u64,

    /// The VMCS region
    pub vmcs: Box<Vmcs, PhysicalAllocator>,

    /// The physical address of the vmcs naturally aligned 4-KByte region of memory
    pub vmcs_physical_address: u64,

    /// The index of the processor.
    pub index: u32,
}

impl Vcpu {
    pub fn new(index: u32) -> Self {
        Self {
            vmxon: unsafe { Box::try_new_zeroed_in(PhysicalAllocator).expect("Failed to allocate VMXON Region").assume_init() },
            vmxon_physical_address: 0,
            vmcs: unsafe { Box::try_new_zeroed_in(PhysicalAllocator).expect("Failed to allocate VMCS Region").assume_init() },
            vmcs_physical_address: 0,
            index,
        }
    }
}