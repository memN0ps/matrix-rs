use alloc::boxed::Box;
use kernel_alloc::KernelAlloc;

use crate::error::HypervisorError;

pub const KERNEL_STACK_SIZE: usize = 0x6000;
pub const STACK_CONTENTS_SIZE: usize = KERNEL_STACK_SIZE - (core::mem::size_of::<*mut u64>() * 2); // 0x6000 - 16 bytes for alignment/padding

#[repr(C, align(4096))]
pub struct Host {
    pub stack_contents: [u8; STACK_CONTENTS_SIZE],
    // To keep Host Rsp 16 bytes aligned
    pub padding_1: u64,
    pub reserved_1: u64,
}

impl Host {
    pub fn new() -> Result<Box<Self, KernelAlloc>, HypervisorError> {
        let host_rsp: Box<Host, KernelAlloc> =
            unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };

        Ok(host_rsp)
    }
}
