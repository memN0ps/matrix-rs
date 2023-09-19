use {alloc::boxed::Box, kernel_alloc::KernelAlloc};

use crate::error::HypervisorError;

pub const KERNEL_STACK_SIZE: usize = 0x6000;
pub const STACK_CONTENTS_SIZE: usize = KERNEL_STACK_SIZE - (core::mem::size_of::<*mut u64>() * 2); // 0x6000 - 16 bytes for alignment/padding

#[repr(C, align(4096))]
pub struct HostRsp {
    pub stack_contents: [u8; STACK_CONTENTS_SIZE],
    // To keep Host Rsp 16 bytes aligned
    pub padding_1: u64,
    pub reserved_1: u64,
}
const_assert_eq!(core::mem::size_of::<HostRsp>(), KERNEL_STACK_SIZE);
const_assert_eq!(STACK_CONTENTS_SIZE % 16, 0);

impl HostRsp {
    pub fn new() -> Result<Box<Self, KernelAlloc>, HypervisorError> {
        log::info!("Setting up VMCS_HOST_RSP region");
        let host_rsp: Box<HostRsp, KernelAlloc> =
            unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };

        log::info!("VMCS_HOST_RSP Virtual Address: {:p}", host_rsp);

        log::info!("VMCS_HOST_RSP successful!");

        Ok(host_rsp)
    }
}
