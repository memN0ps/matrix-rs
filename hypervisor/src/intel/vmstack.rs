use {
    crate::{error::HypervisorError, println, utils::alloc::KernelAlloc},
    alloc::boxed::Box,
    core::mem::size_of,
};

pub const KERNEL_STACK_SIZE: usize = 0x6000;
pub const HOST_RSP_RESERVED: usize = size_of::<*mut u64>() * 2;
pub const STACK_CONTENTS_SIZE: usize = KERNEL_STACK_SIZE - HOST_RSP_RESERVED;

#[repr(C, align(4096))]
pub struct VmStack {
    pub stack_contents: [u8; STACK_CONTENTS_SIZE],

    /// Provides a reference to the `Vmx` structure which can be utilized within the VM exit handlers.
    /// By leveraging an offset of `[RSP + 8]`, we can retrieve this "self data" reference during the handler's execution, if required.
    // pub self_data: *mut u64,

    // To keep Host Rsp 16 bytes aligned
    pub padding_1: u64,
    pub reserved_1: u64,
}
const_assert_eq!(size_of::<VmStack>(), KERNEL_STACK_SIZE);

impl VmStack {
    pub fn setup(host_rsp: &mut Box<VmStack, KernelAlloc>) -> Result<(), HypervisorError> {
        println!("Setting up VMCS_HOST_RSP region");

        println!("VMCS_HOST_RSP Virtual Address: {:p}", host_rsp);

        host_rsp.stack_contents = [0u8; STACK_CONTENTS_SIZE];
        host_rsp.reserved_1 = u64::MAX;
        host_rsp.padding_1 = u64::MAX;

        println!("VMCS_HOST_RSP successful!");

        Ok(())
    }
}
