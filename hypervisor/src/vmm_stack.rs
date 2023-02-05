use crate::vmm::Vmm;

pub const KERNEL_STACK_SIZE: usize = 0x6000;

#[repr(C, align(4096))]
pub struct VmmStack {
    limit: [u8; KERNEL_STACK_SIZE - core::mem::size_of::<Vmm>()],
    pub vmm_context: Vmm,
}