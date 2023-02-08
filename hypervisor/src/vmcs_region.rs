const VMCS_RESERVED_SIZE: usize = 0x1000;

#[repr(C, align(4096))]
pub struct VmcsRegion {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub reserved: [u8; VMCS_RESERVED_SIZE - 8],
}