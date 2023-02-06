pub const PAGE_SIZE: usize = 0x1000;

#[repr(C, align(4096))]
pub struct VmcsRegion {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub data: [u8; PAGE_SIZE - 8],
}