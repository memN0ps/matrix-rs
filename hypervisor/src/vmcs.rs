
pub const PAGE_SIZE: usize = 0x1000;

#[repr(C)]
pub struct Vmcs {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub data: [u8; PAGE_SIZE - 8],
}

#[repr(C)]
pub struct Vmxon {
    pub revision_id: u32,
    pub data: [u8; PAGE_SIZE - 4],
}