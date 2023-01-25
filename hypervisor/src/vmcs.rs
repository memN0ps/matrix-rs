
pub const PAGE_SIZE: usize = 0x1000;

#[repr(C)]
pub struct Vmcs {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub data: [u8; PAGE_SIZE - 8],
}

impl Vmcs {
    pub fn new() -> Self {
        Self { revision_id: 0, abort_indicator: 0, data: [0; PAGE_SIZE - 8] }
    }
}

#[repr(C)]
pub struct Vmxon {
    pub revision_id: u32,
    pub data: [u8; PAGE_SIZE - 4],
}

impl Vmxon {
    pub fn new() -> Self {
        Self {
            revision_id: 0, data: [0; PAGE_SIZE - 4],
        }
    }
}