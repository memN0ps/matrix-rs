use crate::save_area::SaveArea;

const VMCS_RESERVED_SIZE: usize = 0x1000 - core::mem::size_of::<SaveArea>();

#[repr(C, align(4096))]
pub struct VmcsRegion {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub save_area: SaveArea,
    pub reserved: [u8; VMCS_RESERVED_SIZE - 8],
}