use super::vmcs_data::VmcsData;

const VMCS_RESERVED_SIZE: usize = 0x1000 - core::mem::size_of::<VmcsData>() - 8;

#[repr(C, align(4096))]
pub struct VmcsRegion {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub vmcs_data: VmcsData,
    pub reserved: [u8; VMCS_RESERVED_SIZE],
}