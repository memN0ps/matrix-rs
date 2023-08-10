#[repr(C)]
pub struct MsrBitmap {
    /// 0000_0000 to 0000_1FFF
    pub msr_bitmap_0: [u8; 0x800],
    /// C000_0000 to C000_1FFF
    pub msr_bitmap_1: [u8; 0x800],
    /// C001_0000 to C001_1FFF
    pub msr_bitmap_2: [u8; 0x800],
    /// Reserved
    pub msr_bitmap_3: [u8; 0x800],
}
