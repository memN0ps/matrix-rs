pub struct Vcpu {
    /// The virtual address of the vmcs naturally aligned 4-KByte region of memory
    pub vmcs_virtual: *mut u64,
    /// The physical address of the vmcs naturally aligned 4-KByte region of memory
    pub vmcs_physical: u64,
    /// The index of the processor.
    pub index: u32,
}

impl Vcpu {
    pub fn new(index: u32) -> Self {
        Self {
            vmcs_virtual: core::ptr::null_mut(),
            vmcs_physical: 0,
            index,
        }
    }
}