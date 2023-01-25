pub struct Vcpu {
    /// The physical address of the vmxon naturally aligned 4-KByte region of memory
    pub vmxon_physical_address: u64,

    /// The physical address of the vmcs naturally aligned 4-KByte region of memory
    pub vmcs_physical_address: u64,

    /// The index of the processor.
    pub index: u32,
}

impl Vcpu {
    pub fn new(index: u32) -> Self {
        Self {
            vmxon_physical_address: 0,
            vmcs_physical_address: 0,
            index,
        }
    }
}