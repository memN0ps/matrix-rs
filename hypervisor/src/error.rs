use thiserror_no_std::Error;

#[derive(Error, Debug)]
pub enum HypervisorError {
    #[error("Intel CPU not found")]
    InvalidCPU,
    #[error("VMX is not supported")]
    VMXUnsupported,
    #[error("VMX locked off in BIOS")]
    VMXBIOSLock,
    #[error("Failed allocate memory via PhysicalAllocator")]
    MemoryAllocationFailed,
    #[error("Failed to convert from virtual address to physical address")]
    VirtualToPhysicalAddressFailed,
    #[error("Failed to execute VMXON")]
    VMXONFailed,
    #[error("Failed to execute VMPTRLD")]
    VMPTRLDFailed,
}