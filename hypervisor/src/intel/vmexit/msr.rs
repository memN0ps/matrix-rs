use crate::intel::{events::EventInjection, vmlaunch::GuestRegisters};

/// Enum representing the type of MSR access.
///
/// There are two types of MSR access: reading from an MSR and writing to an MSR.
pub enum MsrAccessType {
    Read,
    Write,
}

/// Handles MSR access based on the provided access type.
///
/// This function checks if the requested MSR address is within a valid
/// range or a reserved range. For valid MSRs, the function will either
/// read or write to the MSR based on the access type. For reserved MSRs,
/// a general protection fault is injected.
///
/// # Arguments
///
/// * `registers` - A mutable reference to the guest's current register state.
/// * `access_type` - The type of MSR access (read or write).
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: RDMSR—Read From Model Specific Register or WRMSR—Write to Model Specific Register
/// and Table C-1. Basic Exit Reasons 31 and 32.
pub fn handle_msr_access(registers: &mut GuestRegisters, access_type: MsrAccessType) {
    /// Constants related to MSR addresses and ranges.
    const MSR_MASK_LOW: u64 = u32::MAX as u64;
    const MSR_RANGE_LOW_END: u64 = 0x00001FFF;
    const MSR_RANGE_HIGH_START: u64 = 0xC0000000;
    const MSR_RANGE_HIGH_END: u64 = 0xC0001FFF;
    const RESERVED_MSR_RANGE_LOW: u64 = 0x40000000;
    const RESERVED_MSR_RANGE_HI: u64 = 0x400000FF;

    let msr_id = registers.rcx;

    // Determine if the MSR address is in a valid or reserved range.
    let is_valid_msr = (msr_id <= MSR_RANGE_LOW_END)
        || ((msr_id >= MSR_RANGE_HIGH_START) && (msr_id <= MSR_RANGE_HIGH_END));

    let is_reserved_msr = (msr_id >= RESERVED_MSR_RANGE_LOW) && (msr_id <= RESERVED_MSR_RANGE_HI);

    // If the MSR address falls within a reserved range, inject a general protection fault.
    if is_reserved_msr {
        EventInjection::vmentry_inject_gp(0);
        return;
    }

    // If the MSR address is valid, execute the appropriate read or write operation.
    if is_valid_msr {
        match access_type {
            MsrAccessType::Read => {
                let msr_value = unsafe { x86::msr::rdmsr(msr_id as _) };
                registers.rdx = msr_value >> 32;
                registers.rax = msr_value & MSR_MASK_LOW;
            }
            MsrAccessType::Write => {
                let msr_value = (registers.rdx << 32) | (registers.rax & MSR_MASK_LOW);
                unsafe { x86::msr::wrmsr(msr_id as _, msr_value) };
            }
        }
    }
    // Note: Optionally, you can handle the case where the MSR is neither valid nor reserved.
}
