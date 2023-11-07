//! Provides virtual machine management capabilities, specifically for handling MSR
//! read and write operations. It ensures that guest MSR accesses are properly
//! intercepted and handled, with support for injecting faults for unauthorized accesses.

use crate::intel::vmlaunch::GuestRegisters;

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
/// range, a reserved range, or a synthetic MSR range used by Hyper-V.
/// For valid MSRs, the function will either read or write to the MSR based
/// on the access type. For reserved or synthetic MSRs, a general protection
/// fault is injected.
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

    // Hyper-V synthetic MSRs
    const HYPERV_MSR_START: u64 = 0x40000000;
    const HYPERV_MSR_END: u64 = 0x4000FFFF;

    let msr_id = registers.rcx;
    log::info!("MSR ID: {:#x}", msr_id);

    /*
        // If the MSR address falls within a synthetic or reserved range, inject a general protection fault.
        if (msr_id >= HYPERV_MSR_START) && (msr_id <= HYPERV_MSR_END) {
            // Inject general protection fault with an error code.
            // The error code can be zero or you can define a specific one for synthetic MSR access.
            // Injecting #GP causes "Shutdown occurred" for Vmware Workstation (Uncomment later if needed). Hv can be detected if we don't inject #GP.
            EventInjection::vmentry_inject_gp(0);
            return;
        }
    */

    // Determine if the MSR address is in a valid, reserved, or synthetic range.
    // If the MSR address is valid, execute the appropriate read or write operation.
    if (msr_id <= MSR_RANGE_LOW_END)
        || ((msr_id >= MSR_RANGE_HIGH_START) && (msr_id <= MSR_RANGE_HIGH_END))
        || (msr_id >= HYPERV_MSR_START) && (msr_id <= HYPERV_MSR_END)
    {
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
    } else {
        // If the MSR is neither a known valid MSR nor a synthetic MSR, inject a general protection fault.
        // Injecting #GP causes "Shutdown occurred" for Vmware Workstation. Hv can be detected if we don't inject #GP.
        // EventInjection::vmentry_inject_gp(0);
    }
}
