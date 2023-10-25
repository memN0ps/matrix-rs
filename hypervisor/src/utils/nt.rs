#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use {
    alloc::vec::Vec,
    wdk_sys::{
        ntddk::KeLowerIrql, ntddk::MmGetSystemRoutineAddress, KIRQL, NTSTATUS, PVOID,
        UNICODE_STRING,
    },
};

// See: https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2#bug-check-codes
pub const MANUALLY_INITIATED_CRASH: u32 = 0x000000E2;

/// Passive release level
pub const PASSIVE_LEVEL: KIRQL = 0;
/// Lowest interrupt level
pub const LOW_LEVEL: KIRQL = 0;
/// APC interrupt level
pub const APC_LEVEL: KIRQL = 1;
/// Dispatcher level
pub const DISPATCH_LEVEL: KIRQL = 2;
/// CMCI interrupt level
pub const CMCI_LEVEL: KIRQL = 5;

/// Interval clock level
pub const CLOCK_LEVEL: KIRQL = 13;
/// Interprocessor interrupt level
pub const IPI_LEVEL: KIRQL = 14;
/// Deferred Recovery Service level
pub const DRS_LEVEL: KIRQL = 14;
/// Power failure level
pub const POWER_LEVEL: KIRQL = 14;
/// Timer used for profiling.
pub const PROFILING_LEVEL: KIRQL = 15;
/// Highest interrupt level
pub const HIGH_LEVEL: KIRQL = 15;

#[repr(C)]
pub struct RTL_BITMAP {
    pub(crate) SizeOfBitMap: u32,
    pub(crate) Buffer: *mut u32,
}

pub type PRTL_BITMAP = *mut RTL_BITMAP;

/// Gets ta pointer to a function from ntoskrnl exports
fn get_ntoskrnl_export(function_name: *mut UNICODE_STRING) -> PVOID {
    // The MmGetSystemRoutineAddress routine returns a pointer to a function specified by SystemRoutineName.
    unsafe { MmGetSystemRoutineAddress(function_name) }
}

/// Raises the current IRQL to DISPATCH_LEVEL and returns the previous IRQL.
pub fn KeRaiseIrqlToDpcLevel() -> KIRQL {
    type FnKeRaiseIrqlToDpcLevel = unsafe extern "system" fn() -> KIRQL;

    // Include the null terminator for the C-style API
    let wide_string: Vec<u16> = "KeRaiseIrqlToDpcLevel\0".encode_utf16().collect();

    let mut unicode_string = UNICODE_STRING {
        // Length in bytes, excluding the null terminator
        Length: ((wide_string.len() - 1) * 2) as u16,
        MaximumLength: (wide_string.len() * 2) as u16,
        Buffer: wide_string.as_ptr() as *mut _,
    };

    // Get the address of the function from ntoskrnl
    let routine_address = get_ntoskrnl_export(&mut unicode_string);

    let pKeRaiseIrqlToDpcLevel =
        unsafe { core::mem::transmute::<PVOID, FnKeRaiseIrqlToDpcLevel>(routine_address) };

    // Ensure the wide_string doesn't get dropped while the UNICODE_STRING is in use
    core::mem::forget(wide_string);

    // Invoke the retrieved function
    unsafe { pKeRaiseIrqlToDpcLevel() }
}

/// Lowers the current IRQL to the specified value.
pub fn KeLowerIrqlToOldLevel(old_irql: KIRQL) {
    unsafe { KeLowerIrql(old_irql) };
}

#[link(name = "ntoskrnl")]
extern "system" {
    ///undocumented
    pub fn ZwYieldExecution() -> NTSTATUS;
}
