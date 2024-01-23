//! This module provides a safe wrapper around the system's memory validation function, typically named `MmIsAddressValid`.
//! It allows checking the validity of addresses in a way that integrates with a system's memory management routines.
//! The implementation uses a global atomic pointer to hold and replace the original system function with a custom hook,
//! ensuring that any calls to check memory validity are routed through this custom implementation.
//! Credits to Matthias: https://github.com/not-matthias/amd_hypervisor/blob/main/driver/src/hook.rs

use core::{
    mem, ptr,
    sync::atomic::{AtomicPtr, Ordering},
};

// Extern block for interfacing with LLVM intrinsic for getting the return address.
extern "C" {
    // Links to the LLVM intrinsic to get the address of the return address.
    #[link_name = "llvm.addressofreturnaddress"]
    fn return_address() -> *const u64;
}

/// A global atomic pointer to hold the original `mm_is_address_valid` function.
/// It's initialized to a null mutable pointer and will be set during runtime to the actual function.
pub static ORIGINAL: AtomicPtr<u64> = AtomicPtr::new(ptr::null_mut());

/// The type of the `MmIsAddressValid` function.
type MmIsAddressValidType = extern "C" fn(u64) -> bool;

/// A safe wrapper around the `MmIsAddressValid` function.
///
/// ## Parameters
/// - `ptr`: The pointer to check for validity.
///
/// ## Returns
/// Returns `true` if the address is valid, `false` otherwise.
///
/// ## Safety
/// This function assumes that the original `MmIsAddressValid` function is correctly set and points to a valid function.
/// The caller must ensure this is the case to avoid undefined behavior.
pub extern "C" fn mm_is_address_valid(ptr: u64) -> bool {
    // Log the address from which `MmIsAddressValid` was called.
    log::info!("MmIsAddressValid called from {:#x}", unsafe {
        return_address().read_volatile() // Reads the return address in a volatile manner to prevent optimizations.
    });

    // Load the original function pointer from the global atomic pointer.
    let fn_ptr = ORIGINAL.load(Ordering::Relaxed); // Using relaxed ordering for atomic loading.
                                                   // Transmute the function pointer to the expected function type.
    let fn_ptr = unsafe { mem::transmute::<_, MmIsAddressValidType>(fn_ptr) };

    // Call the original `MmIsAddressValid` function with the provided pointer.
    fn_ptr(ptr)
}
