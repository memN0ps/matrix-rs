//! This module provides a safe wrapper around the system's memory validation function, typically named `MmIsAddressValid`.
//! It allows checking the validity of addresses in a way that integrates with a system's memory management routines.
//! The implementation uses a global atomic pointer to hold and replace the original system function with a custom hook,
//! ensuring that any calls to check memory validity are routed through this custom implementation.
//! Credits to Matthias: https://github.com/not-matthias/amd_hypervisor/blob/main/driver/src/hook.rs

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use core::{
    mem, ptr,
    sync::atomic::{AtomicPtr, Ordering},
};
use wdk_sys::{
    ACCESS_MASK, NTSTATUS, PHANDLE, PIO_STATUS_BLOCK, PLARGE_INTEGER, POBJECT_ATTRIBUTES, PVOID,
    ULONG,
};

// Extern block for interfacing with LLVM intrinsic for getting the return address.
extern "C" {
    // Links to the LLVM intrinsic to get the address of the return address.
    #[link_name = "llvm.addressofreturnaddress"]
    fn return_address() -> *const u64;
}

/// A global atomic pointer to hold the original `mm_is_address_valid` function.
/// It's initialized to a null mutable pointer and will be set during runtime to the actual function.
pub static MM_IS_ADDRESS_VALID_ORIGINAL: AtomicPtr<u64> = AtomicPtr::new(ptr::null_mut());

/// The type of the `MmIsAddressValid` function.
type MmIsAddressValidType = extern "C" fn(VirtualAddress: PVOID) -> bool;

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
pub extern "C" fn mm_is_address_valid(virtual_address: u64) -> bool {
    // Log the address from which `MmIsAddressValid` was called.
    log::trace!("MmIsAddressValid called from {:#x}", unsafe {
        return_address().read_volatile() // Reads the return address in a volatile manner to prevent optimizations.
    });

    log::debug!("First Parameter Value: {:x}", virtual_address);

    // Load the original function pointer from the global atomic pointer.
    let fn_ptr = MM_IS_ADDRESS_VALID_ORIGINAL.load(Ordering::Relaxed); // Using relaxed ordering for atomic loading.

    // Transmute the function pointer to the expected function type.
    let fn_ptr = unsafe { mem::transmute::<_, MmIsAddressValidType>(fn_ptr) };

    // Call the original `MmIsAddressValid` function with the provided pointer.
    fn_ptr(virtual_address as _)
}

/// A global atomic pointer to hold the original `nt_create_file` function.
/// It's initialized to a null mutable pointer and will be set during runtime to the actual function.
pub static NT_CREATE_FILE_ORIGINAL: AtomicPtr<u64> = AtomicPtr::new(ptr::null_mut());

type NtCreateFileType = extern "C" fn(
    FileHandle: PHANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    IoStatusBlock: PIO_STATUS_BLOCK,
    AllocationSize: PLARGE_INTEGER,
    FileAttributes: ULONG,
    ShareAccess: ULONG,
    CreateDisposition: ULONG,
    CreateOptions: ULONG,
    EaBuffer: PVOID,
    EaLength: ULONG,
) -> NTSTATUS;

pub extern "C" fn nt_create_file(
    file_handle: PHANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: POBJECT_ATTRIBUTES,
    io_status_block: PIO_STATUS_BLOCK,
    allocation_size: PLARGE_INTEGER,
    file_attributes: ULONG,
    share_access: ULONG,
    create_disposition: ULONG,
    create_options: ULONG,
    ea_buffer: PVOID,
    ea_length: ULONG,
) -> NTSTATUS {
    log::debug!("NtCreateFile called from {:#x}", unsafe {
        return_address().read_volatile() // Reads the return address in a volatile manner to prevent optimizations.
    });

    log::debug!("First Parameter Value: {:x}", file_handle as u64);

    // Load the original function pointer from the global atomic pointer.
    let fn_ptr = NT_CREATE_FILE_ORIGINAL.load(Ordering::Relaxed); // Using relaxed ordering for atomic loading.

    // Transmute the function pointer to the expected function type.
    let fn_ptr = unsafe { mem::transmute::<_, NtCreateFileType>(fn_ptr) };

    // Call the original `NtCreateFile` function with the provided pointer.
    fn_ptr(
        file_handle,
        desired_access,
        object_attributes,
        io_status_block,
        allocation_size,
        file_attributes,
        share_access,
        create_disposition,
        create_options,
        ea_buffer,
        ea_length,
    )
}
