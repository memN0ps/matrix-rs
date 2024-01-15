//! A hypervisor kernel driver.
//!
//! This crate provides a basic hypervisor kernel driver. It interfaces with the
//! system to virtualize processors and manage hypervisor-related activities.

#![no_std]
#![allow(unused_mut)]
#![feature(allocator_api, new_uninit)]
#![feature(link_llvm_intrinsics)]

// Set up a panic handler for non-test configurations.
extern crate alloc;
#[cfg(not(test))]
extern crate wdk_panic;

/*
// Set up a global allocator for non-test configurations.
#[cfg(not(test))]
use wdk_alloc::WDKAllocator;
*/

#[cfg(not(test))]
#[global_allocator]
static GLOBAL: hypervisor::utils::alloc::KernelAlloc = hypervisor::utils::alloc::KernelAlloc;

use {
    crate::expanded_stack::with_expanded_stack,
    alloc::boxed::Box,
    alloc::vec,
    core::sync::atomic::Ordering,
    hypervisor::{
        error::HypervisorError,
        intel::{
            ept::{
                hooks::{Hook, HookManager, HookType},
                paging::{AccessType, Ept},
            },
            vmm::Hypervisor,
        },
        utils::{alloc::PhysicalAllocator, nt::update_ntoskrnl_cr3},
    },
    log::LevelFilter,
    log::{self},
    wdk_sys::{
        ntddk::MmIsAddressValid, DRIVER_OBJECT, NTSTATUS, PUNICODE_STRING, STATUS_SUCCESS,
        STATUS_UNSUCCESSFUL,
    },
};

pub mod expanded_stack;
pub mod hook;

/// The main entry point for the driver.
///
/// This function is invoked by the system when the driver is loaded. It initializes
/// logging, sets the unload callback, and attempts to virtualize the processors.
///
/// # Parameters
///
/// * `driver`: Reference to the system's DRIVER_OBJECT for this driver.
/// * `_registry_path`: Unused. Path to the driver's registry key.
///
/// # Returns
///
/// * `STATUS_SUCCESS` if the initialization was successful.
/// * `STATUS_UNSUCCESSFUL` if there was an error during initialization.
///
/// Reference: WDF expects a symbol with the name DriverEntry.
#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PUNICODE_STRING,
) -> NTSTATUS {
    // Due to post-vmlaunch issues with the kernel logger, we transition to using a serial port logger.
    // This logger writes to the host OS via VMware Workstation.

    // Initialize the COM2 port logger with level filter set to Info.
    com_logger::builder()
        .base(0x2f8)
        .filter(LevelFilter::Trace)
        .setup();

    log::info!("Driver Entry called");

    // Remove if manually mapping the kernel driver
    driver.DriverUnload = Some(driver_unload);

    with_expanded_stack(|| {
        match virtualize() {
            Ok(_) => log::info!("Virtualization successful!"),
            Err(err) => {
                log::error!("Virtualization failed: {:?}", err);
                return STATUS_UNSUCCESSFUL;
            }
        }

        // Test the hooks
        //
        log::info!("Calling MmIsAddressValid to test EPT hook...");
        unsafe { MmIsAddressValid(0 as _) };

        STATUS_SUCCESS
    })
}

/// The unload callback for the driver.
///
/// This function is invoked by the system just before the driver is unloaded. It
/// handles any necessary cleanup, such as devirtualizing the system.
///
/// # Parameters
///
/// * `_driver`: Pointer to the system's DRIVER_OBJECT for this driver.
///
/// Note: Remove if manually mapping the kernel driver
pub extern "C" fn driver_unload(_driver: *mut DRIVER_OBJECT) {
    log::info!("Driver unloaded successfully!");
    if let Some(mut hypervisor) = unsafe { HYPERVISOR.take() } {
        drop(hypervisor);
    }
}

/// The main hook manager object.
static mut HOOK_MANAGER: Option<HookManager> = None;

/// The main hypervisor object.
///
/// This static mutable option holds the global instance of the hypervisor used by this driver.
static mut HYPERVISOR: Option<Hypervisor> = None;

/// Attempts to virtualize the system.
///
/// This function initializes a new hypervisor and then attempts to virtualize all
/// processors on the system.
///
/// # Returns
///
/// * `Some(())` if the system was successfully virtualized.
/// * `None` if there was an error during virtualization.
fn virtualize() -> Result<(), HypervisorError> {
    // Initialize the hook and hook manager
    //
    let hook = Hook::hook_function("MmIsAddressValid", hook::mm_is_address_valid as *const ())
        .ok_or(HypervisorError::HookError)?;
    if let HookType::Function { ref inline_hook } = hook.hook_type {
        hook::ORIGINAL.store(inline_hook.trampoline_address(), Ordering::Relaxed);
    }
    let hook_manager = HookManager::new(vec![hook]);

    let mut primary_ept: Box<Ept, PhysicalAllocator> =
        unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };
    let mut secondary_ept: Box<Ept, PhysicalAllocator> =
        unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() };

    log::info!("Creating Primary EPT");
    primary_ept.identity_4kb(AccessType::READ_WRITE_EXECUTE)?;

    log::info!("Creating Secondary EPT");
    secondary_ept.identity_4kb(AccessType::READ_WRITE_EXECUTE)?;

    log::info!("Enabling hooks");
    hook_manager.enable_hooks(&mut primary_ept, &mut secondary_ept)?;

    // Save as global to avoid dropping
    unsafe { HOOK_MANAGER = Some(hook_manager) };

    log::info!("Building hypervisor");

    let mut hv = match Hypervisor::builder()
        .primary_ept(primary_ept)
        .secondary_ept(secondary_ept)
        .build()
    {
        Ok(hv) => hv,
        Err(err) => return Err(err),
    };

    // Update NTOSKRNL_CR3 to ensure correct CR3 in case of execution within a user-mode process via DPC.
    update_ntoskrnl_cr3();

    match hv.virtualize_system() {
        Ok(_) => log::info!("Successfully virtualized system!"),
        Err(err) => return Err(err),
    };

    unsafe { HYPERVISOR = Some(hv) };

    Ok(())
}
