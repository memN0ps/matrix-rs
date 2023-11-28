//! A hypervisor kernel driver.
//!
//! This crate provides a basic hypervisor kernel driver. It interfaces with the
//! system to virtualize processors and manage hypervisor-related activities.

#![no_std]
#![allow(unused_mut)]

// Set up a panic handler for non-test configurations.
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
    hypervisor::Hypervisor,
    log::LevelFilter,
    log::{self},
    wdk_sys::{
        DRIVER_OBJECT, NTSTATUS, PUNICODE_STRING, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
    },
};

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
        .filter(LevelFilter::Info)
        .setup();

    log::info!("Driver Entry called");

    // Remove if manually mapping the kernel driver
    driver.DriverUnload = Some(driver_unload);

    if virtualize().is_none() {
        log::error!("Failed to virtualize processors");
        return STATUS_UNSUCCESSFUL;
    }

    STATUS_SUCCESS
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
        core::mem::drop(hypervisor);
    }
}

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
fn virtualize() -> Option<()> {
    let Ok(mut hypervisor) = Hypervisor::new() else {
        log::info!("Failed to build hypervisor");
        return None;
    };

    match hypervisor.virtualize_system() {
        Ok(_) => log::info!("Successfully virtualized system!"),
        Err(err) => {
            log::info!("Failed to virtualize system: {}", err);
            return None;
        }
    }

    unsafe { HYPERVISOR = Some(hypervisor) };

    Some(())
}
