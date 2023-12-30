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

use alloc::boxed::Box;
use alloc::vec;
use core::sync::atomic::Ordering;
use {
    hypervisor::{
        intel::ept::{
            access::AccessType,
            hooks::{Hook, HookManager, HookType},
            paging::Ept,
        },
        utils::alloc::PhysicalAllocator,
        Hypervisor,
    },
    log::LevelFilter,
    log::{self},
    wdk_sys::{DRIVER_OBJECT, NTSTATUS, PUNICODE_STRING, STATUS_SUCCESS, STATUS_UNSUCCESSFUL},
};

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
        drop(hypervisor);
    }
}

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
fn virtualize() -> Option<()> {
    // Initialize the hook and hook manager
    //
    let hook = Hook::hook_function("MmIsAddressValid", hook::mm_is_address_valid as *const ())?;
    if let HookType::Function { ref inline_hook } = hook.hook_type {
        hook::ORIGINAL.store(inline_hook.trampoline_address(), Ordering::Relaxed);
    }
    let hook_manager = HookManager::new(vec![hook]);

    // Setup the extended page tables. Because we also have hooks, we need to change
    // the permissions of the page tables accordingly. This will be done by the
    // `HookManager`.
    //
    let mut primary_ept: Box<Ept, PhysicalAllocator> = unsafe {
        Box::try_new_zeroed_in(PhysicalAllocator)
            .expect("failed to allocate primary ept")
            .assume_init()
    };
    let mut secondary_ept: Box<Ept, PhysicalAllocator> = unsafe {
        Box::try_new_zeroed_in(PhysicalAllocator)
            .expect("failed to allocate secondary ept")
            .assume_init()
    };

    log::info!("Setting Primary EPTs");
    primary_ept.identity_4kb(AccessType::ReadWriteExecute);

    log::info!("Setting Secondary EPTs");
    secondary_ept.identity_4kb(AccessType::ReadWrite);

    let primary_eptp = match primary_ept.create_eptp_with_wb_and_4lvl_walk() {
        Ok(eptp) => eptp,
        Err(err) => {
            log::info!("Failed to create primary EPTP: {}", err);
            return None;
        }
    };

    let secondary_eptp = match secondary_ept.create_eptp_with_wb_and_4lvl_walk() {
        Ok(eptp) => eptp,
        Err(err) => {
            log::info!("Failed to create secondary EPTP: {}", err);
            return None;
        }
    };

    hook_manager.enable_hooks(&mut primary_ept, &mut secondary_ept);

    unsafe { HOOK_MANAGER = Some(hook_manager) };

    let mut hypervisor = match Hypervisor::new(primary_eptp, secondary_eptp) {
        Ok(hypervisor) => hypervisor,
        Err(err) => {
            log::info!("Failed to initialize hypervisor: {}", err);
            return None;
        }
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
