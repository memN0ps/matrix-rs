#![no_std]

/* Add a panic handler in lib.rs */
#[cfg(not(test))]
extern crate wdk_panic;

/* Add a global allocator in lib.rs */
#[cfg(not(test))]
use wdk_alloc::WDKAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WDKAllocator = WDKAllocator;

use hypervisor::{println, Hypervisor};
use wdk_sys::{DRIVER_OBJECT, NTSTATUS, PCUNICODE_STRING, STATUS_SUCCESS, STATUS_UNSUCCESSFUL};

//static mut HYPERVISOR: Option<Hypervisor> = None;

/* WDF expects a symbol with the name DriverEntry */
#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    /* Post-vmlaunch, the kernel logger triggers erratic crashes, consuming significant debug time. Transitioning to a serial port logger for writing to the host OS via VMware Workstation. */

    println!("Driver Entry called");

    driver.DriverUnload = Some(driver_unload);

    let Ok(mut hypervisor) = Hypervisor::new() else {
        println!("Failed to build hypervisor");
        return STATUS_UNSUCCESSFUL;
    };

    match hypervisor.virtualize_system() {
        Ok(_) => println!("Successfully virtualized system!"),
        Err(err) => {
            println!("Failed to virtualize system: {}", err);
            return STATUS_UNSUCCESSFUL;
        }
    }

    STATUS_SUCCESS
}

pub extern "C" fn driver_unload(_driver: *mut DRIVER_OBJECT) {
    println!("Driver unloaded successfully!");
    /*
    if let Some(mut hypervisor) = unsafe { HYPERVISOR.take() } {

        match hypervisor.devirtualize() {
            Ok(_) => println!("Devirtualized successfully!"),
            Err(err) => println!("Failed to dervirtualize {}", err),
        }

    }
    */
}
