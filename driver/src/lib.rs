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

use hypervisor::Hypervisor;
use log::LevelFilter;

use wdk_sys::{DRIVER_OBJECT, NTSTATUS, PCUNICODE_STRING, STATUS_SUCCESS, STATUS_UNSUCCESSFUL};

//static mut HYPERVISOR: Option<Hypervisor> = None;

/* WDF expects a symbol with the name DriverEntry */
#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    /* Upon virtualizing the processors and invoking vmlaunch, the kernel logger introduces unpredictable behavior leading to sporadic crashes. This issue consumed a significant amount of troubleshooting time. */
    //kernel_log::KernelLogger::init(LevelFilter::Info).expect("Failed to initialize logger");

    /* Setup a logger with the default settings. The default settings is COM1 port with level filter Info */
    //com_logger::init();

    /* Use COM2 port with level filter Info */
    com_logger::builder()
        .base(0x2f8)
        .filter(LevelFilter::Info)
        .setup();

    log::info!("Driver Entry called");

    driver.DriverUnload = Some(driver_unload);

    let Ok(mut hypervisor) = Hypervisor::new() else {
        log::error!("Failed to build hypervisor");
        return STATUS_UNSUCCESSFUL;
    };

    match hypervisor.virtualize_system() {
        Ok(_) => log::info!("Successfully virtualized system!"),
        Err(err) => {
            log::error!("Failed to virtualize system: {}", err);
            return STATUS_UNSUCCESSFUL;
        }
    }

    STATUS_SUCCESS
}

pub extern "C" fn driver_unload(_driver: *mut DRIVER_OBJECT) {
    log::info!("Driver unloaded successfully!");
    /*
    if let Some(mut hypervisor) = unsafe { HYPERVISOR.take() } {

        match hypervisor.devirtualize() {
            Ok(_) => log::info!("Devirtualized successfully!"),
            Err(err) => log::error!("Failed to dervirtualize {}", err),
        }

    }
    */
}
