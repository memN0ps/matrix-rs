#![no_std]

use hypervisor::Hypervisor;
use kernel_log::KernelLogger;
use log::LevelFilter;
use winapi::{
    km::wdm::DRIVER_OBJECT,
    shared::{
        ntdef::{NTSTATUS, UNICODE_STRING},
        ntstatus::{STATUS_SUCCESS, STATUS_UNSUCCESSFUL},
    },
};

#[no_mangle]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 {
    unimplemented!()
}

#[global_allocator]
static GLOBAL: kernel_alloc::KernelAlloc = kernel_alloc::KernelAlloc;

#[export_name = "_fltused"]
static _FLTUSED: i32 = 0;

#[allow(unused_imports)]
use core::panic::PanicInfo;
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

//static mut HYPERVISOR: Option<Hypervisor> = None;

#[no_mangle]
pub extern "system" fn driver_entry(driver: &mut DRIVER_OBJECT, _: &UNICODE_STRING) -> NTSTATUS {
    KernelLogger::init(LevelFilter::Info).expect("Failed to initialize logger");
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

pub extern "system" fn driver_unload(_driver: &mut DRIVER_OBJECT) {
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
