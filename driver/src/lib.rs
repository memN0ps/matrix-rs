#![no_std]
//#![feature(alloc_c_string)]
//#![feature(core_c_str)]

use hypervisor::{Hypervisor};
use kernel_log::KernelLogger;
use log::LevelFilter;
use core::panic::PanicInfo;
use winapi::{km::wdm::{DRIVER_OBJECT}, shared::{ntdef::{UNICODE_STRING, NTSTATUS}, ntstatus::{STATUS_SUCCESS, STATUS_UNSUCCESSFUL}}};

/// When using the alloc crate it seems like it does some unwinding. Adding this
/// export satisfies the compiler but may introduce undefined behaviour when a
/// panic occurs.
#[no_mangle]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 { unimplemented!() }

#[global_allocator]
static GLOBAL: kernel_alloc::KernelAlloc = kernel_alloc::KernelAlloc;

/// Explanation can be found here: https://github.com/Trantect/win_driver_example/issues/4
#[export_name = "_fltused"]
static _FLTUSED: i32 = 0;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! { loop {} }


static mut HYPERVISOR: Option<Hypervisor> = None;

#[no_mangle]
pub extern "system" fn driver_entry(driver: &mut DRIVER_OBJECT, _: &UNICODE_STRING) -> NTSTATUS {
    KernelLogger::init(LevelFilter::Info).expect("Failed to initialize logger");
    log::info!("Driver Entry called");

    driver.DriverUnload = Some(driver_unload);


    if virtualize().is_none() {
        log::error!("Failed to virtualize processors");
        return STATUS_UNSUCCESSFUL;
    }

    STATUS_SUCCESS
}


pub extern "system" fn driver_unload(_driver: &mut DRIVER_OBJECT) {
    log::info!("Driver unloaded successfully!");
    
    if let Some(mut hypervisor) = unsafe { HYPERVISOR.take() } {
        match hypervisor.devirtualize() {
            Ok(_) => log::info!("[+] Devirtualized successfully!"),
            Err(err) => log::error!("[-] Failed to dervirtualize {}", err),
        }
    }
}

fn virtualize() -> Option<()> {

    let hv = Hypervisor::builder();

    let Ok(mut hypervisor) = hv.build() else {
        log::error!("[-] Failed to build hypervisor");
        return None;
    };

    match hypervisor.virtualize() {
        Ok(_) => log::info!("[+] VMM initialized"),
        Err(err) =>  {
            log::error!("[-] VMM initialization failed: {}", err);
            return None;
        }
    }

    unsafe { HYPERVISOR = Some(hypervisor) }

    Some(())
}