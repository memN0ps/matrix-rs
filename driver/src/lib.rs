#![no_std]

use kernel_log::KernelLogger;

#[no_mangle]
pub extern "system" fn DriverEntry() -> u64 {
    KernelLogger::init(LevelFilter::Info).expect("Failed to initialize logger");

    log::warn!("This is an example message.");

    0 /* STATUS_SUCCESS */
}