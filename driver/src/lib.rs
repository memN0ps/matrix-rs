#![no_std]
//#![feature(alloc_c_string)]
//#![feature(core_c_str)]

use kernel_log::KernelLogger;
use log::LevelFilter;
use winapi::{km::wdm::{DRIVER_OBJECT, IoDeleteSymbolicLink, IoDeleteDevice, IRP_MJ, PDEVICE_OBJECT, IoCreateDevice, DEVICE_TYPE, IoCreateSymbolicLink, IoGetCurrentIrpStackLocation, IO_PRIORITY::IO_NO_INCREMENT, DEVICE_OBJECT, IRP, IoCompleteRequest}, shared::{ntdef::{UNICODE_STRING, NTSTATUS, NT_SUCCESS, FALSE}, ntstatus::STATUS_SUCCESS}};
use core::{panic::PanicInfo, ptr::null_mut};
use crate::string::create_unicode_string;

mod string;


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
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "system" fn driver_entry(driver: &mut DRIVER_OBJECT, _: &UNICODE_STRING) -> NTSTATUS {
    KernelLogger::init(LevelFilter::Info).expect("Failed to initialize logger");
    log::info!("Driver Entry called");

    driver.DriverUnload = Some(driver_unload);

    driver.MajorFunction[IRP_MJ::CREATE as usize] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ::CLOSE as usize] = Some(dispatch_create_close);
    //driver.MajorFunction[IRP_MJ::DEVICE_CONTROL as usize] = Some(dispatch_device_control);

    let device_name = create_unicode_string(obfstr::wide!("\\Device\\hypervisor\0"));
    let mut device_object: PDEVICE_OBJECT = null_mut();
    let mut status = unsafe { 
        IoCreateDevice(
            driver,
            0,
            &device_name,
            DEVICE_TYPE::FILE_DEVICE_UNKNOWN,
            0,
            FALSE, 
            &mut device_object
        ) 
    };

    if !NT_SUCCESS(status) {
        log::error!("Failed to create device object ({:#x})", status);
        return status;
    }

    let symbolic_link = create_unicode_string(obfstr::wide!("\\??\\hypervisor\0"));
    status = unsafe { IoCreateSymbolicLink(&symbolic_link, &device_name) };

    if !NT_SUCCESS(status) {
        log::error!("Failed to create symbolic link ({:#x})", status);
        return status;
    }

    match hypervisor::init_vmx() {
        Ok(_) => log::info!("[+] VMM initialized"),
        Err(err) => log::error!("[-] VMM initialization failed: {}", err),
    }


    return STATUS_SUCCESS;
}

pub extern "system" fn driver_unload(driver: &mut DRIVER_OBJECT) {
    let symbolic_link = create_unicode_string(obfstr::wide!("\\??\\hypervisor\0"));
    unsafe { IoDeleteSymbolicLink(&symbolic_link) };
    unsafe { IoDeleteDevice(driver.DeviceObject) };

    log::info!("Driver unloaded successfully!");
    
}

pub extern "system" fn dispatch_create_close(_device_object: &mut DEVICE_OBJECT, irp: &mut IRP) -> NTSTATUS {
    let stack = IoGetCurrentIrpStackLocation(irp);
    let code = unsafe { (*stack).MajorFunction };

	if code == IRP_MJ::CREATE as u8 {
		log::info!("IRP_MJ_CREATE called");
	} else {
		log::info!("IRP_MJ_CLOSE called");
	}
	
    irp.IoStatus.Information = 0;
    unsafe { *(irp.IoStatus.__bindgen_anon_1.Status_mut()) = STATUS_SUCCESS };

    unsafe { IoCompleteRequest(irp, IO_NO_INCREMENT) };
    
    return STATUS_SUCCESS;
}