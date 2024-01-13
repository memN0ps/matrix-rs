//! This module provides utilities and structures to manage the MSR Bitmap in VMX.
//! The MSR Bitmap is used to control the behavior of RDMSR and WRMSR instructions
//! in a virtualized environment.

use {
    crate::utils::alloc::PhysicalAllocator,
    alloc::boxed::Box,
    core::mem::MaybeUninit,
    wdk_sys::{
        ntddk::{RtlClearAllBits, RtlInitializeBitMap},
        RTL_BITMAP,
    },
};

/// Represents the MSR Bitmap structure used in VMX.
///
/// In processors that support the 1-setting of the “use MSR bitmaps” VM-execution control,
/// the VM-execution control fields include the 64-bit physical address of four contiguous
/// MSR bitmaps, which are each 1-KByte in size.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.6.9 MSR-Bitmap Address
#[repr(C, align(4096))]
pub struct MsrBitmap {
    /// Read bitmap for low MSRs. Contains one bit for each MSR address in the range 00000000H to 00001FFFH.
    /// Determines whether an execution of RDMSR applied to that MSR causes a VM exit.
    pub read_low_msrs: [u8; 0x400],

    /// Read bitmap for high MSRs. Contains one bit for each MSR address in the range C0000000H to C0001FFFH.
    /// Determines whether an execution of RDMSR applied to that MSR causes a VM exit.
    pub read_high_msrs: [u8; 0x400],

    /// Write bitmap for low MSRs. Contains one bit for each MSR address in the range 00000000H to 00001FFFH.
    /// Determines whether an execution of WRMSR applied to that MSR causes a VM exit.
    pub write_low_msrs: [u8; 0x400],

    /// Write bitmap for high MSRs. Contains one bit for each MSR address in the range C0000000H to C0001FFFH.
    /// Determines whether an execution of WRMSR applied to that MSR causes a VM exit.
    pub write_high_msrs: [u8; 0x400],
}

impl MsrBitmap {
    /// Sets up the MSR Bitmap.
    ///
    /// # Returns
    /// * A `Result` indicating the success or failure of the setup process.
    pub fn new() -> Box<MsrBitmap, PhysicalAllocator> {
        log::info!("Setting up MSR Bitmap");

        let instance = Self {
            read_low_msrs: [0; 0x400],
            read_high_msrs: [0; 0x400],
            write_low_msrs: [0; 0x400],
            write_high_msrs: [0; 0x400],
        };
        let mut instance = Box::<Self, PhysicalAllocator>::new_in(instance, PhysicalAllocator);

        log::info!("Initializing MSR Bitmap");

        Self::initialize_bitmap(instance.as_mut() as *mut _ as _);

        log::info!("MSR Bitmap setup successful!");

        instance
    }

    /// Initializes the MSR Bitmap.
    ///
    /// # Arguments
    /// * `bitmap_ptr` - The virtual address of the MSR Bitmap.
    fn initialize_bitmap(bitmap_ptr: *mut u64) {
        let mut bitmap_header: MaybeUninit<RTL_BITMAP> = MaybeUninit::uninit();
        let bitmap_header_ptr = bitmap_header.as_mut_ptr() as *mut _;

        unsafe {
            RtlInitializeBitMap(
                bitmap_header_ptr as _,
                bitmap_ptr as _,
                core::mem::size_of::<Self>() as u32,
            )
        }
        unsafe { RtlClearAllBits(bitmap_header_ptr as _) }
    }
}
