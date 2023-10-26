use {
    crate::{error::HypervisorError, println, utils::alloc::PhysicalAllocator},
    alloc::boxed::Box,
};

/// Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.6.9 MSR-Bitmap Address
/// On processors that support the 1-setting of the “use MSR bitmaps” VM-execution control, the VM-execution control
/// fields include the 64-bit physical address of four contiguous MSR bitmaps, which are each 1-KByte in size. This
/// field does not exist on processors that do not support the 1-setting of that control.
/// A logical processor uses these bitmaps if and only if the “use MSR bitmaps” control is 1. If the bitmaps are used, an
/// execution of RDMSR or WRMSR causes a VM exit if the value of RCX is in neither of the ranges covered by the
/// bitmaps or if the appropriate bit in the MSR bitmaps (corresponding to the instruction and the RCX value) is 1.
/// See Section 26.1.3 for details. If the bitmaps are used, their address must be 4-KByte aligned.
///
/// The four bitmaps are:
#[repr(C, align(4096))]
pub struct MsrBitmap {
    /// Read bitmap for low MSRs (located at the MSR-bitmap address). This contains one bit for each MSR address
    /// in the range 00000000H to 00001FFFH. The bit determines whether an execution of RDMSR applied to that
    /// MSR causes a VM exit.
    pub read_low_msrs: [u8; 0x400],

    /// Read bitmap for high MSRs (located at the MSR-bitmap address plus 1024). This contains one bit for each
    /// MSR address in the range C0000000H to C0001FFFH. The bit determines whether an execution of RDMSR
    /// applied to that MSR causes a VM exit.
    pub read_high_msrs: [u8; 0x400],

    /// Write bitmap for low MSRs (located at the MSR-bitmap address plus 2048). This contains one bit for each
    /// MSR address in the range 00000000H to 00001FFFH. The bit determines whether an execution of WRMSR
    /// applied to that MSR causes a VM exit.
    pub write_low_msrs: [u8; 0x400],

    /// Write bitmap for high MSRs (located at the MSR-bitmap address plus 3072). This contains one bit for each
    /// MSR address in the range C0000000H to C0001FFFH. The bit determines whether an execution of WRMSR
    /// applied to that MSR causes a VM exit.
    pub write_high_msrs: [u8; 0x400],
}

impl MsrBitmap {
    pub fn setup(
        msr_bitmap: &mut Box<MsrBitmap, PhysicalAllocator>,
    ) -> Result<(), HypervisorError> {
        println!("Setting up MSR-Bitmap");

        // TODO, if needed

        println!("MSR-Bitmap Virtual Address: {:p}", msr_bitmap);

        println!("MSR-Bitmap successful!");

        Ok(())
    }
}
