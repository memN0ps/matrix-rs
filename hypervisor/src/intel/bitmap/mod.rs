use crate::error::HypervisorError;
use alloc::boxed::Box;
use kernel_alloc::KernelAlloc;

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
    pub fn new() -> Result<Box<Self, KernelAlloc>, HypervisorError> {
        let mut msr_bitmap: Box<MsrBitmap, KernelAlloc> =
            unsafe { Box::try_new_zeroed_in(KernelAlloc)?.assume_init() };

        // MSR_READ
        msr_bitmap.mask(0x277, false); // IA32_PAT
        msr_bitmap.mask(0x2FF, false); // IA32_MTRR_DEF_TYPE

        msr_bitmap.mask(0x802, false); // IA32_X2APIC_APICID
        msr_bitmap.mask(0x803, false); // IA32_X2APIC_VERSION
        msr_bitmap.mask(0x808, false); // IA32_X2APIC_TPR
        msr_bitmap.mask(0x80A, false); // IA32_X2APIC_PPR
        msr_bitmap.mask(0x80D, false); // IA32_X2APIC_LDR
        msr_bitmap.mask(0x80F, false); // IA32_X2APIC_SIVR
        msr_bitmap.mask_range(0x810..=0x817, false); // IA32_X2APIC_ISR0..IA32_X2APIC_ISR7
        msr_bitmap.mask_range(0x818..=0x81F, false); // IA32_X2APIC_TMR0..IA32_X2APIC_TMR7
        msr_bitmap.mask_range(0x820..=0x827, false); // IA32_X2APIC_IRR0..IA32_X2APIC_IRR7
        msr_bitmap.mask(0x828, false); // IA32_X2APIC_ESR
        msr_bitmap.mask(0x82F, false); // IA32_X2APIC_LVT_CMCI
        msr_bitmap.mask(0x830, false); // IA32_X2APIC_ICR
        msr_bitmap.mask_range(0x832..=0x837, false); // IA32_X2APIC_LVT_*
        msr_bitmap.mask(0x838, false); // IA32_X2APIC_INIT_COUNT
        msr_bitmap.mask(0x839, false); // IA32_X2APIC_CUR_COUNT
        msr_bitmap.mask(0x83E, false); // IA32_X2APIC_DIV_CONF

        // MSR_WRITE
        msr_bitmap.mask(0x1B, true); // IA32_APIC_BASE
        msr_bitmap.mask_range(0x200..=0x277, true); // IA32_MTRR_*
        msr_bitmap.mask(0x277, true); // IA32_PAT
        msr_bitmap.mask(0x2FF, true); // IA32_MTRR_DEF_TYPE
        msr_bitmap.mask(0x38F, true); // IA32_PERF_GLOBAL_CTRL
        msr_bitmap.mask_range(0xC80..=0xD8F, true);

        msr_bitmap.mask(0x808, true); // IA32_X2APIC_TPR
        msr_bitmap.mask(0x80B, true); // IA32_X2APIC_EOI
        msr_bitmap.mask(0x80F, true); // IA32_X2APIC_SIVR
        msr_bitmap.mask(0x828, true); // IA32_X2APIC_ESR
        msr_bitmap.mask(0x82F, true); // IA32_X2APIC_LVT_CMCI
        msr_bitmap.mask(0x830, true); // IA32_X2APIC_ICR
        msr_bitmap.mask_range(0x832..=0x837, true); // IA32_X2APIC_LVT_*
        msr_bitmap.mask(0x838, true); // IA32_X2APIC_INIT_COUNT
        msr_bitmap.mask(0x839, true); // IA32_X2APIC_CUR_COUNT
        msr_bitmap.mask(0x83E, true); // IA32_X2APIC_DIV_CONF

        Ok(msr_bitmap)
    }

    fn mask_range(&mut self, msr_range: core::ops::RangeInclusive<u32>, is_write: bool) {
        for msr in msr_range {
            self.mask(msr, is_write);
        }
    }

    fn mask(&mut self, msr: u32, is_write: bool) {
        let mut ptr = self.read_low_msrs.as_mut_ptr();
        let msr_low = msr & 0x1fff;
        let msr_byte = (msr_low / 8) as usize;
        let msr_bit = (msr_low % 8) as u8;

        unsafe {
            if msr >= 0xc000_0000 {
                ptr = ptr.add(1 << 10);
            }
            if is_write {
                ptr = ptr.add(2 << 10);
            }
            core::slice::from_raw_parts_mut(ptr, 1024)[msr_byte] &= 1 << msr_bit;
        }
    }
}
