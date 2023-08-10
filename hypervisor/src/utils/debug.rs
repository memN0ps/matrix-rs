use crate::nt::{KeBugCheck, MANUALLY_INITIATED_CRASH};

/// Breaks if a kernel debugger is present on the system.
pub macro dbg_break() {
    #[allow(unused_unsafe)]
    if unsafe { !*crate::nt::KdDebuggerNotPresent } {
        #[allow(unused_unsafe)]
        unsafe {
            core::arch::asm!("int 3")
        };
    }
}

/// Breaks if a kernel debugger is present on the system and manually crash the system with KeBugCheck (BSOD).
pub fn breakpoint_to_bugcheck() {
    // We should never continue the guest execution here.
    //
    dbg_break!();
    unsafe { KeBugCheck(MANUALLY_INITIATED_CRASH) };
}
