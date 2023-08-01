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
