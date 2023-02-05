use crate::utils::nt::RtlCaptureContext;
use core::mem::MaybeUninit;

#[repr(C, align(16))]
pub struct M128A {
    low: u64,
    high: u64,
}

#[repr(C, align(16))]
pub struct XsaveFormat {
    control_word: u16,
    status_word: u16,
    tag_word: u8,
    reserved_1: u8,
    error_opcode: u16,
    error_offset: u32,
    error_selector: u16,
    reserved_2: u16,
    data_offset: u32,
    data_selector: u16,
    reserved_3: u16,
    mx_csr: u32,
    mx_csr_mask: u32,
    float_registers: [u128; 8],
    #[cfg(target_pointer_width = "64")]
    xmm_registers: [u128; 16],
    #[cfg(target_pointer_width = "32")]
    xmm_registers: [u128; 8],
    #[cfg(target_pointer_width = "64")]
    reserved_4: [u8; 96],
    #[cfg(target_pointer_width = "32")]
    reserved_4: [u8; 224],
}
pub type XmmSaveArea = XsaveFormat;

///
/// Context Frame
///
///  This frame has a several purposes: 1) it is used as an argument to
///  NtContinue, 2) it is used to constuct a call frame for APC delivery,
///  and 3) it is used in the user level thread creation routines.
///
///
/// The flags field within this record controls the contents of a CONTEXT
/// record.
///
/// If the context record is used as an input parameter, then for each
/// portion of the context record controlled by a flag whose value is
/// set, it is assumed that that portion of the context record contains
/// valid context. If the context record is being used to modify a threads
/// context, then only that portion of the threads context is modified.
///
/// If the context record is used as an output parameter to capture the
/// context of a thread, then only those portions of the thread's context
/// corresponding to set flags will be returned.
///
/// CONTEXT_CONTROL specifies SegSs, Rsp, SegCs, Rip, and EFlags.
///
/// CONTEXT_INTEGER specifies Rax, Rcx, Rdx, Rbx, Rbp, Rsi, Rdi, and R8-R15.
///
/// CONTEXT_SEGMENTS specifies SegDs, SegEs, SegFs, and SegGs.
///
/// CONTEXT_FLOATING_POINT specifies Xmm0-Xmm15.
///
/// CONTEXT_DEBUG_REGISTERS specifies Dr0-Dr3 and Dr6-Dr7.
///
/// Size: 1232 bytes (confirmed)
#[repr(C, align(16))]
pub struct Context {
    //
    // Register parameter home addresses.
    //
    // N.B. These fields are for convenience - they could be used to extend the
    //      context record in the future.
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    /*
     * Control flags.
     */
    pub context_flags: u32,
    pub mx_csr: u32,
    /*
     * Segment Registers and processor flags.
     */
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub e_flags: u32,
    //
    // Debug registers
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    /*
     * Integer registers.
     */
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /*
     * Program counter.
     */
    pub rip: u64,
    /*
     * Floating point state.
     */
    pub flt_save: XmmSaveArea,
    /*
     * Vector registers.
     */
    pub vector_register: [u128; 26],
    pub vector_control: u64,
    /*
     * Special debug control registers.
     */
    pub debug_control: u64,
    pub last_branch_to_rip: u64,
    pub last_branch_from_rip: u64,
    pub last_exception_to_rip: u64,
    pub last_exception_from_rip: u64,
}

impl Context {
    pub fn capture() -> Self {
        let mut context: MaybeUninit<Context> = MaybeUninit::uninit();

        unsafe { RtlCaptureContext(context.as_mut_ptr() as _) };

        unsafe { context.assume_init() }
    }
}
