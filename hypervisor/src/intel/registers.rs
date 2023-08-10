/// The collection of the guest general purpose register values.
#[derive(Debug, Default)]
#[repr(C)]
pub struct GuestRegisters {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
}

/// Save general-purpose registers onto stack.
#[macro_export]
macro_rules! save_general_purpose_registers_to_stack {
    () => {
        "
        push    rax
        push    rcx
        push    rdx
        push    rbx
        push    rsi
        push    rdi
        push    rbp
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15
        "
    };
}

/// Restore general-purpose registers from stack.
#[macro_export]
macro_rules! restore_general_purpose_registers_from_stack {
    () => {
        "
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx
        pop     rdx
        pop     rcx
        pop     rax
        "
    };
}
