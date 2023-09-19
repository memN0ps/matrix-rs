use crate::x86_64::intel::{support::vmread, vmerror::VmInstructionError};

use super::vmexit::VmExit;

/// The collection of XMM register values.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Xmm {
    value: [u8; 16],
}

/// The collection of the guest general purpose register values.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct GuestRegisters {
    pub xmm: [Xmm; 6],
    pub alignment: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
}

extern "C" {
    /// Run the VM until the VM-exit occurs.
    pub fn launch_vm() -> !;
    pub fn vmexit_stub();
}

// Inline assembly for VM operations
core::arch::global_asm!(
    r#"
    .global launch_vm
    launch_vm:
        // Save general purpose registers onto stack
        push    rax
        push    rcx
        push    rdx
        push    rbx
        push    rbp
        push    rsi
        push    rdi
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15

        // Launch the VM until a VM-exit occurs
        vmlaunch

        // If vmlaunch fails, call the error handler
        call    vmlaunch_failed

    .global vmexit_stub
    vmexit_stub:
        // Ensure stack alignment
        sub    rsp, 8

        // Save general purpose registers
        push    rax
        push    rcx
        push    rdx
        push    rbx
        push    rbp
        push    rsi
        push    rdi
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15

        // Save xmm registers
        sub     rsp,   0x70  // Increased this for more space
        movaps  xmmword ptr [rsp +  0x00], xmm0
        movaps  xmmword ptr [rsp + 0x10], xmm1
        movaps  xmmword ptr [rsp + 0x20], xmm2
        movaps  xmmword ptr [rsp + 0x30], xmm3
        movaps  xmmword ptr [rsp + 0x40], xmm4
        movaps  xmmword ptr [rsp + 0x50], xmm5

        // Call vmexit_handler
        call    vmexit_handler

        // Restore xmm registers
        movaps  xmm0, xmmword ptr [rsp +  0x00]
        movaps  xmm1, xmmword ptr [rsp + 0x10]
        movaps  xmm2, xmmword ptr [rsp + 0x20]
        movaps  xmm3, xmmword ptr [rsp + 0x30]
        movaps  xmm4, xmmword ptr [rsp + 0x40]
        movaps  xmm5, xmmword ptr [rsp + 0x50]
        add     rsp, 0x70  // Match the increased space

        // Restore general purpose registers
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

        // Restore the stack alignment
        add    rsp, 8

        // Resume VM
        vmresume

        // If vmresume fails, call the error handler
        call vmresume_failed
    "#
);

/// The first parameter is a pointer to GuestRegisters that were just saved on the stack in reverse order.
/// Reverse order because when you push something on stack the last thing you push will be at the top of the stack
#[no_mangle]
pub unsafe extern "C" fn vmexit_handler(registers: *mut GuestRegisters) {
    // Ensure the pointer is not null before dereferencing.
    if registers.is_null() {
        panic!("vmexit_handler received a null pointer for registers.");
    }

    // Safely dereference the pointer to access the registers.
    let registers = &mut *registers;

    let vmexit = VmExit::new();

    // Handle the VM exit.
    if let Err(e) = vmexit.handle_vmexit(registers) {
        panic!("Failed to handle VMEXIT: {:?}", e);
    }
}

/// Handles the failure of the VMLAUNCH instruction.
#[no_mangle]
pub extern "C" fn vmlaunch_failed() {
    let instruction_error = vmread(x86::vmx::vmcs::ro::VM_INSTRUCTION_ERROR) as u32;

    let Some(error) = VmInstructionError::from_u32(instruction_error) else {
        panic!("Unknown instruction error: {:#x}", instruction_error);
    };
    panic!("VMLAUNCH instruction error: {}", error);
}

/// Handles the failure of the VMRESUME instruction.
#[no_mangle]
pub extern "C" fn vmresume_failed() {
    let instruction_error = vmread(x86::vmx::vmcs::ro::VM_INSTRUCTION_ERROR) as u32;

    let Some(error) = VmInstructionError::from_u32(instruction_error) else {
        panic!("Unknown instruction error: {:#x}", instruction_error);
    };

    panic!("VMRESUME instruction error: {}", error);
}
