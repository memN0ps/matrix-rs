use crate::x86_64::intel::{support::vmread, vmerror::VmInstructionError};

use super::vmexit::VmExit;

/// Guest registers.
#[repr(C)]
pub struct GuestRegisters {
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
    pub rsp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
}
const_assert_eq!(
    core::mem::size_of::<GuestRegisters>(),
    0x80 /* 16 * 0x8 */
);

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
    // The host's state is saved in the VMCS before executing `vmlaunch`.
    // The processor will automatically save and restore the host's state using the VMCS.
    vmlaunch

    // If vmlaunch fails, call the error handler
    call    vmlaunch_failed

.global vmexit_stub
vmexit_stub:
    // On VM-exit, the processor saves some of the guest's state in the VMCS, but not all.
    // Manually save the rest of the guest's state to ensure full restoration on `vmresume`.

    // Save general purpose registers
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    -1      // Dummy for rsp.
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

    // Set rcx to point to the saved guest registers for the vmexit_handler.
    mov     rcx, rsp

    // Allocate stack space and save XMM registers.
    sub     rsp, 0x20 + 0x60
    movaps  [rsp + 0x20], xmm0
    movaps  [rsp + 0x20 + 0x10], xmm1
    movaps  [rsp + 0x20 + 0x20], xmm2
    movaps  [rsp + 0x20 + 0x30], xmm3
    movaps  [rsp + 0x20 + 0x40], xmm4
    movaps  [rsp + 0x20 + 0x50], xmm5

    // Handle the VM-exit event
    call    vmexit_handler

    // Restore XMM registers and adjust the stack pointer
    movaps  xmm5, [rsp + 0x20 + 0x50]
    movaps  xmm4, [rsp + 0x20 + 0x40]
    movaps  xmm3, [rsp + 0x20 + 0x30]
    movaps  xmm2, [rsp + 0x20 + 0x20]
    movaps  xmm1, [rsp + 0x20 + 0x10]
    movaps  xmm0, [rsp + 0x20]
    add     rsp, 0x20 + 0x60

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
    pop     rbx    // Dummy for rsp.
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax

    // Attempt to resume VM execution
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
