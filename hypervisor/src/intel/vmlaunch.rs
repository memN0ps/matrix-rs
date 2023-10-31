//! Assembly routines and external functions for hypervisor operations.
//!
//! This module contains inline assembly for VM operations and the declarations
//! for external C functions related to the hypervisor's VM management.

use crate::intel::{
    support::vmread,
    vmerror::VmInstructionError,
    vmexit::{VmExit, VmExitType},
};

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
// Alignment check
const_assert_eq!(
    core::mem::size_of::<GuestRegisters>(),
    0x80 /* 16 * 0x8 */
);

extern "C" {
    /// Run the VM until the VM-exit occurs.
    ///
    /// This function attempts to launch the VM using the `vmlaunch` instruction.
    /// If the launch fails, it calls the `vmlaunch_failed` function.
    pub fn launch_vm() -> !;

    /// Stub function called upon VM-exit.
    ///
    /// This function is responsible for saving the state of the guest that isn't
    /// automatically saved by the processor, then it calls the Rust VM-exit handler.
    pub fn vmexit_stub();
}

// Inline assembly for VM operations.
core::arch::global_asm!(
    r#"
.macro pushaq
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
.endmacro

.macro popaq
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
.endmacro

.global launch_vm
launch_vm:
    // Attempt to launch the VM.
    vmlaunch
    // If we reach here, vmlaunch failed.
    call     vmlaunch_failed

.global vmexit_stub
vmexit_stub:
    // On VM-exit, save the guest's state that isn't automatically saved by the processor.
    pushaq

    // Set rcx to point to the saved guest registers for the vmexit_handler.
    mov     rcx, rsp

    // Save XMM registers (0-5, extend if needed). Allocate space on the stack.
    sub     rsp, 0x20 + 0x60
    movaps  [rsp + 0x20], xmm0
    movaps  [rsp + 0x20 + 0x10], xmm1
    movaps  [rsp + 0x20 + 0x20], xmm2
    movaps  [rsp + 0x20 + 0x30], xmm3
    movaps  [rsp + 0x20 + 0x40], xmm4
    movaps  [rsp + 0x20 + 0x50], xmm5

    // Call the Rust VM-exit handler.
    call    vmexit_handler

    // Restore the saved guest state and attempt to resume the VM.
    movaps  xmm5, [rsp + 0x20 + 0x50]
    movaps  xmm4, [rsp + 0x20 + 0x40]
    movaps  xmm3, [rsp + 0x20 + 0x30]
    movaps  xmm2, [rsp + 0x20 + 0x20]
    movaps  xmm1, [rsp + 0x20 + 0x10]
    movaps  xmm0, [rsp + 0x20]
    add     rsp, 0x20 + 0x60

    // Check the return value of `vmexit_handler` to see if we have to turn off vmx or not.
    test    al, al

    // Restore the guest's state that isn't automatically restored by the processor.
    popaq

    // If it's non-zero, exit the hypervisor.
    jnz     hypervisor_exit

    // Otherwise, attempt to resume the VM.
    vmresume

    // If vmresume fails, handle the error.
    call    vmresume_failed

hypervisor_exit:
    // Update rcx with a magic value, hinting that the hypervisor needs to be unloaded.
    mov     ecx, 0xDEADBEEF

    // This might fail for now and will need fixing later. We need to do vmxoff here or after returning to the caller?
    int3
"#
);

/// Handles VM exits.
///
/// This function is triggered upon a VM exit event. It determines the cause of the VM exit
/// and performs the necessary actions based on the exit reason.
///
/// # Parameters
///
/// * `registers`: A pointer to `GuestRegisters` that were just saved on the stack in reverse order.
///   The order is reversed because when pushing something onto the stack, the last item pushed
///   will be at the top of the stack.
///
/// # Returns
///
/// Returns a `u8` representation of the `VmExitType`, indicating whether the hypervisor
/// should continue or exit.
#[no_mangle]
pub unsafe extern "C" fn vmexit_handler(registers: *mut GuestRegisters) -> u8 {
    // Ensure the pointer is not null before dereferencing.
    if registers.is_null() {
        // Handle this error
        log::error!("Null Guest Registers pointer passed to vmexit_handler.");
        return VmExitType::ExitHypervisor as u8;
    }

    // Safely dereference the pointer to access the registers.
    let registers = &mut *registers;

    let vmexit = VmExit::new();

    // Handle the VM exit.
    match vmexit.handle_vmexit(registers) {
        Ok(_) => VmExitType::Continue as u8,
        Err(e) => {
            log::error!("Error handling VMEXIT: {:?}", e);
            return VmExitType::ExitHypervisor as u8;
        }
    }
}

/// Handles the failure of the VMLAUNCH instruction.
#[no_mangle]
pub extern "C" fn vmlaunch_failed() {
    let instruction_error = vmread(x86::vmx::vmcs::ro::VM_INSTRUCTION_ERROR) as u32;

    match VmInstructionError::from_u32(instruction_error) {
        Some(error) => {
            log::error!("VMLAUNCH instruction error: {}", error);
            // TODO: Capture additional state here for debugging
        }
        None => log::error!("Unknown instruction error: {:#x}", instruction_error),
    };

    // Transition to a safe state or halt
    panic!("VMLAUNCH failed");
}

/// Handles the failure of the VMRESUME instruction.
#[no_mangle]
pub extern "C" fn vmresume_failed() {
    let instruction_error = vmread(x86::vmx::vmcs::ro::VM_INSTRUCTION_ERROR) as u32;

    match VmInstructionError::from_u32(instruction_error) {
        Some(error) => {
            log::error!("VMRESUME instruction error: {}", error);
            // TODO: Capture additional state here for debugging
        }
        None => log::error!("Unknown instruction error: {:#x}", instruction_error),
    };

    // Transition to a safe state or halt
    panic!("VMRESUME failed");
}
