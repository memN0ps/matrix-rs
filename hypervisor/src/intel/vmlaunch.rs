//! A module for managing Intel VMX-based virtualization.
//!
//! This module provides structures and functions for interacting with Intel's VMX
//! virtualization extensions. It offers abstractions for the guest's register state,
//! VM-entry, VM-exit, and handling VMX-specific instructions.
//!
//! Main components include:
//! - `GeneralPurposeRegisters`: Represents the state of guest registers during a VM exit.
//! - VMX assembly integrations: Assembly routines to interface directly with VMX instructions.
//!
//! The module is designed to be used in conjunction with a broader hypervisor framework.
//! 
//! Credits: Thanks @daaximus (daax) <3

use {
    super::vmexit::VmExit,
    crate::intel::{support::vmread, vmerror::VmInstructionError},
    static_assertions::const_assert_eq,
};

/// Represents the state of guest registers during a VM exit.
///
/// This structure is used to capture the state of all general-purpose registers,
/// of a virtualized guest when a VM exit occurs.
/// It allows the hypervisor to inspect or modify the guest's state as necessary
/// before resuming guest execution.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.4.1 Guest Register State
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GeneralPurposeRegisters {
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
}
// Ensure the size of `GeneralPurposeRegisters` is consistent with expected layout.
const_assert_eq!(
    core::mem::size_of::<GeneralPurposeRegisters>(),
    0x80 /* 16 * 0x8 */
);

extern "C" {
    /// Launches the VM using VMX instructions.
    ///
    /// This function is defined in Assembly and interacts directly with the VMX
    /// instructions `vmlaunch` and `vmresume`. Upon successful execution, this function
    /// does not return, instead transitioning control to the guest VM. On VM-exit,
    /// the function returns, allowing the hypervisor to handle the exit.
    ///
    /// # Arguments
    ///
    /// * `host_rsp` - A pointer to the end of `stack_contents` in the `VmStack` structure.
    pub fn launch_vm(host_rsp: *mut u64);

    /// Assembly stub for handling VM exits.
    pub fn vmexit_stub();
}

// Credits: Thanks @daaximus (daax) <3
core::arch::global_asm!(r#"
// Macro to push all general-purpose registers onto the stack.
.macro save_gpr
    push	r15
    push	r14
    push	r13
    push	r12
    push	r11
    push	r10
    push	r9
    push	r8
    push	rdi
    push	rsi
    push	rbp
    sub		rsp,    0x8 // Substitutes for RSP
    push	rbx
    push	rdx
    push	rcx
    push	rax
.endmacro

// Macro to pop all general-purpose registers off the stack.
.macro restore_gpr
	pop		rax
	pop		rcx
	pop		rdx
	pop		rbx
	add		rsp,    0x8 // Substitutes for RSP
	pop		rbp
	pop		rsi
	pop		rdi
	pop		r8
	pop		r9
	pop		r10
	pop		r11
	pop		r12
	pop		r13
	pop		r14
	pop		r15
.endmacro

.macro save_xmm
    // Allocate stack space for xmm registers.
    sub rsp, 0x100

    // Save xmm registers.
    movaps xmmword ptr [rsp], xmm0
    movaps xmmword ptr [rsp + 0x10], xmm1
    movaps xmmword ptr [rsp + 0x20], xmm2
    movaps xmmword ptr [rsp + 0x30], xmm3
    movaps xmmword ptr [rsp + 0x40], xmm4
    movaps xmmword ptr [rsp + 0x50], xmm5
    movaps xmmword ptr [rsp + 0x60], xmm6
    movaps xmmword ptr [rsp + 0x70], xmm7
    movaps xmmword ptr [rsp + 0x80], xmm8
    movaps xmmword ptr [rsp + 0x90], xmm9
    movaps xmmword ptr [rsp + 0xA0], xmm10
    movaps xmmword ptr [rsp + 0xB0], xmm11
    movaps xmmword ptr [rsp + 0xC0], xmm12
    movaps xmmword ptr [rsp + 0xD0], xmm13
    movaps xmmword ptr [rsp + 0xE0], xmm14
    movaps xmmword ptr [rsp + 0xF0], xmm15
.endmacro

.macro restore_xmm
    // Free the allocated stack space.
    add rsp, 0x100

    // Restore xmm registers.
    movaps xmm0, xmmword ptr [rsp]
    movaps xmm1, xmmword ptr [rsp + 0x10]
    movaps xmm2, xmmword ptr [rsp + 0x20]
    movaps xmm3, xmmword ptr [rsp + 0x30]
    movaps xmm4, xmmword ptr [rsp + 0x40]
    movaps xmm5, xmmword ptr [rsp + 0x50]
    movaps xmm6, xmmword ptr [rsp + 0x60]
    movaps xmm7, xmmword ptr [rsp + 0x70]
    movaps xmm8, xmmword ptr [rsp + 0x80]
    movaps xmm9, xmmword ptr [rsp + 0x90]
    movaps xmm10, xmmword ptr [rsp + 0xA0]
    movaps xmm11, xmmword ptr [rsp + 0xB0]
    movaps xmm12, xmmword ptr [rsp + 0xC0]
    movaps xmm13, xmmword ptr [rsp + 0xD0]
    movaps xmm14, xmmword ptr [rsp + 0xE0]
    movaps xmm15, xmmword ptr [rsp + 0xF0]
.endmacro

.global launch_vm
launch_vm:
    // Replace the current stack pointer with `host_rsp` (passed in rcx),
    // which is the end of the `stack_contents` in `VmStack`.
    mov rsp, rcx

    // Save host general-purpose registers onto the newly allocated stack.
    save_gpr

    // Attempt to launch the VM with vmlaunch.
    vmlaunch

    // VM launch failure handling: restore host registers and call `vmlaunch_failed`.
    restore_gpr
    call vmlaunch_failed

.global vmexit_stub
vmexit_stub:
    // Save guest general-purpose registers upon VM-exit.
    save_gpr

    // Set rcx to point to the saved guest registers for `vmexit_handler`.
    mov rcx, rsp

    // Save xmm registers.
    save_xmm

    // Allocate stack space for the VM exit handler.
    sub rsp, 0x20
    
    // Call the VM exit handler.
    call vmexit_handler
    
    // Restore stack pointer.
    add rsp, 0x20

    // Restore xmm registers.
    restore_xmm

    // Restore guest registers and resume VM execution.
    restore_gpr

    vmresume
    
    // VM resume failure handling: restore host registers and call `vmresume_failed`.
    restore_gpr
    call vmresume_failed
"#
);

// Handles VM exits.
///
/// This function is called when a VM exit occurs, and is responsible for handling
/// the VM exit logic.
///
/// # Arguments
///
/// * `registers` - A pointer to `GeneralPurposeRegisters` representing the guest's state at VM exit.
///
/// # Panics
///
/// Panics if `registers` is a null pointer.
#[no_mangle]
pub unsafe extern "C" fn vmexit_handler(registers: *mut GeneralPurposeRegisters) {
    assert!(
        !registers.is_null(),
        "vmexit_handler received a null pointer for registers."
    );

    let registers = &mut *registers;
    let vmexit = VmExit::new();

    if let Err(e) = vmexit.handle_vmexit(registers) {
        panic!("Failed to handle VMEXIT: {:?}", e);
    }
}

/// Handles the failure of the `VMLAUNCH` instruction.
///
/// This function is invoked when `VMLAUNCH` fails, and it retrieves and reports
/// the specific VM instruction error.
///
/// # Panics
///
/// Panics with the specific VM instruction error or an unknown error code.
///
/// Note: This can be handled with IDT later instead.
#[no_mangle]
pub extern "C" fn vmlaunch_failed() {
    //unsafe { core::arch::asm!("int3") };
    let instruction_error = vmread(x86::vmx::vmcs::ro::VM_INSTRUCTION_ERROR) as u32;

    if let Some(error) = VmInstructionError::from_u32(instruction_error) {
        panic!("VMLAUNCH instruction error: {}", error);
    } else {
        panic!("Unknown instruction error: {:#x}", instruction_error);
    };
}

/// Handles the failure of the `VMRESUME` instruction.
///
/// This function is invoked when `VMRESUME` fails, retrieving and reporting
/// the specific VM instruction error.
///
/// # Panics
///
/// Panics with the specific VM instruction error or an unknown error code.
///
/// Note: This can be handled with IDT later instead.
#[no_mangle]
pub extern "C" fn vmresume_failed() {
    //unsafe { core::arch::asm!("int3") };
    let instruction_error = vmread(x86::vmx::vmcs::ro::VM_INSTRUCTION_ERROR) as u32;

    if let Some(error) = VmInstructionError::from_u32(instruction_error) {
        panic!("VMRESUME instruction error: {}", error);
    } else {
        panic!("Unknown instruction error: {:#x}", instruction_error);
    };
}
