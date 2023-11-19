//! A module for managing Intel VMX-based virtualization.
//!
//! This module provides structures and functions for interacting with Intel's VMX
//! virtualization extensions. It offers abstractions for the guest's register state,
//! VM-entry, VM-exit, and handling VMX-specific instructions.
//!
//! Main components include:
//! - `GuestRegisters`: Represents the state of guest registers during a VM exit.
//! - VMX assembly integrations: Assembly routines to interface directly with VMX instructions.
//!
//! The module is designed to be used in conjunction with a broader hypervisor framework.
//!
//! Credits: Thanks to @daaximus (daax), @drewbervisor (drew) and @tandasat (Satoshi Tanda) <3

use crate::intel::support::vmread;
use crate::intel::vmerror::VmInstructionError;
use {super::vmexit::VmExit, static_assertions::const_assert_eq};

/// Represents the state of guest registers during a VM exit.
///
/// This structure is used to capture the state of all general-purpose registers,
/// of a virtualized guest when a VM exit occurs.
/// It allows the hypervisor to inspect or modify the guest's state as necessary
/// before resuming guest execution.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.4.1 Guest Register State
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, Default)]
pub struct GuestRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rdi: u64,
    pub rsi: u64,
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
    // XMM registers (each represented as two u64 for 16-byte alignment)
    pub xmm0: [u64; 2],
    pub xmm1: [u64; 2],
    pub xmm2: [u64; 2],
    pub xmm3: [u64; 2],
    pub xmm4: [u64; 2],
    pub xmm5: [u64; 2],
    pub xmm6: [u64; 2],
    pub xmm7: [u64; 2],
    pub xmm8: [u64; 2],
    pub xmm9: [u64; 2],
    pub xmm10: [u64; 2],
    pub xmm11: [u64; 2],
    pub xmm12: [u64; 2],
    pub xmm13: [u64; 2],
    pub xmm14: [u64; 2],
    pub xmm15: [u64; 2],
}
const_assert_eq!(
    core::mem::size_of::<GuestRegisters>(),
    0x190 /* 400 bytes */
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
    /// * `general_purpose_registers` - A pointer to the `GuestRegisters` structure
    /// * `host_rsp` - A pointer to the end of `stack_contents` in the `VmStack` structure.
    pub fn launch_vm(guest_registers: &mut GuestRegisters, host_rsp: *mut u64);

    /// Assembly stub for handling VM exits.
    pub fn vmexit_stub();
}

core::arch::global_asm!(
    r#"
.set registers_rax, 0x0
.set registers_rbx, 0x8
.set registers_rcx, 0x10
.set registers_rdx, 0x18
.set registers_rdi, 0x20
.set registers_rsi, 0x28
.set registers_rbp, 0x30
.set registers_r8,  0x38
.set registers_r9,  0x40
.set registers_r10, 0x48
.set registers_r11, 0x50
.set registers_r12, 0x58
.set registers_r13, 0x60
.set registers_r14, 0x68
.set registers_r15, 0x70
.set registers_rip, 0x78
.set registers_rsp, 0x80
.set registers_rflags, 0x88
.set registers_xmm0, 0x90
.set registers_xmm1, 0xA0
.set registers_xmm2, 0xB0
.set registers_xmm3, 0xC0
.set registers_xmm4, 0xD0
.set registers_xmm5, 0xE0
.set registers_xmm6, 0xF0
.set registers_xmm7, 0x100
.set registers_xmm8, 0x110
.set registers_xmm9, 0x120
.set registers_xmm10, 0x130
.set registers_xmm11, 0x140
.set registers_xmm12, 0x150
.set registers_xmm13, 0x160
.set registers_xmm14, 0x170
.set registers_xmm15, 0x180


.global launch_vm
launch_vm:
    // Replace the current stack pointer with `host_rsp` (passed in rdx),
    // which is the end of the `stack_contents` in `VmStack`.
    mov rsp, rdx

    // Save host general-purpose registers onto the newly allocated stack.
    ;// Save current (host) general purpose registers onto stack.
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

    // Save the guest's general-purpose registers into r15.
    mov     r15, rcx    ;// r15 <= `registers`

    // Push guest general-purpose registers onto the stack.
    push    rcx

    ;// Restore guest general purpose registers from `registers`.
    mov     rax, [r15 + registers_rax]
    mov     rbx, [r15 + registers_rbx]
    mov     rcx, [r15 + registers_rcx]
    mov     rdx, [r15 + registers_rdx]
    mov     rdi, [r15 + registers_rdi]
    mov     rsi, [r15 + registers_rsi]
    mov     rbp, [r15 + registers_rbp]
    mov      r8, [r15 + registers_r8]
    mov      r9, [r15 + registers_r9]
    mov     r10, [r15 + registers_r10]
    mov     r11, [r15 + registers_r11]
    mov     r12, [r15 + registers_r12]

    movdqa  xmm0, [r15 + registers_xmm0]
    movdqa  xmm1, [r15 + registers_xmm1]
    movdqa  xmm2, [r15 + registers_xmm2]
    movdqa  xmm3, [r15 + registers_xmm3]
    movdqa  xmm4, [r15 + registers_xmm4]
    movdqa  xmm5, [r15 + registers_xmm5]
    movdqa  xmm6, [r15 + registers_xmm6]
    movdqa  xmm7, [r15 + registers_xmm7]
    movdqa  xmm8, [r15 + registers_xmm8]
    movdqa  xmm9, [r15 + registers_xmm9]
    movdqa  xmm10, [r15 + registers_xmm10]
    movdqa  xmm11, [r15 + registers_xmm11]
    movdqa  xmm12, [r15 + registers_xmm12]
    movdqa  xmm13, [r15 + registers_xmm13]
    movdqa  xmm14, [r15 + registers_xmm14]
    movdqa  xmm15, [r15 + registers_xmm15]

    // Set VMCS_HOST_RSP to point to `stack_contents` right after host general-purpose registers.
    mov     r14, 0x6C14 ;// VMCS_HOST_RSP
    vmwrite r14, rsp

    // Set VMCS_HOST_RIP to point to `vmexit_stub`, so when a VM-exit occurs, it will be handled.
    lea     r13, [rip + .Vmexit]
    mov     r14, 0x6C16 ;// VMCS_HOST_RIP
    vmwrite r14, r13

    mov     r13, [r15 + registers_r13]
    mov     r14, [r15 + registers_r14]
    mov     r15, [r15 + registers_r15]

    // Attempt to launch the VM with vmlaunch.
    vmlaunch
    call vmlaunch_failed

.Vmexit:
    xchg    r15, [rsp]  ;// r15 <= `registers` / [rsp] <= guest r15
    mov     [r15 + registers_rax], rax
    mov     [r15 + registers_rbx], rbx
    mov     [r15 + registers_rcx], rcx
    mov     [r15 + registers_rdx], rdx
    mov     [r15 + registers_rsi], rsi
    mov     [r15 + registers_rdi], rdi
    mov     [r15 + registers_rbp], rbp
    mov     [r15 + registers_r8],  r8
    mov     [r15 + registers_r9],  r9
    mov     [r15 + registers_r10], r10
    mov     [r15 + registers_r11], r11
    mov     [r15 + registers_r12], r12
    mov     [r15 + registers_r13], r13
    mov     [r15 + registers_r14], r14

    movdqa  [r15 + registers_xmm0], xmm0
    movdqa  [r15 + registers_xmm1], xmm1
    movdqa  [r15 + registers_xmm2], xmm2
    movdqa  [r15 + registers_xmm3], xmm3
    movdqa  [r15 + registers_xmm4], xmm4
    movdqa  [r15 + registers_xmm5], xmm5
    movdqa  [r15 + registers_xmm6], xmm6
    movdqa  [r15 + registers_xmm7], xmm7
    movdqa  [r15 + registers_xmm8], xmm8
    movdqa  [r15 + registers_xmm9], xmm9
    movdqa  [r15 + registers_xmm10], xmm10
    movdqa  [r15 + registers_xmm11], xmm11
    movdqa  [r15 + registers_xmm12], xmm12
    movdqa  [r15 + registers_xmm13], xmm13
    movdqa  [r15 + registers_xmm14], xmm14
    movdqa  [r15 + registers_xmm15], xmm15

    // Set rcx to point to the saved guest registers for `vmexit_handler`.
    mov rcx, r15

    // Restore r15 but keep registers at the top of stack without changing the stack pointer since the next vmexit will be in same location
    mov     rax, [rsp]
    xchg    r15, [rsp]
    mov     [rcx + registers_r15], rax

    // Allocate stack space for the VM exit handler.
    sub     rsp, 0x20

    // Call the VM exit handler.
    call vmexit_handler

    // Restore stack pointer.
    add rsp, 0x20

    // get guest registers and put them in r15
    mov     r15, [rsp]

    ;// Restore guest general purpose registers from `registers`.
    mov     rax, [r15 + registers_rax]
    mov     rbx, [r15 + registers_rbx]
    mov     rcx, [r15 + registers_rcx]
    mov     rdx, [r15 + registers_rdx]
    mov     rdi, [r15 + registers_rdi]
    mov     rsi, [r15 + registers_rsi]
    mov     rbp, [r15 + registers_rbp]
    mov      r8, [r15 + registers_r8]
    mov      r9, [r15 + registers_r9]
    mov     r10, [r15 + registers_r10]
    mov     r11, [r15 + registers_r11]
    mov     r12, [r15 + registers_r12]
    mov     r13, [r15 + registers_r13]
    mov     r14, [r15 + registers_r14]

    movdqa  xmm0, [r15 + registers_xmm0]
    movdqa  xmm1, [r15 + registers_xmm1]
    movdqa  xmm2, [r15 + registers_xmm2]
    movdqa  xmm3, [r15 + registers_xmm3]
    movdqa  xmm4, [r15 + registers_xmm4]
    movdqa  xmm5, [r15 + registers_xmm5]
    movdqa  xmm6, [r15 + registers_xmm6]
    movdqa  xmm7, [r15 + registers_xmm7]
    movdqa  xmm8, [r15 + registers_xmm8]
    movdqa  xmm9, [r15 + registers_xmm9]
    movdqa  xmm10, [r15 + registers_xmm10]
    movdqa  xmm11, [r15 + registers_xmm11]
    movdqa  xmm12, [r15 + registers_xmm12]
    movdqa  xmm13, [r15 + registers_xmm13]
    movdqa  xmm14, [r15 + registers_xmm14]
    movdqa  xmm15, [r15 + registers_xmm15]

    // Do this last to avoid overwriting r15.
    mov     r15, [r15 + registers_r15]

    vmresume
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
/// * `registers` - A pointer to `GuestRegisters` representing the guest's state at VM exit.
///
/// # Panics
///
/// Panics if `registers` is a null pointer.
#[no_mangle]
pub unsafe extern "C" fn vmexit_handler(registers: *mut GuestRegisters) {
    if registers.is_null() {
        panic!("vmexit_handler received a null pointer for registers.");
    }

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
