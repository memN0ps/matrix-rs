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
//! Full credits for some of the assembly implementations go to Satoshi Tanda:
//! - [Hypervisor-101-in-Rust](https://github.com/tandasat/Hypervisor-101-in-Rust)
//! - [Hello-VT-rp](https://github.com/tandasat/Hello-VT-rp)

/// Represents the state of guest registers during a VM exit.
///
/// This structure is used to capture the state of all general-purpose registers,
/// along with `rip`, `rsp`, and `rflags`, of a virtualized guest when a VM exit occurs.
/// It allows the hypervisor to inspect or modify the guest's state as necessary
/// before resuming guest execution.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.4.1 Guest Register State
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct GuestRegisters {
    /// Accumulator register.
    pub rax: u64,
    /// Base register.
    pub rbx: u64,
    /// Counter register.
    pub rcx: u64,
    /// Data register.
    pub rdx: u64,
    /// Destination index register.
    pub rdi: u64,
    /// Source index register.
    pub rsi: u64,
    /// Base pointer (or frame pointer).
    pub rbp: u64,
    /// 8th general-purpose register.
    pub r8: u64,
    /// 9th general-purpose register.
    pub r9: u64,
    /// 10th general-purpose register.
    pub r10: u64,
    /// 11th general-purpose register.
    pub r11: u64,
    /// 12th general-purpose register.
    pub r12: u64,
    /// 13th general-purpose register.
    pub r13: u64,
    /// 14th general-purpose register.
    pub r14: u64,
    /// 15th general-purpose register.
    pub r15: u64,
    /// Instruction pointer.
    pub rip: u64,
    /// Stack pointer.
    pub rsp: u64,
    /// Flags register.
    pub rflags: u64,
}

extern "C" {
    /// Executes the VM using VMX until a VM-exit event occurs.
    ///
    /// This function is defined in Assembly and interacts directly with the VMX
    /// instructions `vmlaunch` and `vmresume`. On success, this function will not return,
    /// instead transitioning control to the guest VM. On VM-exit, the function will return,
    /// allowing the hypervisor to handle the exit reason.
    ///
    /// # Arguments
    ///
    /// * `registers`: A mutable reference to the guest's current register state.
    /// * `launched`: Indicates if the VM has been previously launched.
    ///
    /// # Returns
    ///
    /// * Returns the RFlags value after VM-exit.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual
    pub fn launch_vm(registers: &mut GuestRegisters, launched: u64) -> u64;
}

core::arch::global_asm!(
    r#"
; // Full-Credits to Satoshi Tanda:
; // https://github.com/tandasat/Hypervisor-101-in-Rust/blob/main/hypervisor/src/hardware_vt/svm_run_vm.nasm
; // https://github.com/tandasat/Hello-VT-rp/blob/main/hypervisor/src/intel_vt/run_vmx_vm.S
;// The module containing the `launch_vm` function.

;// The module containing the `launch_vm` function.

;// Offsets to each field in the GuestRegisters struct.
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

;// Runs the guest until VM-exit occurs.
;//
;// This function works as follows:
;// 1. saves host general purpose register values to stack.
;// 2. loads guest general purpose register values from `GuestRegisters`.
;// 3. executes the VMLAUNCH or VMRESUME instruction that
;//     1. saves host register values to the VMCS.
;//     2. loads guest register values from the VMCS.
;//     3. starts running code in VMX non-root operation until VM-exit.
;// 4. on VM-exit, the processor
;//     1. saves guest register values to the VMCS.
;//     2. loads host register values from the VMCS. Some registers are reset to
;//        hard-coded values. For example, interrupts are always disabled.
;//     3. updates VM-exit information fields in VMCS to record causes of VM-exit.
;//     4. starts running code in the VMX root operation.
;// 5. saves guest general purpose register values to `GuestRegisters`.
;// 6. loads host general purpose register values from stack.
;//
;// On VM-exit, the processor comes back to this function (at "VmExit") because
;// the host RIP is configured so.
;//
;// Note that state swich implemented here is not complete, and some register
;// values are "leaked" to the other side, for example, XMM registers.
;//
;// extern "C" fn launch_vm(registers: &mut GuestRegisters, launched: u64) -> u64;
.global launch_vm
launch_vm:
    xchg    bx, bx

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

    ;// Copy `registers` and `launched` for using them. Also, save
    ;// `registers` at the top of stack so that after VM-exit, we can find it.
    mov     r15, rcx    ;// r15 <= `registers`
    mov     r14, rdx    ;// r14 <= `launched`
    push    rcx         ;// [rsp] <= `registers`

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

    ;// If `launched` is false, go to Launch.
    test    r14, r14
    je      .Launch

    ;// Otherwise, restore the rest of the guest general purpose registers and
    ;// run the guest until VM-exit occurs.
    mov     r13, [r15 + registers_r13]
    mov     r14, [r15 + registers_r14]
    mov     r15, [r15 + registers_r15]
    vmresume
    jmp     .VmEntryFailure

.Launch:
    ;// The VM has never launched with the current VMCS. Configure the host RSP
    ;// and RIP first. Then, restore the rest of guest general purpose registers
    ;// and run the guest until VM-exit occurs.
    xchg    bx, bx
    mov     r14, 0x6C14 ;// VMCS_HOST_RSP
    vmwrite r14, rsp
    lea     r13, [rip + .VmExit]
    mov     r14, 0x6C16 ;// VMCS_HOST_RIP
    vmwrite r14, r13
    mov     r13, [r15 + registers_r13]
    mov     r14, [r15 + registers_r14]
    mov     r15, [r15 + registers_r15]
    vmlaunch

.VmEntryFailure:
    ;// VMLAUNCH or VMRESUME failed. If it were successful, VM-exit should have
    ;// led to "VmExit" not here.
    jmp     .Exit

.VmExit:
    ;// VM-exit occured. Save current (guest) general purpose registers.
    xchg    bx, bx
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
    mov     rax, [rsp]  ;// rax <= guest R15
    mov     [r15 + registers_r15], rax

.Exit:
    ;// Adjust the stack pointer.
    pop     rax

    ;// Restore host general purpose registers from stack.
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

    ;// Return the rflags value.
    pushfq
    pop     rax
    ret
"#
);
