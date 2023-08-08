use crate::{
    intel::support::{vmread, vmwrite},
    nt::{KeBugCheck, MANUALLY_INITIATED_CRASH},
    utils::debug::dbg_break,
};
use x86::vmx::vmcs::{self, guest, ro::VMEXIT_INSTRUCTION_LEN};

use super::registers::GuestRegisters;

/// Save general-purpose registers onto stack.
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

/// Runs the guest until VM-exit occurs.
pub unsafe extern "C" fn launch_vm() -> ! {
    core::arch::asm!(
        "nop",

        // Save current (host) general purpose registers onto stack
        save_general_purpose_registers_to_stack!(),

        // Launch the VM until a VM-exit occurs
        "vmlaunch",

        // call vmlaunch_failed as we should never execution here
        "call   {0}",

        sym vmlaunch_failed,
        options(noreturn),
    );
}

#[no_mangle]
pub unsafe extern "C" fn vmexit_stub() -> ! {
    core::arch::asm!(
        "nop",

        // A vmexit occurred. Save current (guest) general purpose registers onto stack
        save_general_purpose_registers_to_stack!(),

        // Save a pointer to the stack, containing Guest Registers, in RCX, which is the first parameter to vmexit_handler
        "mov    rcx, rsp",

        // call vmexit_handler with the pointer to the stack containing Guest Registers
        "call    {0}",

        // We've handled the vmexit and now we want to restore guest general-purpose registers from the stack
        restore_general_purpose_registers_from_stack!(),

        // After handling the vmexit, advancing guest RIP and restoring guest general-purpose registers from the stack, we return to the guest
        "vmresume",

        // call vmresume_failed as we should never continue the guest execution here
        "call {1}",

        sym vmexit_handler,
        sym vmresume_failed,
        options(noreturn),
    );
}

#[no_mangle]
pub unsafe extern "C" fn vmexit_handler(registers: &mut GuestRegisters) {
    log::info!("[+] Called VMEXIT Handler...");

    // A VM-exit occurred. Copy the guest register values from VMCS so that "vmx.registers" is updated.
    registers.rip = vmread(vmcs::guest::RIP);
    registers.rsp = vmread(vmcs::guest::RSP);
    registers.rflags = vmread(vmcs::guest::RFLAGS);

    log::info!("[+] RIP: {:#x}", registers.rip);
    log::info!("[+] RSP: {:#x}", registers.rsp);
    log::info!("[+] RFLAGS: {:#x}", registers.rflags);

    /* TODO */
    /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.9 VM-EXIT INFORMATION FIELDS */
    /* APPENDIX C VMX BASIC EXIT REASONS */
    /* Table C-1. Basic Exit Reasons */
    let exit_reason = vmread(vmcs::ro::EXIT_REASON) as u16;
    log::info!("[+] Exit Reason: {}", exit_reason);

    /*
    // Handle the VM-exit
    match exit_reason {

    }
    */

    log::info!("[+] Advancing Guest RIP...");
    advance_guest_rip();
    log::info!("[+] Guest RIP advanced!");

    panic!("TEMPORARY PANIC");
}

#[no_mangle]
pub unsafe extern "C" fn vmlaunch_failed() {
    // We should never continue the guest execution here.
    //
    dbg_break!();
    unsafe { KeBugCheck(MANUALLY_INITIATED_CRASH) };
}

#[no_mangle]
pub unsafe extern "C" fn vmresume_failed() {
    // We should never continue the guest execution here.
    //
    dbg_break!();
    unsafe { KeBugCheck(MANUALLY_INITIATED_CRASH) };
}

fn advance_guest_rip() {
    let mut rip = vmread(guest::RIP);
    let len = vmread(VMEXIT_INSTRUCTION_LEN);
    rip += len;
    vmwrite(guest::RIP, rip);
}
