
use x86::{vmx, current::vmx::vmread};
use crate::{error::HypervisorError, support};

#[no_mangle]
pub extern "C" fn vmexit_handler(_register_state: *mut GeneralRegisters) -> u64 {
    log::info!("[+] vmexit_handler called........");
    let exit_reason = unsafe { vmread(vmx::vmcs::ro::VM_INSTRUCTION_ERROR).expect("VMREAD FAILED") };
    let exit_qualification = unsafe { vmread(x86::vmx::vmcs::ro::EXIT_QUALIFICATION).expect("VMREAD FAILED") };

    log::info!("Exit Reason: {:#x}", exit_reason);
    log::info!("Exit Qualification: {:#x}", exit_qualification);

    match exit_reason {
        0 => log::info!("OK"),
        1 => log::info!("VMCALL executed in VMX root operation"),
        2 => log::info!("VMCLEAR with invalid physical address"),
        3 => log::info!("VMCLEAR with VMXON pointer"),
        4 => log::info!("VMLAUNCH with non-clear VMCS"),
        5 => log::info!("VMRESUME with non-launched VMCS"),
        6 => log::info!("VMRESUME after VMXOFF (VMXOFF and VMXON between VMLAUNCH and VMRESUME)"),
        7 => log::info!("VM entry with invalid control field(s)"),
        8 => log::info!("VM entry with invalid host-state field(s)"),
        9 => log::info!("VMPTRLD with invalid physical address"),
        10 => log::info!("VMPTRLD with VMXON pointer"),
        11 => log::info!("VMPTRLD with incorrect VMCS revision identifier"),
        12 => log::info!("VMREAD/VMWRITE from/to unsupported VMCS component"),
        13 => log::info!("VMWRITE to read-only VMCS component"),
        15 => log::info!("VMXON executed in VMX root operation"),
        16 => log::info!("VM entry with invalid executive-VMCS pointer"),
        17 => log::info!("VM entry with non-launched executive VMCS"),
        18 => log::info!("VM entry with executive-VMCS pointer not VMXON pointer (when attempting to deactivate the dual-monitor treatment of SMIs and SMM)"),
        19 => log::info!("VMCALL with non-clear VMCS (when attempting to activate the dual-monitor treatment of SMIs and SMM)"),
        20 => log::info!("VMCALL with invalid VM-exit control fields"),
        22 => log::info!("VMCALL with incorrect MSEG revision identifier (when attempting to activate the dual-monitor treatment of SMIs and SMM)"),
        23 => log::info!("VMXOFF under dual-monitor treatment of SMIs and SMM"),
        24 => log::info!("VMCALL with invalid SMM-monitor features (when attempting to activate the dual-monitor treatment of SMIs and SMM)"),
        25 => log::info!("VM entry with invalid VM-execution control fields in executive VMCS (when attempting to return from SMM)"),
        26 => log::info!("VM entry with events blocked by MOV SS"),
        28 => log::info!("Invalid operand to INVEPT/INVVPID"),
        _ => log::info!("[INVALID]"),
    };

    return exit_reason;
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct GeneralRegisters {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    _unused_rsp: u64,
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

macro_rules! save_regs_to_stack {
    () => {
        "
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8
        push rdi
        push rsi
        push rbp
        sub rsp, 8
        push rbx
        push rdx
        push rcx
        push rax"
    };
}

macro_rules! restore_regs_from_stack {
    () => {
        "
        pop rax
        pop rcx
        pop rdx
        pop rbx
        add rsp, 8
        pop rbp
        pop rsi
        pop rdi
        pop r8
        pop r9
        pop r10
        pop r11
        pop r12
        pop r13
        pop r14
        pop r15"
    };
}

#[no_mangle]
pub unsafe extern "C" fn vmexit_stub() -> ! {
    core::arch::asm!(
        save_regs_to_stack!(),
        //"sub     rsp, 68h",
        //"movaps  xmmword ptr [rsp +  0h], xmm0",
        //"movaps  xmmword ptr [rsp + 10h], xmm1",
        //"movaps  xmmword ptr [rsp + 20h], xmm2",
        //"movaps  xmmword ptr [rsp + 30h], xmm3",
        //"movaps  xmmword ptr [rsp + 40h], xmm4",
        //"movaps  xmmword ptr [rsp + 50h], xmm5",
        
        "mov     rcx, rsp",
        //"sub     rsp, 20h",
        "call    {0}",                              //call vmexit_handler
        //"add     rsp, 20h",
        
        //"movaps  xmm0, xmmword ptr [rsp +  0h]",
        //"movaps  xmm1, xmmword ptr [rsp + 10h]",
        //"movaps  xmm2, xmmword ptr [rsp + 20h]",
        //"movaps  xmm3, xmmword ptr [rsp + 30h]",
        //"movaps  xmm4, xmmword ptr [rsp + 40h]",
        //"movaps  xmm5, xmmword ptr [rsp + 50h]",
        //"add     rsp, 68h",

        "cmp     al, 1",
        "je      {2}",                              //call exit
        restore_regs_from_stack!(),
        "vmresume",
        "jmp {1}",                                  //jmp vmerror
        sym vmexit_handler,
        sym vm_resume_failed,
        sym exit,
        options(noreturn),
    );
}

#[naked]
#[no_mangle]
pub unsafe extern "C" fn exit() -> ! {
    core::arch::asm!(
        restore_regs_from_stack!(),
            "vmxoff",
            "jz {0}",
            "jc {0}",
            "push r8",
            "popf",
            "mov     rsp, rdx",
            "push    rcx",
            "ret",
            sym vm_resume_failed,
            options(noreturn),
    );
}

fn instruction_error() -> Result<u64, HypervisorError> {
    let error = support::vmread(vmx::vmcs::ro::VM_INSTRUCTION_ERROR)?;
    Ok(error)
}

fn vm_resume_failed() -> ! {
    panic!("VM resume failed: {:?}", instruction_error().expect("VMREAD FAILED FROM instruction_error"));
}