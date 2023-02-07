
use x86::{vmx, current::vmx::vmread};
use crate::{error::HypervisorError, support};

#[allow(dead_code)]
pub enum VmxExitReason {
    ExceptionNmi = 0,
    ExternalInterrupt = 1,
    TripleFault = 2,
    Init = 3,
    Sipi = 4,
    Smi = 5,
    OtherSmi = 6,
    PendingInterrupt = 7,
    NmiWindow = 8,
    TaskSwitch = 9,
    Cpuid = 10,
    Getsec = 11,
    Hlt = 12,
    Invd = 13,
    Invlpg = 14,
    Rdpmc = 15,
    Rdtsc = 16,
    Rsm = 17,
    Vmcall = 18,
    Vmclear = 19,
    Vmlaunch = 20,
    Vmptrld = 21,
    Vmptrst = 22,
    Vmread = 23,
    Vmresume = 24,
    Vmwrite = 25,
    Vmoff = 26,
    Vmon = 27,
    CrAccess = 28,
    DrAccess = 29,
    IoInstruction = 30,
    MsrRead = 31,
    MsrWrite = 32,
    InvalidGuestState = 33,
    MsrLoadFail = 34,
    MwaitInstruction = 36,
    MonitorTrapFlag = 37,
    MonitorInstruction = 39,
    PauseInstruction = 40,
    MceDuringVmentry = 41,
    TprBelowThreshold = 43,
    ApicAccess = 44,
    EoiInduced = 45,
    GdtrIdtr = 46,
    LdtrTr = 47,
    EptViolation = 48,
    EptMisconfig = 49,
    Invept = 50,
    Rdtscp = 51,
    PreemptionTimer = 52,
    Invvpid = 53,
    Wbinvd = 54,
    Xsetbv = 55,
    ApicWrite = 56,
    Rdrand = 57,
    Invpcid = 58,
    Vmfunc = 59,
    Encls = 60,
    Rdseed = 61,
    PmlFull = 62,
    Xsaves = 63,
    Xrstors = 64,
    SppEvent = 66,
    Umwait = 67,
    Tpause = 68,
}

#[allow(dead_code)]
pub struct VmExitHandler(u32);

#[allow(dead_code)]
impl VmExitHandler {
    pub fn vmexit_handler(stack: u64) -> u64 {
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

#[naked]
pub unsafe extern "C" fn vmexit_stub() -> ! {
    core::arch::asm!(
        save_regs_to_stack!(),
        "sub     rsp, 68h",
        "movaps  xmmword ptr [rsp +  0h], xmm0",
        "movaps  xmmword ptr [rsp + 10h], xmm1",
        "movaps  xmmword ptr [rsp + 20h], xmm2",
        "movaps  xmmword ptr [rsp + 30h], xmm3",
        "movaps  xmmword ptr [rsp + 40h], xmm4",
        "movaps  xmmword ptr [rsp + 50h], xmm5",
        
        "mov     rcx, rsp",
        "sub     rsp, 20h",
        "call    {0}",
        "add     rsp, 20h",
        
        "movaps  xmm0, xmmword ptr [rsp +  0h]",
        "movaps  xmm1, xmmword ptr [rsp + 10h]",
        "movaps  xmm2, xmmword ptr [rsp + 20h]",
        "movaps  xmm3, xmmword ptr [rsp + 30h]",
        "movaps  xmm4, xmmword ptr [rsp + 40h]",
        "movaps  xmm5, xmmword ptr [rsp + 50h]",
        "add     rsp, 68h",

        "cmp     al, 1",
        "je      {2}",
        restore_regs_from_stack!(),
        "vmresume",
        "jmp {1}",
        sym VmExitHandler::vmexit_handler,
        sym vmerror,
        sym exit,
        options(noreturn),
    );
}

#[naked]
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
            sym vmerror,
            options(noreturn),
    );
}

fn instruction_error() -> Result<u64, HypervisorError> {
    let error = support::vmread(vmx::vmcs::ro::VM_INSTRUCTION_ERROR)?;
    Ok(error)
}

fn vmerror() -> ! {
    panic!("VM resume failed: {:?}", instruction_error().expect("VMREAD FAILED FROM instruction_error"));
}