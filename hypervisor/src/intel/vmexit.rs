use core::fmt;

use super::registers::GuestRegisters;
use crate::{
    error::HypervisorError,
    intel::support::{vmread, vmwrite},
    restore_general_purpose_registers_from_stack, save_general_purpose_registers_to_stack,
    utils::debug::breakpoint_to_bugcheck,
};
use x86::vmx::vmcs::{self, guest, ro::VMEXIT_INSTRUCTION_LEN};

pub enum VmxBasicExitReason {
    ExceptionOrNmi = 0,
    ExternalInterrupt = 1,
    TripleFault = 2,
    InitSignal = 3,
    StartupIpi = 4,
    IoSystemManagementInterrupt = 5,
    OtherSmi = 6,
    InterruptWindow = 7,
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
    Vmxoff = 26,
    Vmxon = 27,
    ControlRegisterAccesses = 28,
    MovDr = 29,
    IoInstruction = 30,
    Rdmsr = 31,
    Wrmsr = 32,
    VmEntryFailureInvalidGuestState = 33,
    VmEntryFailureMsrLoading = 34,
    Mwait = 36,
    MonitorTrapFlag = 37,
    Monitor = 39,
    Pause = 40,
    VmEntryFailureMachineCheckEvent = 41,
    TprBelowThreshold = 43,
    ApicAccess = 44,
    VirtualizedEoi = 45,
    AccessToGdtrOrIdtr = 46,
    AccessToLdtrOrTr = 47,
    EptViolation = 48,
    EptMisconfiguration = 49,
    Invept = 50,
    Rdtscp = 51,
    VmxPreemptionTimerExpired = 52,
    Invvpid = 53,
    WbinvdOrWbnoinvd = 54,
    Xsetbv = 55,
    ApicWrite = 56,
    Rdrand = 57,
    Invpcid = 58,
    Vmfunc = 59,
    Encls = 60,
    Rdseed = 61,
    PageModificationLogFull = 62,
    Xsaves = 63,
    Xrstors = 64,
    Pconfig = 65,
    SppRelatedEvent = 66,
    Umwait = 67,
    Tpause = 68,
    Loadiwkey = 69,
    Enclv = 70,
    EnqcmdPasidTranslationFailure = 72,
    EnqcmdsPasidTranslationFailure = 73,
    BusLock = 74,
    InstructionTimeout = 75,
}

pub struct VmExit;

impl VmExit {
    pub fn new() -> Self {
        Self
    }

    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.9 VM-EXIT INFORMATION FIELDS
    /// - APPENDIX C VMX BASIC EXIT REASONS
    /// - Table C-1. Basic Exit Reasons
    pub fn handle_vmexit(
        &self,
        registers: &mut GuestRegisters,
    ) -> Result<VmxBasicExitReason, HypervisorError> {
        // A VM-exit occurred. Copy the guest register values from VMCS so that "vmx.registers" is updated.
        registers.rip = vmread(vmcs::guest::RIP);
        registers.rsp = vmread(vmcs::guest::RSP);
        registers.rflags = vmread(vmcs::guest::RFLAGS);

        log::info!("[+] RIP: {:#x}", registers.rip);
        log::info!("[+] RSP: {:#x}", registers.rsp);
        log::info!("[+] RFLAGS: {:#x}", registers.rflags);

        // The low 16 bits of the exit-reason field form the basic exit reason
        let exit_reason = vmread(vmcs::ro::EXIT_REASON);

        let Some(basic_exit_reason) = VmxBasicExitReason::from_u64(exit_reason) else {
            log::error!("[!] Unknown exit reason: {:#x}", exit_reason);
            return Err(HypervisorError::UnknownVMExitReason);
        };

        log::info!("[+] Basic Exit Reason: {}", basic_exit_reason);

        // Handle the VM-exit
        match basic_exit_reason {
            VmxBasicExitReason::Cpuid => self.handle_cpuid(),
            _ => breakpoint_to_bugcheck(),
        }

        log::info!("[+] Advancing Guest RIP...");
        self.advance_guest_rip();
        log::info!("[+] Guest RIP advanced!");

        return Ok(basic_exit_reason);
    }

    /// TODO: Implement CPUID handling
    fn handle_cpuid(&self) {}

    fn advance_guest_rip(&self) {
        let mut rip = vmread(guest::RIP);
        let len = vmread(VMEXIT_INSTRUCTION_LEN);
        rip += len;
        vmwrite(guest::RIP, rip);
    }
}

impl VmxBasicExitReason {
    /// Every VM exit writes a 32-bit exit reason to the VMCS (see Section 25.9.1). Certain VM-entry failures also do this (see Section 27.8).
    /// The low 16 bits of the exit-reason field form the basic exit reason which provides basic information about the cause of the VM exit or VM-entry failure.
    pub fn from_u64(value: u64) -> Option<Self> {
        let basic_exit_reason = (value & 0xFFFF) as u16;
        match basic_exit_reason {
            0 => Some(Self::ExceptionOrNmi),
            1 => Some(Self::ExternalInterrupt),
            2 => Some(Self::TripleFault),
            3 => Some(Self::InitSignal),
            4 => Some(Self::StartupIpi),
            5 => Some(Self::IoSystemManagementInterrupt),
            6 => Some(Self::OtherSmi),
            7 => Some(Self::InterruptWindow),
            8 => Some(Self::NmiWindow),
            9 => Some(Self::TaskSwitch),
            10 => Some(Self::Cpuid),
            11 => Some(Self::Getsec),
            12 => Some(Self::Hlt),
            13 => Some(Self::Invd),
            14 => Some(Self::Invlpg),
            15 => Some(Self::Rdpmc),
            16 => Some(Self::Rdtsc),
            17 => Some(Self::Rsm),
            18 => Some(Self::Vmcall),
            19 => Some(Self::Vmclear),
            20 => Some(Self::Vmlaunch),
            21 => Some(Self::Vmptrld),
            22 => Some(Self::Vmptrst),
            23 => Some(Self::Vmread),
            24 => Some(Self::Vmresume),
            25 => Some(Self::Vmwrite),
            26 => Some(Self::Vmxoff),
            27 => Some(Self::Vmxon),
            28 => Some(Self::ControlRegisterAccesses),
            29 => Some(Self::MovDr),
            30 => Some(Self::IoInstruction),
            31 => Some(Self::Rdmsr),
            32 => Some(Self::Wrmsr),
            33 => Some(Self::VmEntryFailureInvalidGuestState),
            34 => Some(Self::VmEntryFailureMsrLoading),
            36 => Some(Self::Mwait),
            37 => Some(Self::MonitorTrapFlag),
            39 => Some(Self::Monitor),
            40 => Some(Self::Pause),
            41 => Some(Self::VmEntryFailureMachineCheckEvent),
            43 => Some(Self::TprBelowThreshold),
            44 => Some(Self::ApicAccess),
            45 => Some(Self::VirtualizedEoi),
            46 => Some(Self::AccessToGdtrOrIdtr),
            47 => Some(Self::AccessToLdtrOrTr),
            48 => Some(Self::EptViolation),
            49 => Some(Self::EptMisconfiguration),
            50 => Some(Self::Invept),
            51 => Some(Self::Rdtscp),
            52 => Some(Self::VmxPreemptionTimerExpired),
            53 => Some(Self::Invvpid),
            54 => Some(Self::WbinvdOrWbnoinvd),
            55 => Some(Self::Xsetbv),
            56 => Some(Self::ApicWrite),
            57 => Some(Self::Rdrand),
            58 => Some(Self::Invpcid),
            59 => Some(Self::Vmfunc),
            60 => Some(Self::Encls),
            61 => Some(Self::Rdseed),
            62 => Some(Self::PageModificationLogFull),
            63 => Some(Self::Xsaves),
            64 => Some(Self::Xrstors),
            65 => Some(Self::Pconfig),
            66 => Some(Self::SppRelatedEvent),
            67 => Some(Self::Umwait),
            68 => Some(Self::Tpause),
            69 => Some(Self::Loadiwkey),
            70 => Some(Self::Enclv),
            72 => Some(Self::EnqcmdPasidTranslationFailure),
            73 => Some(Self::EnqcmdsPasidTranslationFailure),
            74 => Some(Self::BusLock),
            75 => Some(Self::InstructionTimeout),
            _ => None,
        }
    }
}

impl fmt::Display for VmxBasicExitReason {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            VmxBasicExitReason::ExceptionOrNmi => write!(f, "Exception or non-maskable interrupt (NMI)"),
            VmxBasicExitReason::ExternalInterrupt => write!(f, "External interrupt"),
            VmxBasicExitReason::TripleFault => write!(f, "Triple fault"),
            VmxBasicExitReason::InitSignal => write!(f, "INIT signal"),
            VmxBasicExitReason::StartupIpi => write!(f, "Start-up IPI (SIPI)"),
            VmxBasicExitReason::IoSystemManagementInterrupt => write!(f, "I/O system-management interrupt (SMI)"),
            VmxBasicExitReason::OtherSmi => write!(f, "Other SMI"),
            VmxBasicExitReason::InterruptWindow => write!(f, "Interrupt window"),
            VmxBasicExitReason::NmiWindow => write!(f, "NMI window"),
            VmxBasicExitReason::TaskSwitch => write!(f, "Task switch"),
            VmxBasicExitReason::Cpuid => write!(f, "Guest software attempted to execute CPUID"),
            VmxBasicExitReason::Getsec => write!(f, "Guest software attempted to execute GETSEC"),
            VmxBasicExitReason::Hlt => write!(f, "Guest software attempted to execute HLT"),
            VmxBasicExitReason::Invd => write!(f, "Guest software attempted to execute INVD"),
            VmxBasicExitReason::Invlpg => write!(f, "Guest software attempted to execute INVLPG"),
            VmxBasicExitReason::Rdpmc => write!(f, "Guest software attempted to execute RDPMC"),
            VmxBasicExitReason::Rdtsc => write!(f, "Guest software attempted to execute RDTSC"),
            VmxBasicExitReason::Rsm => write!(f, "Guest software attempted to execute RSM in SMM"),
            VmxBasicExitReason::Vmcall => write!(f, "VMCALL was executed"),
            VmxBasicExitReason::Vmclear => write!(f, "Guest software attempted to execute VMCLEAR"),
            VmxBasicExitReason::Vmlaunch => write!(f, "Guest software attempted to execute VMLAUNCH"),
            VmxBasicExitReason::Vmptrld => write!(f, "Guest software attempted to execute VMPTRLD"),
            VmxBasicExitReason::Vmptrst => write!(f, "Guest software attempted to execute VMPTRST"),
            VmxBasicExitReason::Vmread => write!(f, "Guest software attempted to execute VMREAD"),
            VmxBasicExitReason::Vmresume => write!(f, "Guest software attempted to execute VMRESUME"),
            VmxBasicExitReason::Vmwrite => write!(f, "Guest software attempted to execute VMWRITE"),
            VmxBasicExitReason::Vmxoff => write!(f, "Guest software attempted to execute VMXOFF"),
            VmxBasicExitReason::Vmxon => write!(f, "Guest software attempted to execute VMXON"),
            VmxBasicExitReason::ControlRegisterAccesses => write!(f, "Control-register accesses"),
            VmxBasicExitReason::MovDr => write!(f, "Guest software attempted a MOV to or from a debug register"),
            VmxBasicExitReason::IoInstruction => write!(f, "Guest software attempted to execute an I/O instruction"),
            VmxBasicExitReason::Rdmsr => write!(f, "Guest software attempted to execute RDMSR"),
            VmxBasicExitReason::Wrmsr => write!(f, "Guest software attempted to execute WRMSR"),
            VmxBasicExitReason::VmEntryFailureInvalidGuestState => write!(f, "VM-entry failure due to invalid guest state"),
            VmxBasicExitReason::VmEntryFailureMsrLoading => write!(f, "VM-entry failure due to MSR loading"),
            VmxBasicExitReason::Mwait => write!(f, "Guest software attempted to execute MWAIT"),
            VmxBasicExitReason::MonitorTrapFlag => write!(f, "Monitor trap flag"),
            VmxBasicExitReason::Monitor => write!(f, "Guest software attempted to execute MONITOR"),
            VmxBasicExitReason::Pause => write!(f, "Either guest software attempted to execute PAUSE or the PAUSE-loop exiting VM-execution control was 1"),
            VmxBasicExitReason::VmEntryFailureMachineCheckEvent => write!(f, "VM-entry failure due to machine-check event"),
            VmxBasicExitReason::TprBelowThreshold => write!(f, "TPR below threshold"),
            VmxBasicExitReason::ApicAccess => write!(f, "APIC access"),
            VmxBasicExitReason::VirtualizedEoi => write!(f, "Virtualized EOI"),
            VmxBasicExitReason::AccessToGdtrOrIdtr => write!(f, "Access to GDTR or IDTR"),
            VmxBasicExitReason::AccessToLdtrOrTr => write!(f, "Access to LDTR or TR"),
            VmxBasicExitReason::EptViolation => write!(f, "EPT violation"),
            VmxBasicExitReason::EptMisconfiguration => write!(f, "EPT misconfiguration"),
            VmxBasicExitReason::Invept => write!(f, "Guest software attempted to execute INVEPT"),
            VmxBasicExitReason::Rdtscp => write!(f, "Guest software attempted to execute RDTSCP"),
            VmxBasicExitReason::VmxPreemptionTimerExpired => write!(f, "VMX-preemption timer expired"),
            VmxBasicExitReason::Invvpid => write!(f, "Guest software attempted to execute INVVPID"),
            VmxBasicExitReason::WbinvdOrWbnoinvd => write!(f, "Guest software attempted to execute WBINVD or WBNOINVD"),
            VmxBasicExitReason::Xsetbv => write!(f, "Guest software attempted to execute XSETBV"),
            VmxBasicExitReason::ApicWrite => write!(f, "APIC write"),
            VmxBasicExitReason::Rdrand => write!(f, "Guest software attempted to execute RDRAND"),
            VmxBasicExitReason::Invpcid => write!(f, "Guest software attempted to execute INVPCID"),
            VmxBasicExitReason::Vmfunc => write!(f, "Guest software invoked a VM function with the VMFUNC instruction"),
            VmxBasicExitReason::Encls => write!(f, "Guest software attempted to execute ENCLS"),
            VmxBasicExitReason::Rdseed => write!(f, "Guest software attempted to execute RDSEED"),
            VmxBasicExitReason::PageModificationLogFull => write!(f, "Page-modification log full"),
            VmxBasicExitReason::Xsaves => write!(f, "Guest software attempted to execute XSAVES"),
            VmxBasicExitReason::Xrstors => write!(f, "Guest software attempted to execute XRSTORS"),
            VmxBasicExitReason::Pconfig => write!(f, "Guest software attempted to execute PCONFIG"),
            VmxBasicExitReason::SppRelatedEvent => write!(f, "SPP-related event"),
            VmxBasicExitReason::Umwait => write!(f, "Guest software attempted to execute UMWAIT"),
            VmxBasicExitReason::Tpause => write!(f, "Guest software attempted to execute TPAUSE"),
            VmxBasicExitReason::Loadiwkey => write!(f, "Guest software attempted to execute LOADIWKEY"),
            VmxBasicExitReason::Enclv => write!(f, "Guest software attempted to execute ENCLV"),
            VmxBasicExitReason::EnqcmdPasidTranslationFailure => write!(f, "ENQCMD PASID translation failure"),
            VmxBasicExitReason::EnqcmdsPasidTranslationFailure => write!(f, "ENQCMDS PASID translation failure"),
            VmxBasicExitReason::BusLock => write!(f, "Bus lock"),
            VmxBasicExitReason::InstructionTimeout => write!(f, "Instruction timeout"),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn vmexit_handler(registers: &mut GuestRegisters) -> u16 {
    log::info!("[+] Called VMEXIT Handler...");

    let vmexit = VmExit::new();

    match vmexit.handle_vmexit(registers) {
        Ok(vmexit_basic_reason) => {
            log::info!("[+] VMEXIT handled successfully!");
            return vmexit_basic_reason as u16; // we return the vmexit basic reason if it's needed by the caller
        }
        Err(e) => {
            panic!("[-] Failed to handle VMEXIT: {:?}", e); // panic if error could not be handled
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn vmlaunch_failed() {
    breakpoint_to_bugcheck();
}

#[no_mangle]
pub unsafe extern "C" fn vmresume_failed() {
    breakpoint_to_bugcheck();
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
