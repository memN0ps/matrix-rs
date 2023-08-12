use core::fmt;

use super::{events::EventInjection, registers::GuestRegisters};
use crate::{
    error::HypervisorError,
    intel::support::{vmread, vmwrite},
    restore_general_purpose_registers_from_stack, save_general_purpose_registers_to_stack,
    utils::debug::breakpoint_to_bugcheck,
};
use x86::vmx::vmcs::{self, guest, ro::VMEXIT_INSTRUCTION_LEN};

pub struct VmExit;

impl VmExit {
    pub fn new() -> Self {
        Self
    }

    /// Handle the VM-exit
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.9 VM-EXIT INFORMATION FIELDS
    /// - APPENDIX C VMX BASIC EXIT REASONS
    /// - Table C-1. Basic Exit Reasons
    pub fn handle_vmexit(
        &self,
        registers: &mut GuestRegisters,
    ) -> Result<VmxBasicExitReason, HypervisorError> {
        // A VM-exit occurred. Copy the guest register values from VMCS so that "vmx.registers" is updated.
        //registers.rip = vmread(vmcs::guest::RIP);
        //registers.rsp = vmread(vmcs::guest::RSP);
        //registers.rflags = vmread(vmcs::guest::RFLAGS);

        log::info!("[+] VMEXIT occurred at RIP: {:#x}", vmread(guest::RIP));
        log::info!("[+] VMEXIT occurred at RSP: {:#x}", vmread(guest::RSP));

        // Every VM exit writes a 32-bit exit reason to the VMCS (see Section 25.9.1). Certain VM-entry failures also do this (see Section 27.8).
        // The low 16 bits of the exit-reason field form the basic exit reason which provides basic information about the cause of the VM exit or VM-entry failure.
        let exit_reason = vmread(vmcs::ro::EXIT_REASON) as u32;
        log::info!("[+] VMEXIT Reason: {:#x}", exit_reason);

        let Some(basic_exit_reason) = VmxBasicExitReason::from_u32(exit_reason) else {
            log::error!("[!] Unknown exit reason: {:#x}", exit_reason);
            return Err(HypervisorError::UnknownVMExitReason);
        };

        log::info!("[+] Basic Exit Reason: {}", basic_exit_reason);

        /* Handle VMEXIT */
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 26.1.2 Instructions That Cause VM Exits Unconditionally */
        /* - The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC, INVD, and XSETBV. */
        /* - This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID, VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON. */
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 26.1.3 Instructions That Cause VM Exits Conditionally */
        /* - Certain instructions cause VM exits in VMX non-root operation depending on the setting of the VM-execution controls.*/
        match basic_exit_reason {
            VmxBasicExitReason::Cpuid => self.handle_cpuid(registers),
            VmxBasicExitReason::Rdmsr => self.handle_msr_access(registers, false),
            VmxBasicExitReason::Wrmsr => self.handle_msr_access(registers, true),
            _ => breakpoint_to_bugcheck(),
        }

        log::info!("[+] Advancing guest RIP...");
        self.advance_guest_rip();
        log::info!("[+] Guest RIP advanced to: {:#x}", vmread(guest::RIP));

        return Ok(basic_exit_reason);
    }

    /// The CPUID (processor identification) instruction returns information about the processor on which the instruction is executed.
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: Table C-1. Basic Exit Reasons 10
    /// CPUID. Guest software attempted to execute CPUID.
    fn handle_cpuid(&self, registers: &mut GuestRegisters) {
        log::info!("[+] Handling CPUID...");

        // More leafs here if needed: https://docs.rs/raw-cpuid/10.6.0/src/raw_cpuid/lib.rs.html#289
        const EAX_HYPERVISOR_PRESENT: u32 = 0x1;
        const EAX_HYPERVISOR_INTERFACE: u32 = 0x4000_0000;

        let leaf = registers.rax as u32;
        let sub_leaf = registers.rcx as u32;

        // Macro which queries cpuid directly.
        // First parameter is cpuid leaf (EAX register value), second optional parameter is the subleaf (ECX register value).
        let mut cpuid_result = x86::cpuid::cpuid!(leaf, sub_leaf);

        // Change vendor info if required
        if leaf == EAX_HYPERVISOR_INTERFACE {
            let interface_identifier: [u8; 4] = *b"BEEF";
            cpuid_result.eax = u32::from_le_bytes(interface_identifier);
        } else if leaf == EAX_HYPERVISOR_PRESENT {
            // Clearing VT-x Support: If the leaf value is 1 (which corresponds to the standard CPUID function that returns feature information),
            // We clear bit 5 in the ECX register, which is used to indicate support for VT-x (Virtualization Technology),
            // to prevent the guest from recognizing VT-x support and attempting to use it.
            cpuid_result.ecx &= !(1 << 5);
        }

        // Update the Guest registers with cpuid result
        registers.rax = cpuid_result.eax as u64;
        registers.rbx = cpuid_result.ebx as u64;
        registers.rcx = cpuid_result.ecx as u64;
        registers.rdx = cpuid_result.edx as u64;

        log::info!("[+] CPUID handled!");
    }

    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: Table C-1. Basic Exit Reasons 31 and 32
    /// RDMSR. Guest software attempted to execute RDMSR and either:
    /// 1: The “use MSR bitmaps” VM-execution control was 0.
    /// 2: The value of RCX is neither in the range 00000000H – 00001FFFH nor in the range C0000000H – C0001FFFH.
    /// 3: The value of RCX was in the range 00000000H – 00001FFFH and the nth bit in read bitmap for low MSRs is 1, where n was the value of RCX
    /// 4: The value of RCX is in the range C0000000H – C0001FFFH and the nth bit in read bitmap for high MSRs is 1, where n is the value of RCX & 00001FFFH
    ///
    /// WRMSR. Guest software attempted to execute WRMSR and either:
    /// 1: The “use MSR bitmaps” VM-execution control was 0.
    /// 2: The value of RCX is neither in the range 00000000H – 00001FFFH nor in the range C0000000H – C0001FFFH
    /// 3: The value of RCX was in the range 00000000H – 00001FFFH and the nth bit in write bitmap for low MSRs is 1, where n was the value of RCX.
    /// 4: The value of RCX is in the range C0000000H – C0001FFFH and the nth bit in write bitmap for high MSRs is 1, where n is the value of RCX & 00001FFFH.
    fn handle_msr_access(&self, registers: &mut GuestRegisters, access_type: bool) {
        log::info!("[+] Handling Rdmsr/Wrmsr access...");

        const MSR_MASK_LOW: u64 = u32::MAX as u64;
        const RESERVED_MSR_RANGE_LOW: u64 = 0x40000000;
        const RESERVED_MSR_RANGE_HI: u64 = 0x400000FF;
        const MSR_READ: bool = true;
        const MSR_WRITE: bool = false;

        let msr_id = registers.rcx;

        // RESERVED_MSR_RANGE_LOW is the lower bound on a range of MSR IDs reserved for Hyper-V, they're referred to as Synthetic MSRs
        // Synthetic MSRs are not hardware MSRs, regardless of access type we're going to inject #GP into the guest.
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: RDMSR—Read From Model Specific Register and WRMSR—Write to Model Specific Register*/
        /*      - Protected Mode Exceptions */
        /*          - #GP(0) If the current privilege level is not 0. */
        /*          - If the value in ECX specifies a reserved or unimplemented MSR address */
        if msr_id >= RESERVED_MSR_RANGE_LOW && msr_id <= RESERVED_MSR_RANGE_HI {
            log::error!(
                "[!] Attempted to access Hyper-V reserved MSR: {:#x}",
                msr_id
            );
            self.vmentry_inject_gp(0);
            return;
        }

        if access_type == MSR_READ {
            let msr_value = unsafe { x86::msr::rdmsr(msr_id as _) };
            registers.rdx = msr_value >> 32;
            registers.rax = msr_value & MSR_MASK_LOW;
        } else if access_type == MSR_WRITE {
            let mut msr_value = registers.rdx << 32;
            msr_value |= (registers.rax) & MSR_MASK_LOW;
            unsafe { x86::msr::wrmsr(msr_id as _, msr_value) };
        }
    }

    /// Intel® 64 and IA-32 Architectures Software Developer's Manual:
    /// # Event Injection
    /// - 25.8.3 VM-Entry Controls for Event Injection
    /// - Table 25-17. Format of the VM-Entry Interruption-Information Field
    fn vmentry_inject_gp(&self, error_code: u32) {
        let gp_exception = EventInjection::general_protection();

        vmwrite(
            x86::vmx::vmcs::control::VMENTRY_EXCEPTION_ERR_CODE,
            error_code,
        );
        vmwrite(
            x86::vmx::vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
            gp_exception.0,
        );
        vmwrite(
            x86::vmx::vmcs::control::VMENTRY_INSTRUCTION_LEN,
            vmread(x86::vmx::vmcs::ro::VMEXIT_INSTRUCTION_LEN),
        );
    }

    fn advance_guest_rip(&self) {
        let mut rip = vmread(guest::RIP);
        let len = vmread(VMEXIT_INSTRUCTION_LEN);
        rip += len;
        vmwrite(guest::RIP, rip);
    }
}

/// The first parameter is a pointer to GuestRegisters that were just saved on the stack in reverse order.
/// Reverse order because when you push something on stack the last thing you push will be at the top of the stack
#[no_mangle]
pub unsafe extern "C" fn vmexit_handler(registers: *mut GuestRegisters) -> u16 {
    log::info!("[+] Called VMEXIT Handler...");
    let registers = unsafe { &mut *registers };

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

//vmwrite(host::RSP, host_rsp + STACK_CONTENTS_SIZE as u64);
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

/// Intel® 64 and IA-32 Architectures Software Developer's Manual: Table C-1. Basic Exit Reasons
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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

/// Intel® 64 and IA-32 Architectures Software Developer's Manual: Table C-1. Basic Exit Reasons
impl VmxBasicExitReason {
    /// Every VM exit writes a 32-bit exit reason to the VMCS (see Section 25.9.1). Certain VM-entry failures also do this (see Section 27.8).
    /// The low 16 bits of the exit-reason field form the basic exit reason which provides basic information about the cause of the VM exit or VM-entry failure.
    pub fn from_u32(value: u32) -> Option<Self> {
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

/// Intel® 64 and IA-32 Architectures Software Developer's Manual: Table C-1. Basic Exit Reasons
impl fmt::Display for VmxBasicExitReason {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let description = match *self {
            VmxBasicExitReason::ExceptionOrNmi => "Exception or non-maskable interrupt (NMI)",
            VmxBasicExitReason::ExternalInterrupt => "External interrupt",
            VmxBasicExitReason::TripleFault => "Triple fault",
            VmxBasicExitReason::InitSignal => "INIT signal",
            VmxBasicExitReason::StartupIpi => "Start-up IPI (SIPI)",
            VmxBasicExitReason::IoSystemManagementInterrupt => "I/O system-management interrupt (SMI)",
            VmxBasicExitReason::OtherSmi => "Other SMI",
            VmxBasicExitReason::InterruptWindow => "Interrupt window",
            VmxBasicExitReason::NmiWindow => "NMI window",
            VmxBasicExitReason::TaskSwitch => "Task switch",
            VmxBasicExitReason::Cpuid => "Guest software attempted to execute CPUID",
            VmxBasicExitReason::Getsec => "Guest software attempted to execute GETSEC",
            VmxBasicExitReason::Hlt => "Guest software attempted to execute HLT",
            VmxBasicExitReason::Invd => "Guest software attempted to execute INVD",
            VmxBasicExitReason::Invlpg => "Guest software attempted to execute INVLPG",
            VmxBasicExitReason::Rdpmc => "Guest software attempted to execute RDPMC",
            VmxBasicExitReason::Rdtsc => "Guest software attempted to execute RDTSC",
            VmxBasicExitReason::Rsm => "Guest software attempted to execute RSM in SMM",
            VmxBasicExitReason::Vmcall => "VMCALL was executed",
            VmxBasicExitReason::Vmclear => "Guest software attempted to execute VMCLEAR",
            VmxBasicExitReason::Vmlaunch => "Guest software attempted to execute VMLAUNCH",
            VmxBasicExitReason::Vmptrld => "Guest software attempted to execute VMPTRLD",
            VmxBasicExitReason::Vmptrst => "Guest software attempted to execute VMPTRST",
            VmxBasicExitReason::Vmread => "Guest software attempted to execute VMREAD",
            VmxBasicExitReason::Vmresume => "Guest software attempted to execute VMRESUME",
            VmxBasicExitReason::Vmwrite => "Guest software attempted to execute VMWRITE",
            VmxBasicExitReason::Vmxoff => "Guest software attempted to execute VMXOFF",
            VmxBasicExitReason::Vmxon => "Guest software attempted to execute VMXON",
            VmxBasicExitReason::ControlRegisterAccesses => "Control-register accesses",
            VmxBasicExitReason::MovDr => "Guest software attempted a MOV to or from a debug register",
            VmxBasicExitReason::IoInstruction => "Guest software attempted to execute an I/O instruction",
            VmxBasicExitReason::Rdmsr => "Guest software attempted to execute RDMSR",
            VmxBasicExitReason::Wrmsr => "Guest software attempted to execute WRMSR",
            VmxBasicExitReason::VmEntryFailureInvalidGuestState => "VM-entry failure due to invalid guest state",
            VmxBasicExitReason::VmEntryFailureMsrLoading => "VM-entry failure due to MSR loading",
            VmxBasicExitReason::Mwait => "Guest software attempted to execute MWAIT",
            VmxBasicExitReason::MonitorTrapFlag => "Monitor trap flag",
            VmxBasicExitReason::Monitor => "Guest software attempted to execute MONITOR",
            VmxBasicExitReason::Pause => "Either guest software attempted to execute PAUSE or the PAUSE-loop exiting VM-execution control was 1",
            VmxBasicExitReason::VmEntryFailureMachineCheckEvent => "VM-entry failure due to machine-check event",
            VmxBasicExitReason::TprBelowThreshold => "TPR below threshold",
            VmxBasicExitReason::ApicAccess => "APIC access",
            VmxBasicExitReason::VirtualizedEoi => "Virtualized EOI",
            VmxBasicExitReason::AccessToGdtrOrIdtr => "Access to GDTR or IDTR",
            VmxBasicExitReason::AccessToLdtrOrTr => "Access to LDTR or TR",
            VmxBasicExitReason::EptViolation => "EPT violation",
            VmxBasicExitReason::EptMisconfiguration => "EPT misconfiguration",
            VmxBasicExitReason::Invept => "Guest software attempted to execute INVEPT",
            VmxBasicExitReason::Rdtscp => "Guest software attempted to execute RDTSCP",
            VmxBasicExitReason::VmxPreemptionTimerExpired => "VMX-preemption timer expired",
            VmxBasicExitReason::Invvpid => "Guest software attempted to execute INVVPID",
            VmxBasicExitReason::WbinvdOrWbnoinvd => "Guest software attempted to execute WBINVD or WBNOINVD",
            VmxBasicExitReason::Xsetbv => "Guest software attempted to execute XSETBV",
            VmxBasicExitReason::ApicWrite => "APIC write",
            VmxBasicExitReason::Rdrand => "Guest software attempted to execute RDRAND",
            VmxBasicExitReason::Invpcid => "Guest software attempted to execute INVPCID",
            VmxBasicExitReason::Vmfunc => "Guest software invoked a VM function with the VMFUNC instruction",
            VmxBasicExitReason::Encls => "Guest software attempted to execute ENCLS",
            VmxBasicExitReason::Rdseed => "Guest software attempted to execute RDSEED",
            VmxBasicExitReason::PageModificationLogFull => "Page-modification log full",
            VmxBasicExitReason::Xsaves => "Guest software attempted to execute XSAVES",
            VmxBasicExitReason::Xrstors => "Guest software attempted to execute XRSTORS",
            VmxBasicExitReason::Pconfig => "Guest software attempted to execute PCONFIG",
            VmxBasicExitReason::SppRelatedEvent => "SPP-related event",
            VmxBasicExitReason::Umwait => "Guest software attempted to execute UMWAIT",
            VmxBasicExitReason::Tpause => "Guest software attempted to execute TPAUSE",
            VmxBasicExitReason::Loadiwkey => "Guest software attempted to execute LOADIWKEY",
            VmxBasicExitReason::Enclv => "Guest software attempted to execute ENCLV",
            VmxBasicExitReason::EnqcmdPasidTranslationFailure => "ENQCMD PASID translation failure",
            VmxBasicExitReason::EnqcmdsPasidTranslationFailure => "ENQCMDS PASID translation failure",
            VmxBasicExitReason::BusLock => "Bus lock",
            VmxBasicExitReason::InstructionTimeout => "Instruction timeout",
        };

        // Write both the discriminant (as a number) and the description to the formatter.
        write!(f, "{}: {}", *self as u16, description)
    }
}
