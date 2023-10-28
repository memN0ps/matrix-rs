use {
    super::{
        events::EventInjection, support::vmwrite, vmerror::VmxBasicExitReason,
        vmlaunch::GuestRegisters,
    },
    crate::{
        error::HypervisorError,
        intel::{support::vmread, vmerror::VmInstructionError},
    },
    x86::vmx::vmcs::{self, guest, ro::VMEXIT_INSTRUCTION_LEN},
};

// More leafs here if needed: https://docs.rs/raw-cpuid/10.6.0/src/raw_cpuid/lib.rs.html#289
pub const EAX_HYPERVISOR_PRESENT: u32 = 0x1;

pub enum MsrAccessType {
    Read,
    Write,
}

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
        //println!("VMEXIT occurred at RIP: {:#x}", vmread(guest::RIP));
        //println!("VMEXIT occurred at RSP: {:#x}", vmread(guest::RSP));

        // Every VM exit writes a 32-bit exit reason to the VMCS (see Section 25.9.1). Certain VM-entry failures also do this (see Section 27.8).
        // The low 16 bits of the exit-reason field form the basic exit reason which provides basic information about the cause of the VM exit or VM-entry failure.
        let exit_reason = vmread(vmcs::ro::EXIT_REASON) as u32;

        let Some(basic_exit_reason) = VmxBasicExitReason::from_u32(exit_reason) else {
            //println!("Unknown exit reason: {:#x}", exit_reason);
            return Err(HypervisorError::UnknownVMExitReason);
        };
        //println!("Basic Exit Reason: {}", basic_exit_reason);

        let instruction_error = vmread(vmcs::ro::VM_INSTRUCTION_ERROR) as u32;

        let Some(_error) = VmInstructionError::from_u32(instruction_error) else {
            //println!("Unknown instruction error: {:#x}", instruction_error);
            return Err(HypervisorError::UnknownVMInstructionError);
        };
        //println!("VM Instruction Error: {}", error);

        /* Handle VMEXIT */
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 26.1.2 Instructions That Cause VM Exits Unconditionally */
        /* - The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC, INVD, and XSETBV. */
        /* - This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID, VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON. */
        /* Intel® 64 and IA-32 Architectures Software Developer's Manual: 26.1.3 Instructions That Cause VM Exits Conditionally */
        /* - Certain instructions cause VM exits in VMX non-root operation depending on the setting of the VM-execution controls.*/
        match basic_exit_reason {
            VmxBasicExitReason::Cpuid => self.handle_cpuid(registers),
            VmxBasicExitReason::Rdmsr => self.handle_msr_access(registers, MsrAccessType::Read),
            VmxBasicExitReason::Wrmsr => self.handle_msr_access(registers, MsrAccessType::Write),
            _ => panic!("Unhandled VMEXIT: {}", basic_exit_reason),
        }

        //println!("Advancing guest RIP...");
        self.advance_guest_rip();
        //println!("Guest RIP advanced to: {:#x}", vmread(guest::RIP));

        //println!("VMEXIT handled successfully.");

        return Ok(basic_exit_reason);
    }

    /// The CPUID (processor identification) instruction returns information about the processor on which the instruction is executed.
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: Table C-1. Basic Exit Reasons 10
    /// CPUID. Guest software attempted to execute CPUID.
    fn handle_cpuid(&self, registers: &mut GuestRegisters) {
        let leaf = registers.rax as u32;
        let sub_leaf = registers.rcx as u32;

        // First parameter is cpuid leaf (EAX register value), second optional parameter is the subleaf (ECX register value).
        let cpuid_result = x86::cpuid::cpuid!(leaf, sub_leaf);

        /* Uncomment later if needed
        if leaf == EAX_HYPERVISOR_PRESENT {
            // Clearing VT-x Support: If the leaf value is 1 (which corresponds to the standard CPUID function that returns feature information),
            // We clear bit 5 in the ECX register, which is used to indicate support for VT-x (Virtualization Technology),
            // to prevent the guest from recognizing VT-x support and attempting to use it.
            cpuid_result.ecx &= !(1 << 5);
        }
        */

        // Update the Guest registers with cpuid result
        registers.rax = cpuid_result.eax as u64;
        registers.rbx = cpuid_result.ebx as u64;
        registers.rcx = cpuid_result.ecx as u64;
        registers.rdx = cpuid_result.edx as u64;
    }

    /// Intel® 64 and IA-32 Architectures Software Developer's Manual: Table C-1. Basic Exit Reasons 31 and 32
    /// RDMSR. Guest software attempted to execute RDMSR and either / WRMSR. Guest software attempted to execute WRMSR and either:
    /// 1: The “use MSR bitmaps” VM-execution control was 0.
    /// 2: The value of RCX is neither in the range 00000000H – 00001FFFH nor in the range C0000000H – C0001FFFH.
    /// 3: The value of RCX was in the range 00000000H – 00001FFFH and the nth bit in read bitmap for low MSRs is 1, where n was the value of RCX
    /// 4: The value of RCX is in the range C0000000H – C0001FFFH and the nth bit in read bitmap for high MSRs is 1, where n is the value of RCX & 00001FFFH
    fn handle_msr_access(&self, registers: &mut GuestRegisters, access_type: MsrAccessType) {
        const MSR_MASK_LOW: u64 = u32::MAX as u64;
        //const MSR_RANGE_LOW_START: u64 = 0x00000000;
        const MSR_RANGE_LOW_END: u64 = 0x00001FFF;
        const MSR_RANGE_HIGH_START: u64 = 0xC0000000;
        const MSR_RANGE_HIGH_END: u64 = 0xC0001FFF;

        const RESERVED_MSR_RANGE_LOW: u64 = 0x40000000;
        const RESERVED_MSR_RANGE_HI: u64 = 0x400000FF;

        let msr_id = registers.rcx;

        // Intel® 64 and IA-32 Architectures Software Developer's Manual: RDMSR—Read From Model Specific Register / WRMSR—Write to Model Specific Register
        // - Protected Mode Exceptions
        // - #GP(0) If the current privilege level is not 0
        // - If the value in ECX specifies a reserved or unimplemented MSR address
        // Check for reserved or unimplemented MSR address

        /* (This causes a problem and in Windbg it says "Shutdown occurred")
        if msr_id >= RESERVED_MSR_RANGE_LOW && msr_id <= RESERVED_MSR_RANGE_HI {
            self.vmentry_inject_gp(0);
            return;
        }
        */

        // Check for sanity of MSR if they're valid or they're for reserved range for WRMSR and RDMSR
        if (msr_id <= MSR_RANGE_LOW_END)
            || ((msr_id >= MSR_RANGE_HIGH_START) && (msr_id <= MSR_RANGE_HIGH_END))
            || (msr_id >= RESERVED_MSR_RANGE_LOW && msr_id <= RESERVED_MSR_RANGE_HI)
        {
            match access_type {
                MsrAccessType::Read => {
                    let msr_value = unsafe { x86::msr::rdmsr(msr_id as _) };
                    registers.rdx = msr_value >> 32;
                    registers.rax = msr_value & MSR_MASK_LOW;
                }
                MsrAccessType::Write => {
                    let mut msr_value = registers.rdx << 32;
                    msr_value |= registers.rax & MSR_MASK_LOW;
                    unsafe { x86::msr::wrmsr(msr_id as _, msr_value) };
                }
            }
        }
    }

    /// Intel® 64 and IA-32 Architectures Software Developer's Manual:
    /// # Event Injection
    /// - 25.8.3 VM-Entry Controls for Event Injection
    /// - Table 25-17. Format of the VM-Entry Interruption-Information Field
    #[allow(dead_code)]
    fn vmentry_inject_gp(&self, error_code: u32) {
        vmwrite(
            x86::vmx::vmcs::control::VMENTRY_EXCEPTION_ERR_CODE,
            error_code,
        );
        vmwrite(
            x86::vmx::vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
            EventInjection::general_protection(),
        );
        vmwrite(
            x86::vmx::vmcs::control::VMENTRY_INSTRUCTION_LEN,
            vmread(x86::vmx::vmcs::ro::VMEXIT_INSTRUCTION_LEN),
        );
    }

    /// Advances the guest's instruction pointer (RIP) after a VM exit.
    ///
    /// When a VM exit occurs, the guest's execution is interrupted, and control is transferred
    /// to the hypervisor. To ensure that the guest does not re-execute the instruction that
    /// caused the VM exit (which would lead to another VM exit), the hypervisor needs to advance
    /// the guest's RIP to the next instruction. This function reads the length of the instruction
    /// that caused the VM exit and updates the guest's RIP accordingly, ensuring smooth
    /// continuation of the guest's execution.
    fn advance_guest_rip(&self) {
        let mut rip = vmread(guest::RIP);
        let len = vmread(VMEXIT_INSTRUCTION_LEN);
        rip += len;
        vmwrite(guest::RIP, rip);
    }
}
