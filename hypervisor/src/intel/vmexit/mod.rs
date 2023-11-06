//! A module providing utilities and structures for handling VM exits.
//!
//! This module focuses on the reasons for VM exits, VM instruction errors, and the associated handlers for each exit type.
//! The handlers interpret and respond to different VM exit reasons, ensuring the safe and correct execution of the virtual machine.

use {
    super::{support::vmwrite, vmerror::VmxBasicExitReason},
    crate::{
        error::HypervisorError,
        intel::{
            support::vmread,
            vmexit::{
                cpuid::handle_cpuid,
                msr::{handle_msr_access, MsrAccessType},
            },
            vmlaunch::GuestRegisters,
        },
    },
    x86::vmx::vmcs::{guest, ro},
};

pub mod cpuid;
pub mod msr;

/// Represents a VM exit, which can be caused by various reasons.
///
/// A VM exit transfers control from the guest to the host (hypervisor).
/// The `VmExit` structure provides methods to handle various VM exit reasons and ensures the correct and safe continuation of the guest's execution.
pub struct VmExit;

impl VmExit {
    pub fn new() -> Self {
        Self
    }

    /// Handles the VM-exit.
    ///
    /// This function interprets the VM exit reason and invokes the appropriate handler based on the exit type.
    ///
    /// # Arguments
    ///
    /// * `registers` - A mutable reference to the guest's current register state.
    ///
    /// # Returns
    ///
    /// A result containing the VM exit reason if the handling was successful or an error if the VM exit reason is unknown or unsupported.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.9 VM-EXIT INFORMATION FIELDS
    /// - APPENDIX C VMX BASIC EXIT REASONS
    /// - Table C-1. Basic Exit Reasons
    pub fn handle_vmexit(&self, registers: &mut GuestRegisters) -> Result<(), HypervisorError> {
        let exit_reason = vmread(ro::EXIT_REASON) as u32;

        let Some(basic_exit_reason) = VmxBasicExitReason::from_u32(exit_reason) else {
            log::info!("Unknown exit reason: {:#x}", exit_reason);
            return Err(HypervisorError::UnknownVMExitReason);
        };
        log::info!("Basic Exit Reason: {}", basic_exit_reason);

        // Handle VMEXIT
        // Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 26.1.2 Instructions That Cause VM Exits Unconditionally:
        // - The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC, INVD, and XSETBV.
        // - This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID, VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
        //
        // 26.1.3 Instructions That Cause VM Exits Conditionally: Certain instructions cause VM exits in VMX non-root operation depending on the setting of the VM-execution controls.
        match basic_exit_reason {
            VmxBasicExitReason::Cpuid => handle_cpuid(registers),
            VmxBasicExitReason::Rdmsr => handle_msr_access(registers, MsrAccessType::Read),
            VmxBasicExitReason::Wrmsr => handle_msr_access(registers, MsrAccessType::Write),
            _ => return Err(HypervisorError::UnhandledVmExit),
        };

        log::info!("Advancing guest RIP...");
        Self::advance_guest_rip(registers);
        log::info!("Guest RIP advanced to: {:#x}", vmread(guest::RIP));

        log::info!("VMEXIT handled successfully.");

        return Ok(());
    }

    /// Advances the guest's instruction pointer (RIP) after a VM exit.
    ///
    /// When a VM exit occurs, the guest's execution is interrupted, and control is transferred
    /// to the hypervisor. To ensure that the guest does not re-execute the instruction that
    /// caused the VM exit, the hypervisor needs to advance the guest's RIP to the next instruction.
    #[rustfmt::skip]
    fn advance_guest_rip(registers: &mut GuestRegisters) {
        let len = vmread(ro::VMEXIT_INSTRUCTION_LEN);
        registers.rip += len;
        vmwrite(guest::RIP, registers.rip);
    }
}
