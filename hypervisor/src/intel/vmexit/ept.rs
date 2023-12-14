use {
    crate::{
        error::HypervisorError,
        intel::{support::vmread, vmerror::EptViolationExitQualification, vmexit::ExitType},
        utils::{capture::GuestRegisters, addresses::PhysicalAddress},
    },
    x86::vmx::vmcs,
};

/// Handle VM exits for EPT violations. Violations are thrown whenever an operation is performed on an EPT entry that does not provide permissions to access that page.
/// 29.3.3.2 EPT Violations
/// Table 28-7. Exit Qualification for EPT Violations
#[rustfmt::skip]
pub fn handle_ept_violation(_guest_registers: &mut GuestRegisters) -> ExitType {
    let guest_physical_address = vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);
    log::info!("EPT Violation: Guest Physical Address: {:#x}", guest_physical_address);

    let exit_qualification_value = vmread(vmcs::ro::EXIT_QUALIFICATION);

    // Create an instance of EptViolationExitQualification from the raw exit qualification value
    let ept_violation_qualification = EptViolationExitQualification::from_exit_qualification(exit_qualification_value);

    // Log the detailed information about the EPT violation
    log::info!("Exit Qualification for EPT Violations: {}", ept_violation_qualification);

    unsafe {
        core::arch::asm!("int3");
    }

    let exit_type = match ept_handle_page_hook_exit(exit_qualification_value, guest_physical_address) {
        Ok(_) => ExitType::IncrementRIP,
        Err(e) => {
            log::error!("Error handling page hook exit: {}", e);
            ExitType::ExitHypervisor
        }
    };

    exit_type
}

#[rustfmt::skip]
fn ept_handle_page_hook_exit(exit_qualification: u64, guest_physical_address: u64) -> Result<(), HypervisorError> {
    // Translate the page from a physical address to virtual so we can read its memory.
    let va = PhysicalAddress::va_from_pa(guest_physical_address);
    log::info!("EPT Violation: Guest Virtual Address: {:#x}", va);

    Ok(())
}

/// Handles an EPT misconfiguration VM exit.
///
/// This function is invoked when an EPT misconfiguration VM exit occurs, indicating
/// an issue with the Extended Page Tables (EPT) setup. It logs the faulting
/// guest physical address and triggers a breakpoint exception for immediate debugging.
///
/// # Safety
///
/// This function executes an `int3` instruction, which triggers a breakpoint exception.
/// This is used for debugging critical issues and should be employed cautiously.
/// Appropriate debugging tools must be attached to handle the `int3` exception.
///
/// Note: EPT misconfigurations are critical errors that can lead to system instability or crashes.
/// Continuing normal execution after such an exception is not recommended, as it may result in
/// unpredictable behavior or a crashed operating system.
///
/// Reference: 29.3.3.1 EPT Misconfigurations
#[rustfmt::skip]
pub fn handle_ept_misconfiguration() -> ExitType {
    // Retrieve the guest physical address that caused the EPT misconfiguration.
    let guest_physical_address = vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);

    // Log the critical error information.
    log::info!("EPT Misconfiguration: Faulting guest address: {:#x}. This is a critical error that cannot be safely ignored.", guest_physical_address);

    // Trigger a breakpoint exception to halt execution for debugging.
    // Continuing after this point is unsafe due to the potential for system instability.
    unsafe {  core::arch::asm!("int3") };

    // Execution should not continue beyond this point.
    // EPT misconfiguration is a fatal exception and continuing may lead to system crashes.

    // We may chose to exit the hypervisor here instead of triggering a breakpoint exception.
    return ExitType::ExitHypervisor;
}
