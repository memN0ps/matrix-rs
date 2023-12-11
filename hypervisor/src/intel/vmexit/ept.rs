use crate::intel::support::vmread;
use crate::intel::vmexit::ExitType;
use crate::utils::capture::GuestRegisters;
use x86::vmx::vmcs;

/// Handle VM exits for EPT violations. Violations are thrown whenever an operation is performed on an EPT entry that does not provide permissions to access that page.
pub fn handle_ept_violation(_guest_registers: &mut GuestRegisters) -> ExitType {
    let guest_physical_address = vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);
    log::info!(
        "EPT Violation: Guest Physical Address: {:#x}",
        guest_physical_address
    );

    let exit_qualification = vmread(vmcs::ro::EXIT_QUALIFICATION);
    log::info!(
        "EPT Violation: Exit Qualification: {:#x}",
        exit_qualification
    );

    //ept_handle_page_hook_exit(exit_qualification, guest_physical_address);

    ExitType::IncrementRIP
}

/*
fn ept_handle_page_hook_exit(exit_qualification: u64, guest_physical_address: u64) -> bool {

    return true;
}
*/

pub fn handle_ept_misconfiguration(_guest_registers: &mut GuestRegisters) -> ExitType {
    log::info!("EPT Misconfiguration");
    ExitType::IncrementRIP
}
