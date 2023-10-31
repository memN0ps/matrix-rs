use {crate::intel::vmlaunch::GuestRegisters, x86::cpuid::cpuid};

/// CPUID leaf used to devirtualize a processor.
pub const CPUID_DEVIRTUALIZE: u32 = 0x4321_1234;

/// Handles the `CPUID` VM-exit.
///
/// This function is invoked when the guest executes the `CPUID` instruction.
/// The handler retrieves the results of the `CPUID` instruction executed on
/// the host and then modifies or masks certain bits, if necessary, before
/// returning the results to the guest.
///
/// # Arguments
///
/// * `registers` - A mutable reference to the guest's current register state.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual, Table C-1. Basic Exit Reasons 10.
pub fn handle_cpuid(registers: &mut GuestRegisters) {
    const VMX_BIT: u32 = 1 << 5; // Bit 5 of ECX for CPUID with EAX=1

    let leaf = registers.rax as u32;
    let sub_leaf = registers.rcx as u32;

    // Execute CPUID instruction on the host and retrieve the result
    let mut cpuid_result = cpuid!(leaf, sub_leaf);

    // If the guest checks for CPU features (leaf 1), mask the VT-x support bit to hide hypervisor presence
    if leaf == 1 {
        cpuid_result.ecx &= !VMX_BIT;
    }

    // Update the guest registers with the modified `CPUID` result
    registers.rax = cpuid_result.eax as u64;
    registers.rbx = cpuid_result.ebx as u64;
    registers.rcx = cpuid_result.ecx as u64;
    registers.rdx = cpuid_result.edx as u64;
}
