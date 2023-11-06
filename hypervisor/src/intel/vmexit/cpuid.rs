//! Handles CPU-related virtualization tasks, specifically intercepting and managing
//! the `CPUID` instruction in a VM to control the exposure of CPU features to the guest.

#![allow(dead_code)]

use {crate::intel::vmlaunch::GuestRegisters, bitfield::BitMut, x86::cpuid::cpuid};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// Enum representing the various CPUID leaves for feature and interface discovery.
/// Reference: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
enum CpuidLeaf {
    /// CPUID function number to retrieve the processor's vendor identification string.
    VendorInfo = 0x0,
    /// CPUID function for feature information, including hypervisor presence.
    FeatureInformation = 0x1,
    /// Hypervisor vendor information leaf.
    HypervisorVendor = 0x40000000,
    /// Hypervisor interface identification leaf.
    HypervisorInterface = 0x40000001,
    /// Hypervisor system identity information leaf.
    HypervisorSystemIdentity = 0x40000002,
    /// Hypervisor feature identification leaf.
    HypervisorFeatureIdentification = 0x40000003,
    /// Hypervisor implementation recommendations leaf.
    ImplementationRecommendations = 0x40000004,
    /// Hypervisor implementation limits leaf.
    HypervisorImplementationLimits = 0x40000005,
    /// Hardware-specific features in use by the hypervisor leaf.
    ImplementationHardwareFeatures = 0x40000006,
    /// Nested hypervisor feature identification leaf.
    NestedHypervisorFeatureIdentification = 0x40000009,
    /// Nested virtualization features available leaf.
    HypervisorNestedVirtualizationFeatures = 0x4000000A,
}

/// Enumerates specific feature bits in the ECX register for CPUID instruction results.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum FeatureBits {
    /// Bit 5 of ECX for CPUID with EAX=1, indicating VMX support.
    HypervisorVmxSupportBit = 5,
    /// Bit 31 of ECX for CPUID with EAX=1, indicating hypervisor presence.
    HypervisorPresentBit = 31,
}

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
#[rustfmt::skip]
pub fn handle_cpuid(registers: &mut GuestRegisters) {
    let leaf = registers.rax as u32;
    let sub_leaf = registers.rcx as u32;

    // Execute CPUID instruction on the host and retrieve the result
    let mut cpuid_result = cpuid!(leaf, sub_leaf);

    log::info!("Leaf: {:#x} Sub-leaf: {:#x}", leaf, sub_leaf);

    if leaf == CpuidLeaf::FeatureInformation as u32 {
        // Hides hypervisor by clearing VMX support and hypervisor present bits in CPU features by overriding CPUID.1H.ECX[Bit 5] and CPUID.1H.ECX[Bit 31] with 0.
        cpuid_result.ecx.set_bit(FeatureBits::HypervisorVmxSupportBit as usize, false);
        cpuid_result.ecx.set_bit(FeatureBits::HypervisorPresentBit as usize, false);
    } else if leaf == CpuidLeaf::HypervisorInterface as u32 {
        // Obscures hypervisor identity by zeroing out Hypervisor Interface CPUID signature by overriding CPUID.40000001H.EAX with anything but "Hv#1"
        cpuid_result.eax = 0;
    }

    // Update the guest registers with the modified `CPUID` result
    registers.rax = cpuid_result.eax as u64;
    registers.rbx = cpuid_result.ebx as u64;
    registers.rcx = cpuid_result.ecx as u64;
    registers.rdx = cpuid_result.edx as u64;

    log::info!("CPUID: RAX: {:#x} RBX: {:#x} RCX: {:#x} RDX: {:#x}", registers.rax, registers.rbx, registers.rcx, registers.rdx);
}
