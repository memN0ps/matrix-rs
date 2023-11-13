//! Manages INVD VM exits to handle guest VM cache invalidation requests securely.

use crate::{
    intel::{vmexit::VmExit, vmlaunch::GuestRegisters},
    utils::instructions::wbinvd,
};

/// Manages the INVD instruction VM exit by logging the event, performing a controlled
/// cache invalidation, and advancing the guest's instruction pointer.
///
/// # Arguments
///
/// * `registers` - General-purpose registers of the guest VM at the VM exit.
pub fn handle_invd(_registers: &mut GuestRegisters) {
    log::info!("INVD instruction executed by guest VM");
    // Perform WBINVD to write back and invalidate the hypervisor's caches.
    // This ensures that any modified data is written to memory before cache lines are invalidated.
    wbinvd();
    // Advances the guest's instruction pointer to the next instruction to be executed.
    VmExit::advance_guest_rip();
}
