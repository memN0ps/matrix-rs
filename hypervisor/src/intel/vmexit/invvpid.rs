//! Manages VM exits related to Virtual Processor Identifier (VPID) operations in Intel VT-x technology.

use crate::intel::{invvpid::invvpid_all_contexts, vmexit::ExitType};

/// Handles the INVVPID VM exit.
///
/// Invalidates all VPID contexts and increments the VM's instruction pointer.
///
/// # Returns
///
/// * `ExitType::IncrementRIP` - Advances past the `INVVPID` instruction in the VM.
pub fn handle_invvpid() -> ExitType {
    // Invalidate all VPID contexts to ensure consistency of TLB entries with the current VM state.
    invvpid_all_contexts();

    // Indicate to increment the VM's instruction pointer post handling.
    ExitType::IncrementRIP
}
