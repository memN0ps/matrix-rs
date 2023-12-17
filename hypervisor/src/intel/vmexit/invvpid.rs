use crate::intel::{invvpid::invvpid_all_contexts, vmexit::ExitType};

pub fn handle_invvpid() -> ExitType {
    invvpid_all_contexts();

    ExitType::IncrementRIP
}
