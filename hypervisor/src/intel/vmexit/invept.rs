use crate::intel::{invept::invept_all_contexts, vmexit::ExitType};

pub fn handle_invept() -> ExitType {
    invept_all_contexts();

    ExitType::IncrementRIP
}
