use crate::intel::ept::paging::{Entry, Pt};

#[repr(C, align(4096))]
pub struct PageTableBuffer {
    /// Page Table (PT).
    pml1: Pt,
}

impl PageTableBuffer {
    /// Returns a mutable reference to the PT entries.
    pub fn entries_mut(&mut self) -> &mut [Entry; 512] {
        &mut self.pml1.0.entries
    }
}
