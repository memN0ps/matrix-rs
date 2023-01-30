extern crate alloc;
use alloc::boxed::Box;
use elain::Align;
use x86::current::paging::{PML4, PDPT, PD, PT, PML4Entry, PDPTEntry, PDEntry, PTEntry, PML4Flags};

use crate::addresses::physical_address;

// We will do this later
#[repr(C, align(4096))]
pub struct Ept {
    pub pml4: PML4,
    align_0: Align<4096>,

    pub pdp_entries: PDPT,
    align_1: Align<4096>,

    pub pd_entries: [PD; 512],
    align_2: Align<4096>,

    pub pt_entries: [[PT; 512]; 512],
}

impl Ept {
    // A feature that can be used to facilitate the virtualization of physical memory is the extended page-table mechanism (EPT).
    // and translates a guest’s physical address to a host’s physical address.
    // Specific addresses typically treated as physical addresses and used to access memory are treated as a guest's physical addresses when EPT is active.
    // To create physical addresses that can be utilised to access memory, a set of EPT paging structures are traversed to transform a guest's physical addresses.
    // EPT converts the physical address of a guest to that of a host.

    #[allow(dead_code)]
    fn empty() -> Self {
        Self {
            pml4: [PML4Entry(0); 512],
            align_0: Default::default(),
            pdp_entries: [PDPTEntry(0); 512],
            align_1: Default::default(),
            pd_entries: [[PDEntry(0); 512]; 512],
            align_2: Default::default(),
            pt_entries: [[[PTEntry(0); 512]; 512]; 512],
        }
    }

    #[allow(dead_code)]
    pub fn new() -> Box<Self> {
        let mut ept: Box<Ept> = Box::new(Self::empty());


        ept.pml4[0] = PML4Entry::new(
            physical_address(ept.pdp_entries.as_ptr() as _),
            PML4Flags::from_iter([PML4Flags::P, PML4Flags::RW, PML4Flags::US]),
        );

        ept
    }
}