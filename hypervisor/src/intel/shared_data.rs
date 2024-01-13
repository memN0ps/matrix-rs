use {
    crate::{
        intel::{ept::paging::Ept, msr_bitmap::MsrBitmap},
        utils::{addresses::PhysicalAddress, alloc::PhysicalAllocator},
    },
    alloc::boxed::Box,
};

#[repr(C)]
pub struct SharedData {
    pub msr_bitmap: Box<MsrBitmap, PhysicalAllocator>,

    pub primary_ept: Box<Ept, PhysicalAllocator>,
    pub primary_pml4: PhysicalAddress,

    #[cfg(feature = "secondary-ept")]
    pub secondary_ept: Box<Ept, PhysicalAllocator>,
    #[cfg(feature = "secondary-ept")]
    pub secondary_pml4: PhysicalAddress,
}

impl SharedData {
    #[cfg(feature = "secondary-ept")]
    pub fn new(
        primary_ept: Box<Ept, PhysicalAllocator>,
        secondary_ept: Box<Ept, PhysicalAllocator>,
    ) -> Box<Self> {
        log::info!("Initializing shared data");

        let primary_pml4 = PhysicalAddress::from_va(primary_ept.pml4.as_ptr() as u64);
        let secondary_pml4 = PhysicalAddress::from_va(secondary_ept.pml4.as_ptr() as u64);

        let bitmap = MsrBitmap::new();
        //bitmap.hook_msr(IA32_EFER);

        Box::new(Self {
            msr_bitmap: { bitmap },

            primary_ept,
            primary_pml4,

            secondary_ept,
            secondary_pml4,
        })
    }

    #[cfg(not(feature = "secondary-ept"))]
    pub fn new(primary_ept: Box<Ept, PhysicalAllocator>) -> Option<Box<Self>> {
        log::info!("Initializing shared data");

        let primary_pml4 = PhysicalAddress::from_va(primary_ept.pml4.as_ptr() as u64);

        let bitmap = MsrBitmap::new();

        //bitmap.hook_msr(IA32_EFER);

        Some(Box::new(Self {
            msr_bitmap: { bitmap },

            primary_ept,
            primary_pml4,
        }))
    }
}
