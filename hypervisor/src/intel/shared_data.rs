use {
    crate::{
        intel::{ept::paging::Ept, msr_bitmap::MsrBitmap},
        utils::alloc::PhysicalAllocator,
    },
    alloc::boxed::Box,
};

#[repr(C)]
pub struct SharedData {
    pub msr_bitmap: Box<MsrBitmap, PhysicalAllocator>,

    pub primary_ept: Box<Ept, PhysicalAllocator>,

    #[cfg(feature = "secondary-ept")]
    pub secondary_ept: Box<Ept, PhysicalAllocator>,
}

impl SharedData {
    #[cfg(feature = "secondary-ept")]
    pub fn new(
        primary_ept: Box<Ept, PhysicalAllocator>,
        secondary_ept: Box<Ept, PhysicalAllocator>,
    ) -> Box<Self> {
        log::info!("Initializing shared data");

        let bitmap = MsrBitmap::new();
        //bitmap.hook_msr(IA32_EFER);

        Box::new(Self {
            msr_bitmap: { bitmap },
            primary_ept,
            secondary_ept,
        })
    }

    #[cfg(not(feature = "secondary-ept"))]
    pub fn new(primary_ept: Box<Ept, PhysicalAllocator>) -> Option<Box<Self>> {
        log::info!("Initializing shared data");
        let bitmap = MsrBitmap::new();
        //bitmap.hook_msr(IA32_EFER);

        Some(Box::new(Self {
            msr_bitmap: { bitmap },
            primary_ept,
        }))
    }
}
