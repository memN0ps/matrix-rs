//! A crate for managing hypervisor functionality, particularly focused on
//! Extended Page Tables (EPT) and Model-Specific Register (MSR) bitmaps.
//! Includes support for primary and optional secondary EPTs.

use {
    crate::{
        error::HypervisorError,
        intel::{
            ept::{hooks::HookManager, paging::Ept},
            msr_bitmap::MsrBitmap,
        },
        utils::alloc::PhysicalAllocator,
    },
    alloc::boxed::Box,
};

/// Represents shared data structures for hypervisor operations.
///
/// This struct manages the MSR (Model-Specific Register) bitmap and Extended Page Tables (EPT)
/// for the hypervisor, enabling memory virtualization and control over certain processor features.
#[repr(C)]
pub struct SharedData {
    /// A bitmap for handling MSRs.
    pub msr_bitmap: Box<MsrBitmap, PhysicalAllocator>,

    /// The primary Extended Page Table.
    pub primary_ept: Box<Ept, PhysicalAllocator>,

    /// The pointer to the primary EPT (Extended Page Table Pointer).
    pub primary_eptp: u64,

    /// The secondary Extended Page Table.
    #[cfg(feature = "secondary-ept")]
    pub secondary_ept: Box<Ept, PhysicalAllocator>,

    /// The pointer to the secondary EPT.
    #[cfg(feature = "secondary-ept")]
    pub secondary_eptp: u64,

    /// The hook manager.
    pub hook_manager: Box<HookManager>,
}

impl SharedData {
    /// Creates a new instance of `SharedData` with primary and optionally secondary EPTs.
    ///
    /// This function initializes the MSR bitmap and sets up the EPTs.
    ///
    /// # Arguments
    ///
    /// * `primary_ept`: The primary EPT to be used.
    /// * `secondary_ept`: The secondary EPT to be used if the feature is enabled.
    ///
    /// # Returns
    /// A result containing a boxed `SharedData` instance or an error of type `HypervisorError`.
    #[cfg(feature = "secondary-ept")]
    pub fn new(
        primary_ept: Box<Ept, PhysicalAllocator>,
        secondary_ept: Box<Ept, PhysicalAllocator>,
        hook_manager: Box<HookManager>,
    ) -> Result<Box<Self>, HypervisorError> {
        log::trace!("Initializing shared data");

        let primary_eptp = primary_ept.create_eptp_with_wb_and_4lvl_walk()?;
        let secondary_eptp = secondary_ept.create_eptp_with_wb_and_4lvl_walk()?;

        let bitmap = MsrBitmap::new();
        //bitmap.hook_msr(IA32_EFER);

        Ok(Box::new(Self {
            msr_bitmap: { bitmap },
            primary_ept,
            primary_eptp,
            secondary_ept,
            secondary_eptp,
            hook_manager,
        }))
    }

    /// Creates a new instance of `SharedData` with primary EPTs.
    ///
    /// This function initializes the MSR bitmap and sets up the EPTs.
    ///
    /// # Arguments
    ///
    /// * `primary_ept`: The primary EPT to be used.
    ///
    /// # Returns
    /// A result containing a boxed `SharedData` instance or an error of type `HypervisorError`.
    #[cfg(not(feature = "secondary-ept"))]
    pub fn new(
        primary_ept: Box<Ept, PhysicalAllocator>,
        hook_manager: Box<HookManager>,
    ) -> Result<Option<Box<Self>>, HypervisorError> {
        log::trace!("Initializing shared data");

        let primary_eptp = primary_ept.create_eptp_with_wb_and_4lvl_walk()?;

        let bitmap = MsrBitmap::new();
        //bitmap.hook_msr(IA32_EFER);

        Ok(Some(Box::new(Self {
            msr_bitmap: { bitmap },
            primary_ept,
            primary_eptp,
            hook_manager,
        })))
    }
}
