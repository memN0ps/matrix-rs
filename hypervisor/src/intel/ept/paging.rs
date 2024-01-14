//! Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3 THE EXTENDED PAGE TABLE MECHANISM (EPT)
//! The extended page-table mechanism (EPT) is a feature that can be used to support the virtualization of physical memory.
//! When EPT is in use, certain addresses that would normally be treated as physical addresses (and used to access memory) are instead treated as guest-physical addresses
//! Guest-physical addresses are translated by traversing a set of EPT paging structures to produce physical addresses that are used to access memory.
//!
//! Credits to the work by Satoshi in their 'Hello-VT-rp' project for assistance and a clear implementation of EPT:
//! https://github.com/tandasat/Hello-VT-rp/blob/main/hypervisor/src/intel_vt/epts.rs

use {
    crate::{
        error::HypervisorError,
        intel::ept::mtrr::{MemoryType, Mtrr},
        utils::addresses::PhysicalAddress,
    },
    bitfield::bitfield,
    bitflags::bitflags,
    core::ptr::addr_of,
    x86::current::paging::{BASE_PAGE_SHIFT, BASE_PAGE_SIZE, LARGE_PAGE_SIZE},
};

bitflags! {
    /// Represents the different access permissions for an EPT entry.
    #[derive(Debug, Clone, Copy)]
    pub struct Access: u8 {
        const READ = 0b001;
        const WRITE = 0b010;
        const EXECUTE = 0b100;
        const READ_WRITE = Self::READ.bits() | Self::WRITE.bits();
        const READ_EXECUTE = Self::READ.bits() | Self::EXECUTE.bits();
        const WRITE_EXECUTE = Self::WRITE.bits() | Self::EXECUTE.bits();
        const READ_WRITE_EXECUTE = Self::READ.bits() | Self::WRITE.bits() | Self::EXECUTE.bits();
    }
}

/// Represents the entire Extended Page Table structure.
///
/// EPT is a set of nested page tables similar to the standard x86-64 paging mechanism.
/// It consists of 4 levels: PML4, PDPT, PD, and PT.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3.2 EPT Translation Mechanism
#[repr(C, align(4096))]
pub struct Ept {
    /// Page Map Level 4 (PML4) Table.
    pml4: Pml4,
    /// Page Directory Pointer Table (PDPT).
    pdpt: Pdpt,
    /// Array of Page Directory Table (PDT).
    pd: [Pd; 512],
    /// Page Table (PT).
    pt: Pt,
}

impl Ept {
    /// Builds an identity map for the Extended Page Table (EPT).
    ///
    /// This method sets up the EPT such that each guest-physical address
    /// maps directly to the same host-physical address. It also configures
    /// memory types based on the current MTRR (Memory Type Range Register) settings.
    ///
    /// # Returns
    /// A `Result<(), HypervisorError>` indicating whether the identity map was built successfully.
    pub fn build_identity_map(&mut self) -> Result<(), HypervisorError> {
        log::info!("Building identity map for EPT");
        // Retrieve the current MTRR settings.
        // This map is used to determine memory types for each physical address.
        let mut mtrr = Mtrr::new();

        // Initialize the physical address to start mapping from.
        let mut pa = 0u64;

        // Configure the first PML4 entry.
        // The PML4 is the top-level structure in the paging hierarchy.
        self.pml4.0.entries[0].set_readable(true);
        self.pml4.0.entries[0].set_writable(true);
        self.pml4.0.entries[0].set_executable(true);
        self.pml4.0.entries[0]
            .set_pfn(PhysicalAddress::pa_from_va(addr_of!(self.pdpt) as u64) >> BASE_PAGE_SHIFT);

        // Iterate over all PDPT entries to configure them.
        for (i, pml3e) in self.pdpt.0.entries.iter_mut().enumerate() {
            // Configure the PDPT entry.
            pml3e.set_readable(true);
            pml3e.set_writable(true);
            pml3e.set_executable(true);
            pml3e.set_pfn(
                PhysicalAddress::pa_from_va(addr_of!(self.pd[i]) as u64) >> BASE_PAGE_SHIFT,
            );

            // Configure each PDE within the current PD.
            for pml2e in &mut self.pd[i].0.entries {
                if pa == 0 {
                    // Special handling for the first PDE.
                    // This is typically where the first PT is set up.
                    pml2e.set_readable(true);
                    pml2e.set_writable(true);
                    pml2e.set_executable(true);
                    pml2e.set_pfn(
                        PhysicalAddress::pa_from_va(addr_of!(self.pt) as u64) >> BASE_PAGE_SHIFT,
                    );

                    // Iterate over all PTEs within the first PT.
                    for pml1e in &mut self.pt.0.entries {
                        // Determine the memory type for the current address.
                        let memory_type = mtrr
                            .find(pa..pa + BASE_PAGE_SIZE as u64)
                            .ok_or(HypervisorError::MemoryTypeResolutionError)?;

                        // Configure the PTE.
                        pml1e.set_readable(true);
                        pml1e.set_writable(true);
                        pml1e.set_executable(true);
                        pml1e.set_memory_type(memory_type as u64);
                        pml1e.set_pfn(pa >> BASE_PAGE_SHIFT);

                        // Move to the next page.
                        pa += BASE_PAGE_SIZE as u64;
                    }
                } else {
                    // Handling for subsequent PDEs.
                    // Configure large pages if used.
                    let memory_type = mtrr
                        .find(pa..pa + LARGE_PAGE_SIZE as u64)
                        .ok_or(HypervisorError::MemoryTypeResolutionError)?;

                    pml2e.set_readable(true);
                    pml2e.set_writable(true);
                    pml2e.set_executable(true);
                    pml2e.set_memory_type(memory_type as u64);
                    pml2e.set_large(true);
                    pml2e.set_pfn(pa >> BASE_PAGE_SHIFT);

                    // Move to the next large page.
                    pa += LARGE_PAGE_SIZE as u64;
                }
            }
        }

        log::info!("Identity map for EPT built successfully!");

        Ok(())
    }

    /// Finds the PML1 entry for a given guest physical address.
    ///
    /// # Arguments
    /// * `guest_phys_addr` - The guest physical address for which to find the PML1 entry.
    ///
    /// # Returns
    /// A `Result<*mut Entry, HypervisorError>` which is a mutable pointer to the PML1 entry or an error.
    pub fn find_pml1_entry(&self, guest_phys_addr: u64) -> Result<*mut Entry, HypervisorError> {
        // Calculate indexes for PML4, PML3, PML2, and PML1 based on the guest physical address.
        let pml4_index = (guest_phys_addr >> 39) & 0x1FF;
        let pml3_index = (guest_phys_addr >> 30) & 0x1FF;
        let pml2_index = (guest_phys_addr >> 21) & 0x1FF;
        let pml1_index = (guest_phys_addr >> 12) & 0x1FF;

        // Navigate the EPT structure to reach the PML1 entry.
        let pml4_entry = &self.pml4.0.entries[pml4_index as usize];
        if !pml4_entry.readable() {
            return Err(HypervisorError::InvalidPml4Entry);
        }

        let pml3_pa = pml4_entry.pfn() << BASE_PAGE_SHIFT;
        let pml3_va = PhysicalAddress::va_from_pa(pml3_pa) as *const Entry;
        let pml3_entry = unsafe { &*pml3_va.add(pml3_index as usize) };
        if !pml3_entry.readable() {
            return Err(HypervisorError::InvalidPml3Entry);
        }

        let pml2_pa = pml3_entry.pfn() << BASE_PAGE_SHIFT;
        let pml2_va = PhysicalAddress::va_from_pa(pml2_pa) as *const Entry;
        let pml2_entry = unsafe { &*pml2_va.add(pml2_index as usize) };

        log::info!("pml2_entry: {:?}", pml2_entry);
        log::info!("pml2_entry.readable(): {:?}", pml2_entry.readable());
        log::info!("pml2_entry.large(): {:?}", pml2_entry.large());

        if !pml2_entry.readable() || pml2_entry.large() {
            return Err(HypervisorError::InvalidPml2Entry);
        }

        let pml1_pa = pml2_entry.pfn() << BASE_PAGE_SHIFT;
        let pml1_va = PhysicalAddress::va_from_pa(pml1_pa) as *const Entry;
        let pml1_entry = unsafe { &mut *(pml1_va.add(pml1_index as usize) as *mut Entry) };

        // Return the mutable pointer to the PML1 entry.
        Ok(pml1_entry)
    }

    /// Changes the permission of a page given its guest physical address.
    ///
    /// # Arguments
    ///
    /// * `guest_phys_addr` - The guest physical address of the page.
    /// * `permissions` - The new permissions to set for the page.
    ///
    /// # Returns
    /// A `Result<(), HypervisorError>` indicating the success or failure of the operation.
    pub fn change_permission(
        &mut self,
        guest_phys_addr: u64,
        permissions: Access,
    ) -> Result<(), HypervisorError> {

        let pml1_entry = self.find_pml1_entry(guest_phys_addr)?;

        // Set permissions based on the flags
        unsafe { (*pml1_entry).set_readable(permissions.contains(Access::READ)) };
        unsafe { (*pml1_entry).set_writable(permissions.contains(Access::WRITE)) };
        unsafe { (*pml1_entry).set_executable(permissions.contains(Access::EXECUTE)) };

        Ok(())
    }

    /// Splits a 2MB large page into 512 smaller 4KB pages.
    ///
    /// # Arguments
    /// * `guest_phys_addr` - The guest physical address indicating the 2MB page to be split.
    ///
    /// # Returns
    /// A `Result<(), HypervisorError>` indicating the success or failure of the operation.
    #[rustfmt::skip]
    pub fn split_2mb_to_4kb(&mut self, guest_phys_addr: u64) -> Result<(), HypervisorError> {
        // Ensure the given address is aligned to a 2MB boundary.
        if guest_phys_addr & (LARGE_PAGE_SIZE as u64 - 1) != 0 {
            return Err(HypervisorError::UnalignedAddressError);
        }

        // Calculate the indexes for PDPT and PD based on the given guest physical address.
        let pdpt_index = (guest_phys_addr >> 30) & 0x1FF;
        let pd_index = (guest_phys_addr >> 21) & 0x1FF;

        // Retrieve the PD entry corresponding to the guest physical address.
        let pd_entry = &mut self.pd[pdpt_index as usize].0.entries[pd_index as usize];

        // Check if the PD entry is already a large page.
        if !pd_entry.large() {
            return Err(HypervisorError::AlreadySplitError);
        }

        // Mark the PD entry as not large, indicating it will reference PT.
        pd_entry.set_large(false);

        // Update the PD entry to point to the corresponding PT.
        let pt_phys_addr = PhysicalAddress::pa_from_va(&self.pt as *const _ as u64);
        pd_entry.set_pfn(pt_phys_addr >> BASE_PAGE_SHIFT);

        // Calculate the starting index in the PT for the 4KB pages corresponding to the 2MB page.
        let pt_start_index = (pd_index * (LARGE_PAGE_SIZE as u64) / (BASE_PAGE_SIZE as u64)) as usize;

        // Iterate over the PT entries corresponding to the 2MB page.
        for index in 0..(LARGE_PAGE_SIZE / BASE_PAGE_SIZE) {
            let pt_entry = &mut self.pt.0.entries[pt_start_index + index];
            pt_entry.set_readable(true);
            pt_entry.set_writable(true);
            pt_entry.set_executable(true);

            // Calculate the physical address for each 4KB page within the 2MB page.
            let page_phys_addr = guest_phys_addr + (index * BASE_PAGE_SIZE) as u64;
            pt_entry.set_pfn(page_phys_addr >> BASE_PAGE_SHIFT);
        }

        Ok(())
    }

    /// Creates an Extended Page Table Pointer (EPTP) with a Write-Back memory type and a 4-level page walk.
    ///
    /// This function is used in the setup of Intel VT-x virtualization, specifically for configuring the EPT.
    /// It encodes the provided physical base address of the EPT PML4 table into the EPTP format, setting
    /// the memory type to Write-Back and indicating a 4-level page walk.
    ///
    /// # Returns
    /// A `Result<u64, HypervisorError>` containing the configured EPTP value. Returns an error if
    /// the base address is not properly aligned.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 28.2.6 EPT Paging-Structure Entries
    pub fn create_eptp_with_wb_and_4lvl_walk(&self) -> Result<u64, HypervisorError> {
        // Get the virtual address of the PML4 table for EPT.
        let addr = addr_of!(self.pml4) as u64;

        // Get the physical address of the PML4 table for EPT.
        let ept_pml4_base_addr = PhysicalAddress::pa_from_va(addr);

        // Represents the EPT page walk length for Intel VT-x, specifically for a 4-level page walk.
        // The value is 3 (encoded as '3 << 3' in EPTP) because the EPTP encoding requires "number of levels minus one".
        const EPT_PAGE_WALK_LENGTH_4: u64 = 3 << 3;

        // Represents the memory type setting for Write-Back (WB) in the EPTP.
        const EPT_MEMORY_TYPE_WB: u64 = MemoryType::WriteBack as u64;

        // Check if the base address is 4KB aligned (the lower 12 bits should be zero).
        if ept_pml4_base_addr.trailing_zeros() >= 12 {
            // Construct the EPTP with the page walk length and memory type for WB.
            Ok(ept_pml4_base_addr | EPT_PAGE_WALK_LENGTH_4 | EPT_MEMORY_TYPE_WB)
        } else {
            Err(HypervisorError::InvalidEptPml4BaseAddress)
        }
    }
}

/// Represents an EPT PML4 Entry (PML4E) that references a Page-Directory-Pointer Table.
///
/// PML4 is the top level in the EPT paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 29-1. Format of an EPT PML4 Entry (PML4E) that References an EPT Page-Directory-Pointer Table
#[derive(Debug, Clone, Copy)]
struct Pml4(Table);

/// Represents an EPT Page-Directory-Pointer-Table Entry (PDPTE) that references an EPT Page Directory.
///
/// PDPTEs are part of the second level in the EPT paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 29-3. Format of an EPT Page-Directory-Pointer-Table Entry (PDPTE) that References an EPT Page Directory
#[derive(Debug, Clone, Copy)]
struct Pdpt(Table);

/// Represents an EPT Page-Directory Entry (PDE) that references an EPT Page Table.
///
/// PDEs are part of the third level in the EPT paging hierarchy.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 29-5. Format of an EPT Page-Directory Entry (PDE) that References an EPT Page Table
#[derive(Debug, Clone, Copy)]
struct Pd(Table);

/// Represents an EPT Page-Table Entry (PTE) that maps a 4-KByte Page.
///
/// PTEs are the lowest level in the EPT paging hierarchy and are used to map individual
/// pages to guest-physical addresses.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Format of an EPT Page-Table Entry that Maps a 4-KByte Page
#[derive(Debug, Clone, Copy)]
struct Pt(Table);

/// General struct to represent a table in the EPT paging structure.
///
/// This struct is used as a basis for PML4, PDPT, PD, and PT. It contains an array of entries
/// where each entry can represent different levels of the EPT hierarchy.
#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
struct Table {
    entries: [Entry; 512],
}

bitfield! {
    /// Represents an Extended Page Table Entry (EPT Entry).
    ///
    /// EPT entries are used in Intel VT-x virtualization to manage memory access
    /// permissions and address mapping for virtual machines.
    ///
    /// # Fields
    ///
    /// * `readable` - If set, the memory region can be read.
    /// * `writable` - If set, the memory region can be written to.
    /// * `executable` - If set, code can be executed from the memory region.
    /// * `memory_type` - The memory type (e.g., WriteBack, Uncacheable).
    /// * `large` - If set, this entry maps a large page.
    /// * `pfn` - The Page Frame Number, indicating the physical address.
    /// * `verify_guest_paging` - Additional flag for guest paging verification.
    /// * `paging_write_access` - Additional flag for paging write access.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3.2 EPT Translation Mechanism
    #[derive(Clone, Copy)]
    pub struct Entry(u64);
    impl Debug;

    // Flag definitions for an EPT entry.
    pub readable, set_readable: 0;
    pub writable, set_writable: 1;
    pub executable, set_executable: 2;
    pub memory_type, set_memory_type: 5, 3;
    pub large, set_large: 7;
    pub pfn, set_pfn: 51, 12;
    pub verify_guest_paging, set_verify_guest_paging: 57;
    pub paging_write_access, set_paging_write_access: 58;
}
