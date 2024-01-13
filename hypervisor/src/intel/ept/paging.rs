//! Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3 THE EXTENDED PAGE TABLE MECHANISM (EPT)
//! The extended page-table mechanism (EPT) is a feature that can be used to support the virtualization of physical memory.
//! When EPT is in use, certain addresses that would normally be treated as physical addresses (and used to access memory) are instead treated as guest-physical addresses
//! Guest-physical addresses are translated by traversing a set of EPT paging structures to produce physical addresses that are used to access memory.
//!
//! Credits to the work by Satoshi (https://github.com/tandasat/Hello-VT-rp/blob/main/hypervisor/src/intel_vt/epts.rs) and Matthias (https://github.com/not-matthias/amd_hypervisor/blob/main/hypervisor/src/svm/nested_page_table.rs).

use {
    crate::{
        error::HypervisorError,
        intel::ept::{
            access::{AccessType, _512GB},
            mtrr::Mtrr,
        },
        utils::addresses::{physical_address, PhysicalAddress},
    },
    core::ptr::addr_of,
    elain::Align,
    static_assertions::{const_assert, const_assert_eq},
    x86::bits64::paging::{
        pd_index, pdpt_index, pml4_index, pt_index, PAddr, PDEntry, PDFlags, PDPTEntry, PML4Entry,
        PTEntry, VAddr, BASE_PAGE_SIZE, LARGE_PAGE_SIZE, PAGE_SIZE_ENTRIES, PD, PDPT, PML4, PT,
    },
};

/// Represents the entire Extended Page Table (EPT) structure similar to the standard x86-64 paging mechanism.
///
/// # Fields
/// - `pml4`: The Page Map Level 4 (PML4) table.
/// - `pdpt`: The Page Directory Pointer Table (PDPT).
/// - `pd`: An array of Page Directory Tables (PDT).
/// - `pt`: A two-dimensional array of Page Tables (PT).
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3.2 EPT Translation Mechanism
#[repr(C, align(4096))]
pub struct Ept {
    /// The Page Map Level 4 (PML4) table.
    pub pml4: PML4,
    align_0: Align<4096>,

    /// The Page Directory Pointer Table (PDPT).
    pub pdpt: PDPT,
    align_1: Align<4096>,

    /// An array of Page Directory Tables (PDT).
    pub pd: [PD; PAGE_SIZE_ENTRIES],
    align_2: Align<4096>,

    /// A two-dimensional array of Page Tables (PT).
    pub pt: [[PT; PAGE_SIZE_ENTRIES]; PAGE_SIZE_ENTRIES],
}
const_assert_eq!(core::mem::size_of::<Ept>(), 0x40202000);
const_assert!(core::mem::align_of::<Ept>() == 4096);

impl Ept {
    /// Splits a large 2MB page into 512 smaller 4KB pages for a given guest physical address.
    ///
    /// # Arguments
    /// - `guest_pa`: The guest physical address within the 2MB page that needs to be split.
    /// - `access_type`: The type of access allowed for the newly created 4KB pages.
    ///
    /// # Remarks
    /// This is necessary to apply more granular hooks and reduce the number of
    /// page faults that occur when the guest tries to access a page that is hooked.
    pub fn split_2mb_to_4kb(&mut self, guest_pa: u64, access_type: AccessType) {
        log::trace!(
            "Splitting 2MB pages into 4KB pages at address: {:x}",
            guest_pa
        );

        // Convert guest physical address to virtual address format for indexing.
        let guest_pa = VAddr::from(guest_pa);

        // Calculate indices for the guest physical address.
        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pd_entry = &mut self.pd[pdpt_index][pd_index];

        // Check if the page directory entry points to a large page.
        if !pd_entry.is_page() {
            log::trace!("No large page found to split at address: {:x}.", guest_pa);
            return;
        }

        // Unmap the 2MB page by resetting the page directory entry.
        Self::unmap_2mb(pd_entry);

        // Remap each 4KB portion of the original 2MB page.
        for i in 0..PAGE_SIZE_ENTRIES as u64 {
            let offset = i * BASE_PAGE_SIZE as u64;
            let address = guest_pa.as_u64() + offset;

            // Remap with the same physical address for identity mapping.
            self.map_4kb(address, address, access_type);
        }
    }

    /// Creates an identity map for 4KB pages in the Extended Page Tables (EPT).
    ///
    /// # Arguments
    /// - `access_type`: The type of access allowed for these pages (read, write, execute).
    ///
    /// # Remarks
    /// An identity map means every guest physical address maps directly to the same host physical address.
    pub fn identity_4kb(&mut self, access_type: AccessType) {
        log::info!("Creating 4KB identity mappings for all addressable space.");
        log::info!("Mapping 512GB of physical memory");

        // Iterate through each possible 4KB page in the addressable space and map it to itself.
        for pa in (0.._512GB).step_by(BASE_PAGE_SIZE) {
            // Mapping guest physical address to the same host physical address.
            self.map_4kb(pa, pa, access_type);
        }
    }

    /// Creates an identity map for 2MB pages in the Extended Page Tables (EPT).
    ///
    /// # Arguments
    /// - `access_type`: The type of access allowed for these pages (read, write, execute).
    ///
    /// # Remarks
    /// Similar to `identity_4kb`, but maps larger 2MB pages for better performance in some scenarios.
    pub fn identity_2mb(&mut self, access_type: AccessType) {
        log::info!("Creating 2MB identity mappings for all addressable space.");
        log::info!("Mapping 512GB of physical memory");

        // Iterate through each possible 2MB page in the addressable space and map it to itself.
        for pa in (0.._512GB).step_by(LARGE_PAGE_SIZE) {
            // Mapping guest physical address to the same host physical address.
            self.map_2mb(pa, pa, access_type);
        }
    }

    /// Maps a single 4KB page in the EPT.
    ///
    /// # Arguments
    /// - `guest_pa`: The guest physical address to map.
    /// - `host_pa`: The host physical address to map to.
    /// - `access_type`: The type of access allowed for this page (read, write, execute).
    pub fn map_4kb(&mut self, guest_pa: u64, host_pa: u64, access_type: AccessType) {
        self.map_pml4(guest_pa, access_type);
        self.map_pdpt(guest_pa, access_type);
        self.map_pdt(guest_pa, access_type);
        self.map_pt(guest_pa, host_pa, access_type);
    }

    /// Maps a single 2MB page in the EPT.
    ///
    /// # Arguments
    /// - `guest_pa`: The guest physical address to map.
    /// - `host_pa`: The host physical address to map to.
    /// - `access_type`: The type of access allowed for this page (read, write, execute).
    pub fn map_2mb(&mut self, guest_pa: u64, host_pa: u64, access_type: AccessType) {
        self.map_pml4(guest_pa, access_type);
        self.map_pdpt(guest_pa, access_type);
        self.map_pde(guest_pa, host_pa, access_type);
    }

    /// Updates the PML4 entry corresponding to the provided guest physical address.
    ///
    /// # Arguments
    /// - `guest_pa`: The guest physical address whose corresponding PML4 entry will be updated.
    /// - `access_type`: The type of access allowed for the region covered by this PML4 entry.
    fn map_pml4(&mut self, guest_pa: u64, access_type: AccessType) {
        // Extract the PML4 index from the guest physical address and fetch the corresponding entry.
        let pml4_index = pml4_index(VAddr::from(guest_pa));
        let pml4_entry = &mut self.pml4[pml4_index];

        // If the PML4 entry is not already present, create a new one with the provided access type.
        if !pml4_entry.is_present() {
            *pml4_entry = PML4Entry::new(
                physical_address(self.pdpt.as_ptr() as _),
                access_type.pml4_flags(),
            );
        }
    }

    /// Updates the PDPT entry corresponding to the provided guest physical address.
    ///
    /// # Arguments
    /// - `guest_pa`: The guest physical address whose corresponding PDPT entry will be updated.
    /// - `access_type`: The type of access allowed for the region covered by this PDPT entry.
    fn map_pdpt(&mut self, guest_pa: u64, access_type: AccessType) {
        // Extract the PDPT index from the guest physical address and fetch the corresponding entry.
        let pdpt_index = pdpt_index(VAddr::from(guest_pa));
        let pdpt_entry = &mut self.pdpt[pdpt_index];

        // If the PDPT entry is not already present, create a new one with the provided access type.
        if !pdpt_entry.is_present() {
            let pa = physical_address(self.pd[pdpt_index].as_ptr() as _);
            *pdpt_entry = PDPTEntry::new(pa, access_type.pdpt_flags());
        }
    }

    /// Updates the PDT entry corresponding to the provided guest physical address.
    ///
    /// # Arguments
    /// - `guest_pa`: The guest physical address whose corresponding PDT entry will be updated.
    /// - `access_type`: The type of access allowed for the region covered by this PDT entry.
    fn map_pdt(&mut self, guest_pa: u64, access_type: AccessType) {
        // Extract the PDT index from the guest physical address and fetch the corresponding entry.
        let pdpt_index = pdpt_index(VAddr::from(guest_pa));
        let pd_index = pd_index(VAddr::from(guest_pa));
        let pd_entry = &mut self.pd[pdpt_index][pd_index];

        // If the PDT entry is not already present, create a new one with the provided access type.
        if !pd_entry.is_present() {
            let pa = physical_address(self.pt[pdpt_index][pd_index].as_ptr() as _);
            *pd_entry = PDEntry::new(pa, access_type.pd_flags());
        }
    }

    /// Updates the PD entry corresponding to the provided guest physical address for 2MB page mapping.
    ///
    /// # Arguments
    /// - `guest_pa`: The guest physical address whose corresponding PD entry will be updated.
    /// - `host_pa`: The host physical address to map to.
    /// - `access_type`: The type of access allowed for this 2MB page.
    fn map_pde(&mut self, guest_pa: u64, host_pa: u64, access_type: AccessType) {
        // Extract the PD index from the guest physical address and fetch the corresponding entry.
        let pdpt_index = pdpt_index(VAddr::from(guest_pa));
        let pd_index = pd_index(VAddr::from(guest_pa));
        let pd_entry = &mut self.pd[pdpt_index][pd_index];

        // If the PD entry is not already present, create a new one representing a 2MB page with the provided access type.
        if !pd_entry.is_present() {
            let flags = access_type.pd_flags() | PDFlags::PS; // Mark the entry as a large (2MB) page.
            *pd_entry = PDEntry::new(PAddr::from(host_pa), flags);
        } else {
            log::warn!(
                "Attempted to map an already-mapped 2MB page: {:x}",
                guest_pa
            );
        }
    }

    /// Updates the PT entry corresponding to the provided guest physical address for 4KB page mapping.
    ///
    /// # Arguments
    /// - `guest_pa`: The guest physical address whose corresponding PT entry will be updated.
    /// - `host_pa`: The host physical address to map to.
    /// - `access_type`: The type of access allowed for this 4KB page.
    fn map_pt(&mut self, guest_pa: u64, host_pa: u64, access_type: AccessType) {
        // Extract indices from the guest physical address and fetch the corresponding PT entry.
        let pdpt_index = pdpt_index(VAddr::from(guest_pa));
        let pd_index = pd_index(VAddr::from(guest_pa));
        let pt_index = pt_index(VAddr::from(guest_pa));
        let pt_entry = &mut self.pt[pdpt_index][pd_index][pt_index];

        // If the PT entry is not already present, create a new one representing a 4KB page with the provided access type.
        if !pt_entry.is_present() {
            let flags = access_type.pt_flags();
            *pt_entry = PTEntry::new(PAddr::from(host_pa), flags);
        } else {
            log::warn!(
                "Attempted to map an already-mapped 4KB page: {:x}",
                guest_pa
            );
        }
    }

    /// Unmaps a 2MB page by clearing the corresponding page directory entry.
    ///
    /// # Arguments
    /// - `entry`: Mutable reference to the page directory entry to unmap.
    ///
    /// # Remarks
    /// This function clears the entry, effectively removing any mapping for the 2MB page.
    /// It's used when transitioning a region of memory from a single large page to multiple smaller pages or simply freeing the page.
    fn unmap_2mb(entry: &mut PDEntry) {
        if !entry.is_present() {
            // The page is already not present; no action needed.
            return;
        }

        // Clear the flags in the page directory entry, effectively unmapping the page.
        *entry = PDEntry::new(entry.address(), PDFlags::empty());
    }

    /// Unmaps a 4KB page, typically involved in deconstructing finer-grained page tables.
    ///
    /// # Arguments
    /// - `entry`: Mutable reference to the page directory entry of the 4KB page to unmap.
    ///
    /// # Remarks
    /// This function wraps the unmap_2mb function, as the actual unmap logic is similar.
    /// It's used for unmap operations specifically targeting 4KB pages.
    #[allow(dead_code)]
    fn unmap_4kb(entry: &mut PDEntry) {
        // Delegate to the unmap_2mb function as the unmap logic is the same.
        Self::unmap_2mb(entry);
    }

    /// Modifies the flags of the specified PML4 entry.
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - Guest physical address of the page whose PML4 entry flags are to be changed.
    /// * `access_type` - The new access permissions to set for the PML4 entry.
    ///
    /// # Details
    ///
    /// This function changes the flags of a PML4 entry corresponding to the specified guest physical address.
    /// It is typically used in conjunction with other flag modifications to ensure proper access permissions
    /// throughout the page table hierarchy.
    ///
    /// # Usage
    ///
    /// This should be used when changes to higher-level page table entries are needed, often as part of
    /// a broader set of page permission changes.
    pub fn change_pml4_flags(&mut self, guest_pa: u64, access_type: AccessType) {
        // Calculate the index for the PML4 entry from the guest physical address
        let pml4_index = pml4_index(VAddr::from(guest_pa));
        // Retrieve the mutable reference to the specific PML4 entry
        let pml4_entry = &mut self.pml4[pml4_index];
        // Update the PML4 entry with new access permissions
        *pml4_entry = PML4Entry::new(pml4_entry.address(), access_type.pml4_flags());
    }

    /// Modifies the flags of the specified PDPT entry.
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - Guest physical address of the page whose PDPT entry flags are to be changed.
    /// * `access_type` - The new access permissions to set for the PDPT entry.
    ///
    /// # Details
    ///
    /// This function changes the flags of a PDPT entry corresponding to the specified guest physical address.
    /// Similar to changing PML4 flags, it is part of ensuring that the entire path from the highest level
    /// of the page table down to the specific page has the specified permissions.
    ///
    /// # Usage
    ///
    /// Use this function when adjustments to the PDPT entries are needed, typically in conjunction with
    /// modifications to other page table entries.
    pub fn change_pdpt_flags(&mut self, guest_pa: u64, access_type: AccessType) {
        // Calculate the index for the PDPT entry from the guest physical address
        let pdpt_index = pdpt_index(VAddr::from(guest_pa));
        // Retrieve the mutable reference to the specific PDPT entry
        let pdp_entry = &mut self.pdpt[pdpt_index];
        // Update the PDPT entry with new access permissions
        *pdp_entry = PDPTEntry::new(pdp_entry.address(), access_type.pdpt_flags());
    }

    /// Modifies the access permissions for a specified page in the extended page table (EPT).
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - Guest physical address of the page whose permissions are to be modified.
    /// * `host_pa` - Host physical address that the guest physical address will be mapped to.
    /// * `access_type` - New access permissions to apply to the page.
    ///
    /// # Warning
    ///
    /// This function will change the permissions for the specified page and all associated higher-level
    /// page table entries. For example, setting a non-executable (XD) permission will propagate to all
    /// upper-level tables, potentially making the entire table non-executable.
    ///
    /// # Usage
    ///
    /// - To transition a non-executable page to executable, upper-level tables must be made executable.
    /// - To change a page to non-executable in an executable table, only the page itself requires changes.
    ///
    /// # Deprecated
    ///
    /// This function is deprecated and will be removed in a future version.
    /// Use `change_page_flags` as the recommended alternative.
    pub fn change_page_permission(&mut self, guest_pa: u64, host_pa: u64, access_type: AccessType) {
        // Log the permission change attempt with the new access type.
        log::trace!(
            "Changing permission of guest page {:#x} to {:?}",
            guest_pa,
            access_type
        );

        // Convert the raw addresses to virtual and physical address types.
        let guest_pa = VAddr::from(guest_pa);
        let host_pa = PAddr::from(host_pa);

        // Ensure both guest and host physical addresses are correctly aligned.
        if (!guest_pa.is_base_page_aligned() && !guest_pa.is_large_page_aligned())
            || (!host_pa.is_base_page_aligned() && !guest_pa.is_large_page_aligned())
        {
            log::error!(
                "Pages are not aligned. Guest: {:#x}, Host: {:#x}",
                guest_pa,
                host_pa
            );
            return;
        }

        // Calculate indexes for each level of the page table from the guest physical address.
        let pml4_index = pml4_index(guest_pa);
        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pt_index = pt_index(guest_pa);

        // Update permissions for the PML4 entry.
        self.pml4[pml4_index] =
            PML4Entry::new(self.pml4[pml4_index].address(), access_type.pml4_flags());

        // Update permissions for the PDPT entry.
        self.pdpt[pdpt_index] =
            PDPTEntry::new(self.pdpt[pdpt_index].address(), access_type.pdpt_flags());

        // Determine if the target is a large (2MB) page and update permissions accordingly.
        let pd_entry = &mut self.pd[pdpt_index][pd_index];

        if pd_entry.is_page() {
            // Log the change for a 2MB page.
            log::trace!("Changing the permissions of a 2mb page");

            *pd_entry = PDEntry::new(host_pa, access_type.modify_2mb(pd_entry.flags()));
        } else {
            // Log the change for a 4KB page.
            log::trace!("Changing the permissions of a 4kb page");

            // Update permissions for the PD entry.
            *pd_entry = PDEntry::new(pd_entry.address(), access_type.pd_flags());

            // Update permissions for the PT entry.
            let pt_entry = &mut self.pt[pdpt_index][pd_index][pt_index];
            let flags = access_type.modify_4kb(pt_entry.flags());
            let entry = PTEntry::new(host_pa, flags);

            *pt_entry = entry;
        }
    }

    /// Modifies the access permissions for a page within the extended page table (EPT).
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - Guest physical address of the page whose permissions are to be changed.
    /// * `access_type` - The new access permissions to set for the page.
    ///
    /// # Details
    ///
    /// This function adjusts the permissions of either a 2MB or a 4KB page based on its alignment.
    /// It is the responsibility of the caller to ensure that the `guest_pa` is aligned to the size
    /// of the page they intend to modify.
    pub fn change_page_flags(&mut self, guest_pa: u64, access_type: AccessType) {
        // Convert the raw address to a virtual address type.
        let guest_pa = VAddr::from(guest_pa);

        // Verify that the provided guest physical address is aligned to the size of the page.
        if !guest_pa.is_large_page_aligned() && !guest_pa.is_base_page_aligned() {
            // Log an error if the page is not aligned.
            log::error!("Page is not aligned: {:#x}", guest_pa);
            return;
        }

        // Calculate the indexes for the page table entries from the guest physical address.
        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pt_index = pt_index(guest_pa);

        // Access the page directory entry for the given address.
        let pd_entry = &mut self.pd[pdpt_index][pd_index];

        // Check if the page directory entry points to a large page.
        if pd_entry.is_page() {
            // Log the operation being performed on a 2MB page.
            log::trace!("Changing the permissions of a 2mb page");

            // Update the permissions of the 2MB page.
            *pd_entry = PDEntry::new(pd_entry.address(), access_type.modify_2mb(pd_entry.flags()));
        } else {
            // Log the operation being performed on a 4KB page.
            log::trace!("Changing the permissions of a 4kb page");

            // Access the page table entry within the page directory.
            let pt_entry = &mut self.pt[pdpt_index][pd_index][pt_index];

            // Update the permissions of the 4KB page.
            *pt_entry = PTEntry::new(pt_entry.address(), access_type.modify_4kb(pt_entry.flags()));
        }
    }

    /// Modifies the access permissions for the specified page and all relevant upper-level tables.
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - Guest physical address of the page whose permissions are to be changed.
    /// * `access_type` - The new access permissions to set for the page and upper-level tables.
    ///
    /// # Details
    ///
    /// This function adjusts the permissions of a specified page as well as the corresponding entries
    /// in the PML4 and PDPT tables. It ensures that the entire path from the highest level of the page
    /// table down to the specified page has the specified permissions. This is necessary when changes
    /// to page execution permissions are made, as the entire table hierarchy must reflect these changes
    /// for them to take effect.
    ///
    /// # Warnings
    ///
    /// - Changing a page's execute-disable (XD) bit will also change the XD bit for all upper levels.
    ///   This could lead to the entire page table becoming non-executable.
    /// - Ensure that the page address is correctly aligned and the access type is properly set to avoid
    ///   unintended behavior.
    ///
    /// # Usage
    ///
    /// Use this function when you need to ensure that the access change of a page is propagated
    /// throughout all levels of the page table. This is especially critical when handling executable
    /// permissions.
    pub fn change_all_page_flags(&mut self, guest_pa: u64, access_type: AccessType) {
        // Change the permissions for the PML4 entry.
        self.change_pml4_flags(guest_pa, access_type);
        // Change the permissions for the PDPT entry.
        self.change_pdpt_flags(guest_pa, access_type);
        // Finally, change the permissions for the specified page.
        self.change_page_flags(guest_pa, access_type);
    }

    /// Prints the page permission for a given guest physical address.
    ///
    /// ## Note
    /// This function should only be used for debugging purposes as it logs the page directory and page table entries corresponding to the given address. It's helpful for verifying changes to page permissions or diagnosing issues with memory access rights.
    ///
    /// ## Arguments
    /// * `guest_pa` - Guest physical address whose page permission is to be printed.
    ///
    /// ## Usage
    /// This function can be used during development or debugging to understand the permission status of a specific guest physical address within the extended page table structure. It logs detailed information about the page directory entry (PDE) and page table entry (PTE) for the given address.
    pub fn print_page_permission(&mut self, guest_pa: u64) {
        // Convert the guest physical address to virtual address format
        let guest_pa = VAddr::from(guest_pa);

        // Calculate indices for the page directory and page table
        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pt_index = pt_index(guest_pa);

        // Retrieve the page directory entry (PDE) and page table entry (PTE)
        let pd_entry = &self.pd[pdpt_index][pd_index];
        let pt_entry = &self.pt[pdpt_index][pd_index][pt_index];

        // Log the permissions in the page directory and page table entries
        log::info!("PDEntry: {:x?}, PTEntry: {:x?}", pd_entry, pt_entry);
    }

    /// Creates an Extended Page Table Pointer (EPTP) with a Write-Back memory type and a 4-level page walk.
    ///
    /// This function is used in the setup of Intel VT-x virtualization, specifically for configuring the EPT.
    /// It encodes the provided physical base address of the EPT PML4 table into the EPTP format, setting
    /// the memory type to Write-Back and indicating a 4-level page walk.
    ///
    /// # Returns
    /// A `Result<u64, HypervisorError>` containing the configured EPTP value or an error if the base address is not properly aligned.
    ///
    /// # Remarks
    /// This function is used in the setup of Intel VT-x virtualization, specifically for configuring the EPT.
    /// It encodes the provided physical base address of the EPT PML4 table into the EPTP format, setting
    /// the memory type to Write-Back and indicating a 4-level page walk.
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
        const EPT_MEMORY_TYPE_WB: u64 = Mtrr::WriteBack as u64;

        // Check if the base address is 4KB aligned (the lower 12 bits should be zero).
        if ept_pml4_base_addr.trailing_zeros() >= 12 {
            // Construct the EPTP with the page walk length and memory type for WB.
            Ok(ept_pml4_base_addr | EPT_PAGE_WALK_LENGTH_4 | EPT_MEMORY_TYPE_WB)
        } else {
            Err(HypervisorError::InvalidEptPml4BaseAddress)
        }
    }
}
