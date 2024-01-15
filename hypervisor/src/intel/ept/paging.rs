//! Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3 THE EXTENDED PAGE TABLE MECHANISM (EPT)
//! The extended page-table mechanism (EPT) is a feature that can be used to support the virtualization of physical memory.
//! When EPT is in use, certain addresses that would normally be treated as physical addresses (and used to access memory) are instead treated as guest-physical addresses
//! Guest-physical addresses are translated by traversing a set of EPT paging structures to produce physical addresses that are used to access memory.
//!
//! Credits to the work by Satoshi in their 'Hello-VT-rp' project for assistance and a clear implementation of EPT:
//! https://github.com/tandasat/Hello-VT-rp/blob/main/hypervisor/src/intel_vt/epts.rs

use x86::bits64::paging::PAGE_SIZE_ENTRIES;
use {
    crate::{
        error::HypervisorError,
        intel::ept::mtrr::{MemoryType, Mtrr},
        utils::addresses::PhysicalAddress,
    },
    bitfield::bitfield,
    bitflags::bitflags,
    core::ptr::addr_of,
    x86::bits64::paging::{
        pd_index, pdpt_index, pml4_index, pt_index, VAddr, BASE_PAGE_SHIFT, BASE_PAGE_SIZE,
        LARGE_PAGE_SIZE,
    },
};

bitflags! {
    /// Represents the different access permissions for an EPT entry.
    #[derive(Debug, Clone, Copy)]
    pub struct AccessType: u8 {
        const READ = 0b001;
        const WRITE = 0b010;
        const EXECUTE = 0b100;
        const READ_WRITE = Self::READ.bits() | Self::WRITE.bits();
        const READ_EXECUTE = Self::READ.bits() | Self::EXECUTE.bits();
        const WRITE_EXECUTE = Self::WRITE.bits() | Self::EXECUTE.bits();
        const READ_WRITE_EXECUTE = Self::READ.bits() | Self::WRITE.bits() | Self::EXECUTE.bits();
    }
}

pub const _512GB: u64 = 512 * 1024 * 1024 * 1024;
pub const _1GB: u64 = 1024 * 1024 * 1024;
pub const _2MB: usize = 2 * 1024 * 1024;
pub const _4KB: usize = 4 * 1024;

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
    /// A two-dimensional array of Page Tables (PT).
    pt: [[Pt; 512]; 512],
}

impl Ept {
    pub fn identity_2mb(&mut self, access: AccessType) -> Result<(), HypervisorError> {
        log::info!("Creating identity map for 2MB pages");

        let mut mtrr = Mtrr::new();

        for pa in (0.._512GB).step_by(_2MB) {
            self.map_2mb(pa, pa, access, &mut mtrr)?;
        }

        Ok(())
    }

    pub fn identity_4kb(&mut self, access: AccessType) -> Result<(), HypervisorError> {
        log::info!("Creating identity map for 4KB pages");

        let mut mtrr = Mtrr::new();

        for pa in (0.._512GB).step_by(BASE_PAGE_SIZE) {
            self.map_4kb(pa, pa, access, &mut mtrr)?;
        }

        Ok(())
    }

    pub fn map_2mb(
        &mut self,
        guest_pa: u64,
        host_pa: u64,
        access: AccessType,
        mtrr: &mut Mtrr,
    ) -> Result<(), HypervisorError> {
        self.map_pml4(guest_pa, access)?;
        self.map_pdpt(guest_pa, access)?;
        self.map_pde(guest_pa, host_pa, access, mtrr)?;

        Ok(())
    }

    pub fn map_4kb(
        &mut self,
        guest_pa: u64,
        host_pa: u64,
        access: AccessType,
        mtrr: &mut Mtrr,
    ) -> Result<(), HypervisorError> {
        self.map_pml4(guest_pa, access)?;
        self.map_pdpt(guest_pa, access)?;
        self.map_pdt(guest_pa, access)?;
        self.map_pt(guest_pa, host_pa, access, mtrr)?;

        Ok(())
    }

    fn map_pml4(&mut self, guest_pa: u64, access_type: AccessType) -> Result<(), HypervisorError> {
        let pml4_index = pml4_index(VAddr::from(guest_pa));
        let pml4_entry = &mut self.pml4.0.entries[pml4_index];

        if !pml4_entry.readable() {
            pml4_entry.set_readable(access_type.contains(AccessType::READ));
            pml4_entry.set_writable(access_type.contains(AccessType::WRITE));
            pml4_entry.set_executable(access_type.contains(AccessType::EXECUTE));
            pml4_entry.set_pfn(
                PhysicalAddress::pa_from_va(addr_of!(self.pdpt) as u64) >> BASE_PAGE_SHIFT,
            );
        }

        Ok(())
    }

    fn map_pdpt(&mut self, guest_pa: u64, access_type: AccessType) -> Result<(), HypervisorError> {
        let pdpt_index = pdpt_index(VAddr::from(guest_pa));
        let pdpt_entry = &mut self.pdpt.0.entries[pdpt_index];

        if !pdpt_entry.readable() {
            pdpt_entry.set_readable(access_type.contains(AccessType::READ));
            pdpt_entry.set_writable(access_type.contains(AccessType::WRITE));
            pdpt_entry.set_executable(access_type.contains(AccessType::EXECUTE));
            pdpt_entry.set_pfn(
                PhysicalAddress::pa_from_va(addr_of!(self.pd[pdpt_index]) as u64)
                    >> BASE_PAGE_SHIFT,
            );
        }

        Ok(())
    }

    fn map_pdt(&mut self, guest_pa: u64, access_type: AccessType) -> Result<(), HypervisorError> {
        let pdpt_index = pdpt_index(VAddr::from(guest_pa));
        let pd_index = pd_index(VAddr::from(guest_pa));
        let pd_entry = &mut self.pd[pdpt_index].0.entries[pd_index];

        if !pd_entry.readable() {
            pd_entry.set_readable(access_type.contains(AccessType::READ));
            pd_entry.set_writable(access_type.contains(AccessType::WRITE));
            pd_entry.set_executable(access_type.contains(AccessType::EXECUTE));
            pd_entry.set_pfn(
                PhysicalAddress::pa_from_va(addr_of!(self.pt[pdpt_index][pd_index]) as u64)
                    >> BASE_PAGE_SHIFT,
            );
        }

        Ok(())
    }

    fn map_pde(
        &mut self,
        guest_pa: u64,
        host_pa: u64,
        access_type: AccessType,
        mtrr: &mut Mtrr,
    ) -> Result<(), HypervisorError> {
        let pdpt_index = pdpt_index(VAddr::from(guest_pa));
        let pd_index = pd_index(VAddr::from(guest_pa));
        let pd_entry = &mut self.pd[pdpt_index].0.entries[pd_index];

        let memory_type = mtrr
            .find(guest_pa..guest_pa + LARGE_PAGE_SIZE as u64)
            .unwrap_or(MemoryType::Uncacheable);

        if !pd_entry.readable() {
            pd_entry.set_readable(access_type.contains(AccessType::READ));
            pd_entry.set_writable(access_type.contains(AccessType::WRITE));
            pd_entry.set_executable(access_type.contains(AccessType::EXECUTE));
            pd_entry.set_memory_type(memory_type as u64);
            pd_entry.set_large(true);
            pd_entry.set_pfn(host_pa >> BASE_PAGE_SHIFT);
        } else {
            log::warn!(
                "Attempted to map an already-mapped 2MB page: {:x}",
                guest_pa
            );
        }

        Ok(())
    }

    fn map_pt(
        &mut self,
        guest_pa: u64,
        host_pa: u64,
        access_type: AccessType,
        mtrr: &mut Mtrr,
    ) -> Result<(), HypervisorError> {
        let pdpt_index = pdpt_index(VAddr::from(guest_pa));
        let pd_index = pd_index(VAddr::from(guest_pa));
        let pt_index = pt_index(VAddr::from(guest_pa));
        let pt_entry = &mut self.pt[pdpt_index][pd_index].0.entries[pt_index];

        let memory_type = mtrr
            .find(guest_pa..guest_pa + BASE_PAGE_SIZE as u64)
            .unwrap_or(MemoryType::Uncacheable);

        if !pt_entry.readable() {
            pt_entry.set_readable(access_type.contains(AccessType::READ));
            pt_entry.set_writable(access_type.contains(AccessType::WRITE));
            pt_entry.set_executable(access_type.contains(AccessType::EXECUTE));
            pt_entry.set_memory_type(memory_type as u64);
            pt_entry.set_pfn(host_pa >> BASE_PAGE_SHIFT);
        } else {
            log::warn!(
                "Attempted to map an already-mapped 4KB page: {:x}",
                guest_pa
            );
        }

        Ok(())
    }

    /// Changes the permission of a single page (can be 2mb or 4kb).
    pub fn change_page_flags(
        &mut self,
        guest_pa: u64,
        access_type: AccessType,
    ) -> Result<(), HypervisorError> {
        let guest_pa = VAddr::from(guest_pa);

        if !guest_pa.is_large_page_aligned() && !guest_pa.is_base_page_aligned() {
            log::error!("Page is not aligned: {:#x}", guest_pa);
            return Err(HypervisorError::UnalignedAddressError);
        }

        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pt_index = pt_index(guest_pa);

        let pd_entry = &mut self.pd[pdpt_index].0.entries[pd_index];

        if pd_entry.large() {
            log::trace!("Changing the permissions of a 2mb page");
            pd_entry.set_readable(access_type.contains(AccessType::READ));
            pd_entry.set_writable(access_type.contains(AccessType::WRITE));
            pd_entry.set_executable(access_type.contains(AccessType::EXECUTE));
        } else {
            log::trace!("Changing the permissions of a 4kb page");

            let pt_entry = &mut self.pt[pdpt_index][pd_index].0.entries[pt_index];
            pt_entry.set_readable(access_type.contains(AccessType::READ));
            pt_entry.set_writable(access_type.contains(AccessType::WRITE));
            pt_entry.set_executable(access_type.contains(AccessType::EXECUTE));
        }

        Ok(())
    }

    pub fn split_2mb_to_4kb(
        &mut self,
        guest_pa: u64,
        access_type: AccessType,
    ) -> Result<(), HypervisorError> {
        log::trace!("Splitting 2mb page into 4kb pages: {:x}", guest_pa);

        let guest_pa = VAddr::from(guest_pa);

        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pd_entry = &mut self.pd[pdpt_index].0.entries[pd_index];

        // We can only split large pages and not page directories.
        // If it's a page directory, it is already split.
        //
        if !pd_entry.large() {
            log::trace!("Page is already split: {:x}.", guest_pa);
            return Err(HypervisorError::PageAlreadySplit);
        }

        // Unmap the 2MB page by resetting the page directory entry.
        Self::unmap_2mb(pd_entry);

        let mut mtrr = Mtrr::new();

        // Map the unmapped physical memory again to 4KB pages.
        for i in 0..PAGE_SIZE_ENTRIES {
            let pa = (guest_pa.as_usize() + i * BASE_PAGE_SIZE) as u64;
            self.map_4kb(pa, pa, access_type, &mut mtrr)?;
        }

        Ok(())
    }

    pub fn unmap_2mb(entry: &mut Entry) {
        if !entry.readable() {
            // The page is already not present; no action needed.
            return;
        }

        // Unmap the large page and clear the flags
        entry.set_readable(false);
        entry.set_writable(false);
        entry.set_executable(false);
        entry.set_memory_type(0);
        entry.set_large(false);
        entry.set_pfn(0); // Reset the Page Frame Number
    }

    fn unmap_4kb(entry: &mut Entry) {
        // Delegate to the unmap_2mb function as the unmap logic is the same.
        Self::unmap_2mb(entry);
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
