#![allow(dead_code)]
//! Intel® 64 and IA-32 Architectures Software Developer's Manual Volume 3C: System Programming Guide, Part 3: 29.3 THE EXTENDED PAGE TABLE MECHANISM (EPT)
//! The extended page-table mechanism (EPT) is a feature that can be used to support the virtualization of physical memory.
//! When EPT is in use, certain addresses that would normally be treated as physical addresses (and used to access memory) are instead treated as guest-physical addresses
//! Guest-physical addresses are translated by traversing a set of EPT paging structures to produce physical addresses that are used to access memory.
use bit_field::BitField;

/// Intel® 64 and IA-32 Architectures Software Developer's Manual Volume 3C: System Programming Guide, Part 3: 29.3.7 EPT and Memory Typing
#[derive(Debug)]
pub enum EptMemoryType {
    /// Memory type: Uncacheable (UC)
    Uncacheable = 0,

    /// Memory type: Write-combining (WC)
    WriteCombining = 1,

    /// Memory type: Write-through (WT)
    WriteThrough = 4,

    /// Memory type: Write-protected (WP)
    WriteProtected = 5,

    /// Memory type: Write-back (WB)
    WriteBack = 6,
}

/* Implementation for Extended-Page-Table Pointer (EPTP), EPT PML4E, EPT PDPTE, and EPT PD is below */

/// 25.6.11 Extended-Page-Table Pointer (EPTP): Table 25-9. Format of Extended-Page-Table Pointer
/// The extended-page-table pointer (EPTP) contains the address of the base of EPT PML4 table, as well as other EPT configuration information.
#[derive(Debug)]
pub struct Eptp(u64);

impl Eptp {
    /// Creates a new EPTP instance
    pub fn new() -> Self {
        Eptp(0)
    }

    /// Sets the EPT paging-structure memory type
    pub fn set_memory_type(&mut self, memory_type: u8) {
        self.0.set_bits(2..=0, memory_type as u64);
    }

    /// Sets the EPT page-walk length
    pub fn set_page_walk_length(&mut self, page_walk_length: u8) {
        self.0.set_bits(5..=3, (page_walk_length - 1) as u64);
    }

    /// Enables/disables the accessed and dirty flags for EPT
    pub fn set_accessed_dirty_flag(&mut self, enable: bool) {
        self.0.set_bit(6, enable);
    }

    /// Enables/disables the enforcement of access rights for supervisor shadow-stack pages
    pub fn set_supervisor_shadow_stack_enforcement(&mut self, enable: bool) {
        self.0.set_bit(7, enable);
    }

    /// Sets the physical address of the EPT PML4 table
    pub fn set_pml4_table_address(&mut self, address: u64) {
        self.0.set_bits(51..=12, address >> 12);
    }
}

/// 29.3.2 EPT Translation Mechanism: Table 29-1. Format of an EPT PML4 Entry (PML4E) that References an EPT Page-Directory-Pointer Table
#[derive(Debug)]
pub struct EptPml4e(u64);

impl EptPml4e {
    /// Creates a new EPT PML4 Entry (PML4E)
    pub fn new() -> Self {
        EptPml4e(0)
    }

    /// Sets the present bit of the PML4E
    pub fn set_present(&mut self, present: bool) {
        self.0.set_bit(0, present);
    }

    /// Sets the read/write bit of the PML4E
    pub fn set_read_write(&mut self, read_write: bool) {
        self.0.set_bit(1, read_write);
    }

    /// Sets the user/supervisor bit of the PML4E
    pub fn set_user_supervisor(&mut self, user_supervisor: bool) {
        self.0.set_bit(2, user_supervisor);
    }

    /// Sets the accessed bit of the PML4E
    pub fn set_accessed(&mut self, accessed: bool) {
        self.0.set_bit(8, accessed);
    }

    /// Sets the execute-disable bit of the PML4E
    pub fn set_execute_disable(&mut self, execute_disable: bool) {
        self.0.set_bit(63, execute_disable);
    }

    /// Sets the physical address of the next level table (PDPTE)
    pub fn set_pdp_table_address(&mut self, address: u64) {
        self.0.set_bits(51..=12, address >> 12);
    }
}

/// 29.3.2 EPT Translation Mechanism: Table 29-3. Format of an EPT Page-Directory-Pointer-Table Entry (PDPTE) that References an EPT Page Directory
#[derive(Debug)]
pub struct EptPdpte(u64);

impl EptPdpte {
    /// Creates a new EPT Page-Directory-Pointer Table Entry (PDPTE)
    pub fn new() -> Self {
        EptPdpte(0)
    }

    /// Sets the present bit of the PDPTE
    pub fn set_present(&mut self, present: bool) {
        self.0.set_bit(0, present);
    }

    /// Sets the read/write bit of the PDPTE
    pub fn set_read_write(&mut self, read_write: bool) {
        self.0.set_bit(1, read_write);
    }

    /// Sets the user/supervisor bit of the PDPTE
    pub fn set_user_supervisor(&mut self, user_supervisor: bool) {
        self.0.set_bit(2, user_supervisor);
    }

    /// Sets the accessed bit of the PDPTE
    pub fn set_accessed(&mut self, accessed: bool) {
        self.0.set_bit(8, accessed);
    }

    /// Sets the execute-disable bit of the PDPTE
    pub fn set_execute_disable(&mut self, execute_disable: bool) {
        self.0.set_bit(63, execute_disable);
    }

    /// Sets the physical address of the next level table (PDE)
    pub fn set_page_directory_address(&mut self, address: u64) {
        self.0.set_bits(51..=12, address >> 12);
    }
}

/// 29.3.2 EPT Translation Mechanism: Table 29-5. Format of an EPT Page-Directory Entry (PDE) that References an EPT Page Table
#[derive(Debug)]
pub struct EptPde(u64);

impl EptPde {
    /// Creates a new EPT Page-Directory Entry (PDE)
    pub fn new() -> Self {
        EptPde(0)
    }

    /// Sets the present bit of the PDE
    pub fn set_present(&mut self, present: bool) {
        self.0.set_bit(0, present);
    }

    /// Sets the read/write bit of the PDE
    pub fn set_read_write(&mut self, read_write: bool) {
        self.0.set_bit(1, read_write);
    }

    /// Sets the user/supervisor bit of the PDE
    pub fn set_user_supervisor(&mut self, user_supervisor: bool) {
        self.0.set_bit(2, user_supervisor);
    }

    /// Sets the accessed bit of the PDE
    pub fn set_accessed(&mut self, accessed: bool) {
        self.0.set_bit(8, accessed);
    }

    /// Sets the dirty bit of the PDE
    pub fn set_dirty(&mut self, dirty: bool) {
        self.0.set_bit(9, dirty);
    }

    /// Sets the execute-disable bit of the PDE
    pub fn set_execute_disable(&mut self, execute_disable: bool) {
        self.0.set_bit(63, execute_disable);
    }

    /// Sets the physical address of the page table entry (PTE)
    pub fn set_page_table_address(&mut self, address: u64) {
        self.0.set_bits(51..=12, address >> 12);
    }
}

/// 29.3.2 EPT Translation Mechanism: Format of an EPT Page-Table Entry that Maps a 4-KByte Page
#[derive(Debug)]
pub struct EptPte(u64);

impl EptPte {
    /// Creates a new EPT Page-Table Entry (PTE)
    pub fn new() -> Self {
        EptPte(0)
    }

    /// Sets the present bit of the PTE
    pub fn set_present(&mut self, present: bool) {
        self.0.set_bit(0, present);
    }

    /// Sets the read/write bit of the PTE
    pub fn set_read_write(&mut self, read_write: bool) {
        self.0.set_bit(1, read_write);
    }

    /// Sets the user/supervisor bit of the PTE
    pub fn set_user_supervisor(&mut self, user_supervisor: bool) {
        self.0.set_bit(2, user_supervisor);
    }

    /// Sets the accessed bit of the PTE
    pub fn set_accessed(&mut self, accessed: bool) {
        self.0.set_bit(8, accessed);
    }

    /// Sets the dirty bit of the PTE
    pub fn set_dirty(&mut self, dirty: bool) {
        self.0.set_bit(9, dirty);
    }

    /// Sets the execute-disable bit of the PTE
    pub fn set_execute_disable(&mut self, execute_disable: bool) {
        self.0.set_bit(63, execute_disable);
    }

    /// Sets the physical address of the memory page
    pub fn set_page_address(&mut self, address: u64) {
        self.0.set_bits(51..=12, address >> 12);
    }
}
