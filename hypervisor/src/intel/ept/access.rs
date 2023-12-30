//! This crate provides utilities for setting up and managing the memory paging mechanism
//! for x86 architecture within a hypervisor context. Special attention is given to the
//! manipulation of page table flags corresponding to different access types and page sizes.
//! Credits to Matthias: https://github.com/not-matthias/amd_hypervisor/blob/main/hypervisor/src/svm/utils/paging.rs

#![allow(dead_code)] // Allows for definitions that may not be used in all configurations.

use x86::bits64::paging::{PDFlags, PDPTFlags, PML4Flags, PTFlags};

// Constants defining sizes for various page table entries.
pub const _512GB: u64 = 512 * 1024 * 1024 * 1024;
pub const _1GB: u64 = 1024 * 1024 * 1024;
pub const _2MB: usize = 2 * 1024 * 1024;
pub const _4KB: usize = 4 * 1024;

/// `AccessType` defines the types of access that can be granted to a page in the paging structure.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub enum AccessType {
    ReadWrite,
    ReadWriteExecute,
}

impl AccessType {
    /// Generates the appropriate PML4 flags for the access type.
    pub fn pml4_flags(self) -> PML4Flags {
        match self {
            AccessType::ReadWrite => PML4Flags::P | PML4Flags::RW | PML4Flags::US | PML4Flags::XD,
            AccessType::ReadWriteExecute => PML4Flags::P | PML4Flags::RW | PML4Flags::US,
        }
    }

    /// Generates the appropriate PDPT flags for the access type.
    pub fn pdpt_flags(self) -> PDPTFlags {
        match self {
            AccessType::ReadWrite => PDPTFlags::P | PDPTFlags::RW | PDPTFlags::US | PDPTFlags::XD,
            AccessType::ReadWriteExecute => PDPTFlags::P | PDPTFlags::RW | PDPTFlags::US,
        }
    }

    /// Generates the appropriate PD flags for the access type.
    pub fn pd_flags(self) -> PDFlags {
        match self {
            AccessType::ReadWrite => PDFlags::P | PDFlags::RW | PDFlags::US | PDFlags::XD,
            AccessType::ReadWriteExecute => PDFlags::P | PDFlags::RW | PDFlags::US,
        }
    }

    /// Generates the appropriate PT flags for the access type.
    pub fn pt_flags(self) -> PTFlags {
        match self {
            AccessType::ReadWrite => {
                PTFlags::from_iter([PTFlags::P, PTFlags::RW, PTFlags::US, PTFlags::XD])
            }
            AccessType::ReadWriteExecute => {
                PTFlags::from_iter([PTFlags::P, PTFlags::RW, PTFlags::US])
            }
        }
    }

    /// Modifies the PDFlags for a 2MB page based on the access type.
    pub fn modify_2mb(&self, mut flags: PDFlags) -> PDFlags {
        match self {
            AccessType::ReadWrite => {
                flags.insert(PDFlags::RW); // Set the ReadWrite flag.
                flags.insert(PDFlags::XD); // Set the Execute Disable flag.
            }
            AccessType::ReadWriteExecute => {
                flags.insert(PDFlags::RW); // Set the ReadWrite flag.
                flags.remove(PDFlags::XD); // Remove the Execute Disable flag to allow execution.
            }
        }

        flags // Return the modified flags.
    }

    /// Modifies the PTFlags for a 4KB page based on the access type.
    pub fn modify_4kb(&self, mut flags: PTFlags) -> PTFlags {
        match self {
            AccessType::ReadWrite => {
                flags.insert(PTFlags::RW); // Set the ReadWrite flag.
                flags.insert(PTFlags::XD); // Set the Execute Disable flag.
            }
            AccessType::ReadWriteExecute => {
                flags.insert(PTFlags::RW); // Set the ReadWrite flag.
                flags.remove(PTFlags::XD); // Remove the Execute Disable flag to allow execution.
            }
        }

        flags // Return the modified flags.
    }
}
