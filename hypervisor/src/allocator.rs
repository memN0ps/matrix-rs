use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::alloc::{Layout, GlobalAlloc};

/// Global allocator
#[global_allocator]
static GLOBAL_ALLOCATOR: mm::GlobalAllocator = mm::GlobalAllocator;

/// Physical memory implementation
///
/// This is used during page table operations
pub struct Pmem {}

impl PhysMem for Pmem {
    /// Allocate a page
    fn alloc_page(&mut self) -> Option<*mut u8> {
        unsafe {
            let layout = Layout::from_size_align(4096, 4096).unwrap();
            let alloc = GLOBAL_ALLOCATOR.alloc(layout);
            if alloc.is_null() {
                None
            } else {
                Some(alloc as *mut u8)
            }
        }
    }

    /// Read a 64-bit value at the physical address specified
    fn read_phys(&mut self, addr: *mut u64) -> Result<u64, &'static str> {
        unsafe { Ok(core::ptr::read(addr)) }
    }
    
    /// Write a 64-bit value to the physical address specified
    fn write_phys(&mut self, addr: *mut u64, val: u64) ->
            Result<(), &'static str> {
        unsafe { Ok(core::ptr::write(addr, val)) }
    }

    /// This is used to let the MMU know if we reserve memory outside of
    /// the page tables. Since we do not do this at all we always return true
    /// allowing any address not in use in the page tables to be used for
    /// ASLR.
    fn probe_vaddr(&mut self, _addr: usize, _length: usize) -> bool {
        true
    }
}