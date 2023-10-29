//! Memory allocation utilities for kernel space.
//!
//! This module provides memory allocators tailored for kernel usage:
//! - `PhysicalAllocator`: Allocates contiguous physical memory.
//! - `KernelAlloc`: Standard kernel memory allocator leveraging WDK functions.
//!
//! Both allocators interface directly with the Windows Driver Kit (WDK) to ensure
//! safe and efficient memory operations.

use {
    core::alloc::{AllocError, Allocator, Layout},
    core::ptr::NonNull,
    wdk_sys::{
        ntddk::{
            ExAllocatePool, ExFreePool, MmAllocateContiguousMemorySpecifyCacheNode,
            MmFreeContiguousMemory,
        },
        MM_ANY_NODE_OK, PHYSICAL_ADDRESS,
        _MEMORY_CACHING_TYPE::MmCached,
        _POOL_TYPE::NonPagedPool,
    },
};

/// Physical memory allocator for kernel space.
///
/// Leverages `MmAllocateContiguousMemorySpecifyCacheNode` from the WDK to
/// allocate memory that is physically contiguous.
pub struct PhysicalAllocator;

unsafe impl Allocator for PhysicalAllocator {
    /// Allocates a contiguous block of physical memory.
    ///
    /// # Parameters
    ///
    /// * `layout` - Memory layout specifications.
    ///
    /// # Returns
    ///
    /// A result containing a non-null pointer to the memory block if successful.
    /// Returns an `AllocError` if the allocation fails.
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let mut boundary: PHYSICAL_ADDRESS = unsafe { core::mem::zeroed() };
        let mut lowest: PHYSICAL_ADDRESS = unsafe { core::mem::zeroed() };
        let mut highest: PHYSICAL_ADDRESS = unsafe { core::mem::zeroed() };

        boundary.QuadPart = 0;
        lowest.QuadPart = 0;
        highest.QuadPart = -1;

        let memory = unsafe {
            MmAllocateContiguousMemorySpecifyCacheNode(
                layout.size() as _,
                lowest,
                highest,
                boundary,
                MmCached,
                MM_ANY_NODE_OK,
            )
        } as *mut u8;

        if memory.is_null() {
            Err(AllocError)
        } else {
            let slice = unsafe { core::slice::from_raw_parts_mut(memory, layout.size()) };
            Ok(unsafe { NonNull::new_unchecked(slice) })
        }
    }

    /// Frees an allocated block of physical memory.
    ///
    /// # Parameters
    ///
    /// * `ptr` - Non-null pointer to the memory to be released.
    /// * `_layout` - Memory layout (not used in this implementation).
    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        MmFreeContiguousMemory(ptr.as_ptr() as _);
    }
}

/// Standard memory allocator for kernel space.
///
/// Utilizes `ExAllocatePool` from the WDK for memory operations.
pub struct KernelAlloc;

unsafe impl Allocator for KernelAlloc {
    /// Allocates a block of kernel memory.
    ///
    /// # Parameters
    ///
    /// * `layout` - Memory layout specifications.
    ///
    /// # Returns
    ///
    /// A result containing a non-null pointer to the memory block if successful.
    /// Returns an `AllocError` if the allocation fails.
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let memory = unsafe { ExAllocatePool(NonPagedPool, layout.size() as _) } as *mut u8;

        if memory.is_null() {
            Err(AllocError)
        } else {
            let slice = unsafe { core::slice::from_raw_parts_mut(memory, layout.size()) };
            Ok(unsafe { NonNull::new_unchecked(slice) })
        }
    }

    /// Frees an allocated block of kernel memory.
    ///
    /// # Parameters
    ///
    /// * `ptr` - Non-null pointer to the memory to be released.
    /// * `_layout` - Memory layout (not used in this implementation).
    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        ExFreePool(ptr.as_ptr() as _);
    }
}
