// Credits to @memN0ps and @not-matthias: https://github.com/not-matthias/kernel-alloc-rs/blob/master/src/lib.rs (WDK)
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

/// Represents a physical memory allocator for the kernel.
///
/// This allocator uses the `MmAllocateContiguousMemorySpecifyCacheNode` function
/// from the WDK to allocate contiguous memory.
pub struct PhysicalAllocator;

unsafe impl Allocator for PhysicalAllocator {
    /// Allocates a block of memory with the given layout.
    ///
    /// # Arguments
    ///
    /// * `layout` - The desired layout of the memory block.
    ///
    /// # Returns
    ///
    /// A result containing a non-null pointer to the allocated memory block, or an `AllocError` if the allocation fails.
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

    /// Deallocates a previously allocated block of memory.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A non-null pointer to the memory block to be deallocated.
    /// * `_layout` - The layout of the memory block. Currently unused.
    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        MmFreeContiguousMemory(ptr.as_ptr() as _);
    }
}

/// Represents the global memory allocator for the kernel.
///
/// This allocator uses the `ExAllocatePool` function from the WDK for memory allocation.
pub struct KernelAlloc;

unsafe impl Allocator for KernelAlloc {
    /// Allocates a block of memory with the given layout.
    ///
    /// # Arguments
    ///
    /// * `layout` - The desired layout of the memory block.
    ///
    /// # Returns
    ///
    /// A result containing a non-null pointer to the allocated memory block, or an `AllocError` if the allocation fails.
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let memory = unsafe { ExAllocatePool(NonPagedPool, layout.size() as _) } as *mut u8;

        if memory.is_null() {
            Err(AllocError)
        } else {
            let slice = unsafe { core::slice::from_raw_parts_mut(memory, layout.size()) };
            Ok(unsafe { NonNull::new_unchecked(slice) })
        }
    }

    /// Deallocates a previously allocated block of memory.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A non-null pointer to the memory block to be deallocated.
    /// * `_layout` - The layout of the memory block. Currently unused.
    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        ExFreePool(ptr.as_ptr() as _);
    }
}
