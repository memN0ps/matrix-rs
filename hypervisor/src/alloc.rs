use core::{
    alloc::{AllocError, Allocator, Layout},
    ptr::NonNull,
};

use winapi::shared::ntdef::PHYSICAL_ADDRESS;

use crate::nt::{
    MmAllocateContiguousMemorySpecifyCacheNode, MmFreeContiguousMemory,
    MEMORY_CACHING_TYPE::MmCached, MM_ANY_NODE_OK,
};

pub struct PhysicalAllocator;

unsafe impl Allocator for PhysicalAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let mut boundary: PHYSICAL_ADDRESS = unsafe { core::mem::zeroed() };
        let mut lowest: PHYSICAL_ADDRESS = unsafe { core::mem::zeroed() };
        let mut highest: PHYSICAL_ADDRESS = unsafe { core::mem::zeroed() };

        unsafe { *(boundary.QuadPart_mut()) = 0 };
        unsafe { *(lowest.QuadPart_mut()) = 0 };
        unsafe { *(highest.QuadPart_mut()) = -1 };

        let memory = unsafe {
            MmAllocateContiguousMemorySpecifyCacheNode(
                layout.size(),
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

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        MmFreeContiguousMemory(ptr.cast().as_ptr());
    }
}
