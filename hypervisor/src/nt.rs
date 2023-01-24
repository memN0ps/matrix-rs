use winapi::shared::{
    basetsd::SIZE_T,
    ntdef::{PHYSICAL_ADDRESS, PVOID, PPROCESSOR_NUMBER, NTSTATUS, PGROUP_AFFINITY},
};

#[link(name = "ntoskrnl")]
extern "system" {
    ///https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmallocatecontiguousmemoryspecifycachenode
    pub fn MmAllocateContiguousMemorySpecifyCacheNode(
        NumberOfBytes: SIZE_T,
        LowestAcceptableAddress: PHYSICAL_ADDRESS,
        HighestAcceptableAddress: PHYSICAL_ADDRESS,
        BoundaryAddressMultiple: PHYSICAL_ADDRESS,
        CacheType: MEMORY_CACHING_TYPE,
        PreferredNode: NODE_REQUIREMENT,
    ) -> PVOID;

    ///https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmfreecontiguousmemory
    pub fn MmFreeContiguousMemory(BaseAddress: PVOID);

    ///https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmgetphysicaladdress
    pub fn MmGetPhysicalAddress(BaseAddress: PVOID) -> PHYSICAL_ADDRESS;

    ///undocumented
    pub fn MmGetVirtualForPhysical(PhysicalAddress: PHYSICAL_ADDRESS) -> *mut u64;

    ///https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryactiveprocessorcountex
    pub fn KeQueryActiveProcessorCountEx(GroupNumber: u16) -> u32;

    ///https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-kegetcurrentprocessornumberex
    pub fn KeGetCurrentProcessorNumberEx(ProcNumber: *mut u64) -> u32;

    ///https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kegetprocessornumberfromindex
    pub fn KeGetProcessorNumberFromIndex(ProcIndex: u32, ProcNumber: PPROCESSOR_NUMBER) -> NTSTATUS;

    ///https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesetsystemgroupaffinitythread
    pub fn KeSetSystemGroupAffinityThread(Affinity: PGROUP_AFFINITY, PreviousAffinity: PGROUP_AFFINITY);

    ///undocumented
    pub fn ZwYieldExecution() -> NTSTATUS;

    ///https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereverttousergroupaffinitythread
    pub fn KeRevertToUserGroupAffinityThread(PreviousAffinity: PGROUP_AFFINITY);
}

#[allow(non_camel_case_types)]
pub const MM_ANY_NODE_OK: u32 = 0x80000000;
#[allow(non_camel_case_types)]
pub type NODE_REQUIREMENT = u32;

///https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_memory_caching_type
#[allow(dead_code)]
#[repr(C)]
pub enum MEMORY_CACHING_TYPE {
    MmNonCached = 0,
    MmCached = 1,
    MmWriteCombined = 2,
    MmHardwareCoherentCached,
    MmNonCachedUnordered,
    MmUSWCCached,
    MmMaximumCacheType,
    MmNotMapped = -1,
}
