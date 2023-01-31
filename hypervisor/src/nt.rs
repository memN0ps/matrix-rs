use winapi::{shared::{
    ntdef::{PHYSICAL_ADDRESS, PVOID, PPROCESSOR_NUMBER, NTSTATUS, PGROUP_AFFINITY},
}};

#[link(name = "ntoskrnl")]
extern "system" {
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

    ///https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitializebitmap
    pub fn RtlInitializeBitMap(
        BitMapHeader: PRTL_BITMAP, BitMapBuffer: *mut u32, SizeOfBitMap: u32,
    );

    ///https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearallbits
    pub fn RtlClearAllBits(BitMapHeader: PRTL_BITMAP);
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct RTL_BITMAP {
    pub(crate) SizeOfBitMap: u32,
    pub(crate) Buffer: *mut u32,
}
#[allow(non_camel_case_types)]
pub type PRTL_BITMAP = *mut RTL_BITMAP;