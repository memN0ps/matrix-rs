//Credits not-matthias: https://github.com/not-matthias/amd_hypervisor/blob/main/hypervisor/src/utils/processor.rs
use core::mem::MaybeUninit;

use winapi::shared::ntdef::{ALL_PROCESSOR_GROUPS, PROCESSOR_NUMBER, NT_SUCCESS, GROUP_AFFINITY};

use crate::nt::{KeQueryActiveProcessorCountEx, KeGetCurrentProcessorNumberEx, KeGetProcessorNumberFromIndex, KeSetSystemGroupAffinityThread, ZwYieldExecution, KeRevertToUserGroupAffinityThread};

/// The KeQueryActiveProcessorCountEx routine returns the number of active logical processors in a specified group in a multiprocessor system or in the entire system.
pub fn processor_count() -> u32 {
    unsafe { KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS)}
}

#[allow(dead_code)]
/// The KeGetCurrentProcessorNumberEx routine gets the processor number of the logical processor that the caller is running on.
pub fn current_processor_index() -> u32 {
    unsafe { KeGetCurrentProcessorNumberEx(core::ptr::null_mut()) }
}

/// Returns the processor number for the specified index.
fn processor_number_from_index(index: u32) -> Option<PROCESSOR_NUMBER> {
    let mut processor_number: MaybeUninit<PROCESSOR_NUMBER> = MaybeUninit::uninit();

    // The KeGetProcessorNumberFromIndex routine converts a systemwide processor index to a group number and a group-relative processor number.
    let status = unsafe { KeGetProcessorNumberFromIndex(index, processor_number.as_mut_ptr()) };
    
    if NT_SUCCESS(status) {
        Some(unsafe { processor_number.assume_init() })
    } else {
        None
    }
}

/// Switches execution to a specific processor until dropped.
pub struct ProcessorExecutor {
    old_affinity: MaybeUninit<GROUP_AFFINITY>,
}

impl ProcessorExecutor {
    pub fn switch_to_processor(i: u32) -> Option<Self> {
        if i > processor_count() {
            log::error!("Invalid processor index: {}", i);
            return None;
        }

        let processor_number = processor_number_from_index(i)?;

        let mut old_affinity: MaybeUninit<GROUP_AFFINITY> = MaybeUninit::uninit();
        let mut affinity: GROUP_AFFINITY = unsafe { core::mem::zeroed() };

        affinity.Group = processor_number.Group;
        affinity.Mask = 1 << processor_number.Number;
        affinity.Reserved[0] = 0;
        affinity.Reserved[1] = 0;
        affinity.Reserved[2] = 0;

        log::trace!("Switching execution to processor {}", i);
        
        //The KeSetSystemGroupAffinityThread routine changes the group number and affinity mask of the calling thread.
        unsafe { KeSetSystemGroupAffinityThread(&mut affinity, old_affinity.as_mut_ptr()) };

        log::trace!("Yielding execution");
        if !NT_SUCCESS(unsafe { ZwYieldExecution() } ) {
            return None;
        }

        Some( Self { old_affinity } )
    }
}

impl Drop for ProcessorExecutor {
    fn drop(&mut self) {
        log::trace!("Switching execution back to previous processor");
        unsafe {
            //The KeRevertToUserGroupAffinityThread routine restores the group affinity of the calling thread to its original value at the time that the thread was created.
            KeRevertToUserGroupAffinityThread(self.old_affinity.as_mut_ptr());
        }
    }
}