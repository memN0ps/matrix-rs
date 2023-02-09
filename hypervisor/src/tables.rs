use alloc::boxed::Box;
use core::fmt::{Debug, Formatter, Result};
use core::mem::size_of;

//use spin::Mutex;
use x86::{segmentation::SegmentSelector, task, Ring};
use x86_64::addr::VirtAddr;
use x86_64::instructions::tables::{lgdt, lidt, sidt};
use x86_64::structures::gdt::{Descriptor, DescriptorFlags};
use x86_64::structures::idt::{Entry, HandlerFunc, InterruptDescriptorTable};
use x86_64::structures::{tss::TaskStateSegment, DescriptorTablePointer};

use super::segmentation::SegmentAccessRights;

/* 
lazy_static! {
    pub(super) static ref IDT: Mutex<IdtStruct> = {
        let mut idt = IdtStruct::alloc();
        idt.init();
        Mutex::new(idt)
    };
}
*/

pub(super) struct TssStruct {
    inner: &'static mut TaskStateSegment,
}

#[allow(dead_code)]
impl TssStruct {
    pub fn alloc() -> Self {
        Self {
            inner: Box::leak(Box::new(TaskStateSegment::new())),
        }
    }
}

pub(super) struct GdtStruct {
    table: &'static mut [u64],
}

#[allow(dead_code)]
impl GdtStruct {
    pub const KCODE_SELECTOR: SegmentSelector = SegmentSelector::new(1, Ring::Ring0);
    pub const KDATA_SELECTOR: SegmentSelector = SegmentSelector::new(2, Ring::Ring0);
    pub const TSS_SELECTOR: SegmentSelector = SegmentSelector::new(3, Ring::Ring0);

    pub fn alloc() -> Self {
        Self {
            table: Box::leak(Box::new([0u64; 16])),
        }
    }

    pub fn init(&mut self, tss: &TssStruct) {
        self.table.fill(0);
        self.table[1] = DescriptorFlags::KERNEL_CODE64.bits(); // 0x00af9b000000ffff
        self.table[2] = DescriptorFlags::KERNEL_DATA.bits(); // 0x00cf93000000ffff
        let tss = unsafe { &*(tss.inner as *const _) }; // required static lifetime
        let tss_desc = Descriptor::tss_segment(tss);
        if let Descriptor::SystemSegment(low, high) = tss_desc {
            self.table[3] = low;
            self.table[4] = high;
        }
    }

    pub fn pointer(&self) -> DescriptorTablePointer {
        DescriptorTablePointer {
            base: VirtAddr::new(self.table.as_ptr() as u64),
            limit: (self.table.len() * size_of::<u64>() - 1) as u16,
        }
    }

    pub fn from_pointer(pointer: &DescriptorTablePointer) -> Self {
        let entry_count = (pointer.limit as usize + 1) / size_of::<u64>();
        Self {
            table: unsafe {
                core::slice::from_raw_parts_mut(pointer.base.as_mut_ptr(), entry_count)
            },
        }
    }

    pub fn sgdt() -> DescriptorTablePointer {
        let mut gdt_ptr = DescriptorTablePointer {
            limit: 0,
            base: VirtAddr::new(0),
        };
        unsafe {
            core::arch::asm!("sgdt [{0}]", in(reg) &mut gdt_ptr, options(nostack, preserves_flags));
        }
        gdt_ptr
    }

    pub fn lgdt(pointer: &DescriptorTablePointer) {
        unsafe { lgdt(pointer) };
    }

    pub fn load(&self) {
        Self::lgdt(&self.pointer());
    }

    pub fn load_tss(&mut self, selector: SegmentSelector) {
        SegmentAccessRights::set_descriptor_type(
            &mut self.table[selector.index() as usize],
            SegmentAccessRights::TSS_AVAIL,
        );
        unsafe { task::load_tr(selector) };
    }
}

impl core::ops::Index<usize> for GdtStruct {
    type Output = u64;
    fn index(&self, idx: usize) -> &Self::Output {
        &self.table[idx]
    }
}

impl core::ops::IndexMut<usize> for GdtStruct {
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        &mut self.table[idx]
    }
}

impl Debug for GdtStruct {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("GdtStruct")
            .field("pointer", &self.pointer())
            .field("table", &self.table)
            .finish()
    }
}

pub(super) struct IdtStruct {
    table: &'static mut InterruptDescriptorTable,
}

#[allow(dead_code)]
impl IdtStruct {
    pub fn alloc() -> Self {
        Self {
            table: Box::leak(Box::new(InterruptDescriptorTable::new())),
        }
    }

    pub fn init(&mut self) {
        extern "C" {
            #[link_name = "exception_entries"]
            static ENTRIES: [extern "C" fn(); 256];
        }
        let entries = unsafe {
            core::slice::from_raw_parts_mut(self.table as *mut _ as *mut Entry<HandlerFunc>, 256)
        };
        for i in 0..256 {
            entries[i].set_handler_fn(unsafe { core::mem::transmute(ENTRIES[i]) });
        }
    }

    pub fn pointer(&self) -> DescriptorTablePointer {
        DescriptorTablePointer {
            base: VirtAddr::new(self.table as *const _ as u64),
            limit: (size_of::<InterruptDescriptorTable>() - 1) as u16,
        }
    }

    pub fn sidt() -> DescriptorTablePointer {
        sidt()
    }

    pub fn lidt(pointer: &DescriptorTablePointer) {
        unsafe { lidt(pointer) };
    }

    pub fn load(&self) {
        Self::lidt(&self.pointer())
    }
}
