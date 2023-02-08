use core::arch::asm;
use x86::{
    controlregs::{self},
    msr::{self}, debugregs, bits64, segmentation::{self, Descriptor}, dtables, task,
};
use x86_64::{
    instructions::tables::{sgdt, sidt},
};

use crate::{segmentation::{SegmentDescriptor, SegmentAttribute}};

#[repr(C)]
pub struct Context {
    pub es_selector: u16,
    pub es_attrib: u16,
    pub es_limit: u32,
    pub es_base: u64,

    pub cs_selector: u16,
    pub cs_attrib: u16,
    pub cs_limit: u32,
    pub cs_base: u64,

    pub ss_selector: u16,
    pub ss_attrib: u16,
    pub ss_limit: u32,
    pub ss_base: u64,

    pub ds_selector: u16,
    pub ds_attrib: u16,
    pub ds_limit: u32,
    pub ds_base: u64,

    pub fs_selector: u16,
    pub fs_attrib: u16,
    pub fs_limit: u32,
    pub fs_base: u64,

    pub gs_selector: u16,
    pub gs_attrib: u16,
    pub gs_limit: u32,
    pub gs_base: u64,

    pub gdtr_selector: u16,
    pub gdtr_attrib: u16,
    pub gdtr_limit: u32,
    pub gdtr_base: u64,

    pub ldtr_selector: u16,
    pub ldtr_attrib: u16,
    pub ldtr_limit: u32,
    pub ldtr_base: u64,

    pub idtr_selector: u16,
    pub idtr_attrib: u16,
    pub idtr_limit: u32,
    pub idtr_base: u64,

    pub tr_selector: u16,
    pub tr_attrib: u16,
    pub tr_limit: u32,
    pub tr_base: u64,

    pub reserved1: [u8; 43],
    pub cpl: u8,
    pub reserved2: u32,
    pub efer: u64,
    pub reserved3: [u8; 112],
    pub cr4: u64,
    pub cr3: u64,
    pub cr0: u64,
    pub dr7: u64,
    pub dr6: u64,
    pub rflags: u64,
    pub rip: u64,
    pub reserved4: [u8; 88],
    pub rsp: u64,
    pub reserved5: [u8; 24],
    pub rax: u64,
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub sf_mask: u64,
    pub kernel_gs_base: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub cr2: u64,
    pub reserved6: [u8; 32usize],
    pub gpat: u64,

    /// Guest DebugCtl MSR—only used if hardware acceleration of LBR
    /// virtualization is supported and enabled by setting the
    /// LBR_VIRTUALIZATION_ENABLE bit of the VMCB control area.
    //pub dbg_ctl: DebugCtl,
    pub dbg_ctl: u64,

    /// Guest LastBranchFromIP MSR—only used if hardware acceleration of LBR
    /// virtualization is supported and enabled.
    pub br_from: u64,

    /// Guest LastBranchToIP MSR—only used if hardware acceleration of LBR
    /// virtualization is supported and enabled.
    pub br_to: u64,

    /// Guest LastIntFromIP MSR—Only used if hardware acceleration of LBR
    /// virtualization is supported and enabled.
    pub last_excep_from: u64,
    pub last_excep_to: u64,
}

impl Context {
    pub fn capture() -> Self {
        let gdt = sgdt();
        let idt = sidt();
        
        Self {
            // Control Registers
            cr0: unsafe { controlregs::cr0().bits() as u64 },
            cr3: unsafe { controlregs::cr3()},
            cr4: unsafe { controlregs::cr4().bits() as u64 },

            // Debug Register
            dr7: unsafe { debugregs::dr7().0 as u64 },

            // RSP and RIP
            rsp: bits64::registers::rsp(),
            rip: bits64::registers::rip(),

            // RFLAGS
            rflags: bits64::rflags::read().bits(),

            // Segment Selector
            cs_selector: segmentation::cs().bits(),
            ss_selector: segmentation::ss().bits(),
            ds_selector: segmentation::ds().bits(),
            es_selector: segmentation::es().bits(),
            fs_selector: segmentation::fs().bits(),
            gs_selector: segmentation::gs().bits(),
            ldtr_selector: unsafe { dtables::ldtr().bits() },
            tr_selector: unsafe { task::tr().bits() },

            // Segment Limit
            cs_limit: Self::segment_limit(segmentation::cs().bits()),
            ss_limit: Self::segment_limit(segmentation::ss().bits()),
            ds_limit: Self::segment_limit(segmentation::ds().bits()),
            es_limit: Self::segment_limit(segmentation::es().bits()),
            fs_limit: Self::segment_limit(segmentation::fs().bits()),
            gs_limit: Self::segment_limit(segmentation::gs().bits()),

            ldtr_limit: unsafe { Self::segment_limit(dtables::ldtr().bits()) },
            tr_limit: unsafe { Self::segment_limit(task::tr().bits()) },

            // GDTR and IDTR Limit/Base


            gdtr_base: gdt.base.as_u64(),
            gdtr_limit: gdt.limit as _,

            idtr_base: idt.base.as_u64(),
            idtr_limit: idt.limit as _,

            // Segment Access Writes
            cs_attrib: Self::segment_access_right(segmentation::cs().bits(), gdt.base.as_u64()),
            ss_attrib: Self::segment_access_right(segmentation::ss().bits(), gdt.base.as_u64()),
            ds_attrib: Self::segment_access_right(segmentation::ds().bits(), gdt.base.as_u64()),
            es_attrib: Self::segment_access_right(segmentation::es().bits(), gdt.base.as_u64()),
            fs_attrib: Self::segment_access_right(segmentation::fs().bits(), gdt.base.as_u64()),
            gs_attrib: Self::segment_access_right(segmentation::gs().bits(), gdt.base.as_u64()),
            ldtr_attrib: unsafe { Self::segment_access_right(dtables::ldtr().bits(), gdt.base.as_u64()) },
            tr_attrib: unsafe { Self::segment_access_right(task::tr().bits(), gdt.base.as_u64()) },


            // Segment CS, SS, DS, ES Base
            cs_base: Self::get_segment_base(gdt.base.as_u64() as _, segmentation::cs().bits()),
            ss_base: Self::get_segment_base(gdt.base.as_u64() as _, segmentation::ss().bits()),
            ds_base: Self::get_segment_base(gdt.base.as_u64() as _, segmentation::ds().bits()),
            es_base: Self::get_segment_base(gdt.base.as_u64() as _, segmentation::es().bits()),

            ldtr_base: unsafe { Self::get_segment_base(gdt.base.as_u64() as _, dtables::ldtr().bits()) },
            tr_base: unsafe { Self::get_segment_base(gdt.base.as_u64() as _, task::tr().bits()) },

            // MSRs
            dbg_ctl: unsafe { msr::rdmsr(msr::IA32_DEBUGCTL) },
            sysenter_cs: unsafe { msr::rdmsr(msr::IA32_SYSENTER_CS) },
            sysenter_esp: unsafe { msr::rdmsr(msr::IA32_SYSENTER_ESP) },
            sysenter_eip: unsafe { msr::rdmsr(msr::IA32_SYSENTER_EIP) },

            fs_base: unsafe { msr::rdmsr(msr::IA32_FS_BASE) },
            gs_base: unsafe { msr::rdmsr(msr::IA32_GS_BASE) },
            gdtr_selector: 0,
            gdtr_attrib: 0,
            idtr_selector: 0,
            idtr_attrib: 0,
            reserved1: [0; 43],
            cpl: 0,
            reserved2: 0,
            efer: 0,
            reserved3: [0; 112],
            dr6: 0,
            reserved4: [0; 88],
            reserved5: [0; 24],
            rax: 0,
            star: 0,
            lstar: 0,
            cstar: 0,
            sf_mask: 0,
            kernel_gs_base: 0,
            cr2: 0,
            reserved6: [0; 32],
            gpat: 0,
            br_from: 0,
            br_to: 0,
            last_excep_from: 0,
            last_excep_to: 0,
        }
    }

    /* 
    pub fn build(&mut self) {
        // Control Registers
        self.cr0 = unsafe { controlregs::cr0().bits() as u64 };
        self.cr3 = unsafe { controlregs::cr3()};
        self.cr4 = unsafe { controlregs::cr4().bits() as u64 };

        // Debug Register
        self.dr7 = unsafe { debugregs::dr7().0 as u64 };
        
        // RSP and RIP
        self.rsp = bits64::registers::rsp();
        self.rip = bits64::registers::rip();

        // RFLAGS
        self.rflags = bits64::rflags::read().bits();

        // Segment Selector
        self.cs_selector = segmentation::cs().bits();
        self.ss_selector = segmentation::ss().bits();
        self.ds_selector = segmentation::ds().bits();
        self.es_selector = segmentation::es().bits();
        self.fs_selector = segmentation::fs().bits();
        self.gs_selector = segmentation::gs().bits();
        self.ldtr_selector = unsafe { dtables::ldtr().bits() };
        self.tr_selector = unsafe { task::tr().bits() };

        // Segment Limit
        self.cs_limit = Self::segment_limit(segmentation::cs().bits());
        self.ss_limit = Self::segment_limit(segmentation::ss().bits());
        self.ds_limit = Self::segment_limit(segmentation::ds().bits());
        self.es_limit = Self::segment_limit(segmentation::es().bits());
        self.fs_limit = Self::segment_limit(segmentation::fs().bits());
        self.gs_limit = Self::segment_limit(segmentation::gs().bits());
        
        self.ldtr_limit = unsafe { Self::segment_limit(dtables::ldtr().bits()) };
        self.tr_limit = unsafe { Self::segment_limit(task::tr().bits()) };

        // GDTR and IDTR Limit/Base
        let gdt = sgdt();
        let idt = sidt();

        self.gdtr_base = gdt.base.as_u64();
        self.gdtr_limit = gdt.limit as _;

        self.idtr_base = idt.base.as_u64();
        self.idtr_limit = idt.limit as _;

        // Segment Access Writes
        self.cs_attrib = Self::segment_access_right(segmentation::cs().bits(), gdt.base.as_u64());
        self.ss_attrib = Self::segment_access_right(segmentation::ss().bits(), gdt.base.as_u64());
        self.ds_attrib = Self::segment_access_right(segmentation::ds().bits(), gdt.base.as_u64());
        self.es_attrib = Self::segment_access_right(segmentation::es().bits(), gdt.base.as_u64());
        self.fs_attrib = Self::segment_access_right(segmentation::fs().bits(), gdt.base.as_u64());
        self.gs_attrib = Self::segment_access_right(segmentation::gs().bits(), gdt.base.as_u64());
        self.ldtr_attrib = unsafe { Self::segment_access_right(dtables::ldtr().bits(), gdt.base.as_u64()) };
        self.tr_attrib = unsafe { Self::segment_access_right(task::tr().bits(), gdt.base.as_u64()) };

        // Segment CS, SS, DS, ES Base
        self.cs_base = Self::get_segment_base(gdt.base.as_u64() as _, segmentation::cs().bits());
        self.ss_base = Self::get_segment_base(gdt.base.as_u64() as _, segmentation::ss().bits());
        self.ds_base = Self::get_segment_base(gdt.base.as_u64() as _, segmentation::ds().bits());
        self.es_base = Self::get_segment_base(gdt.base.as_u64() as _, segmentation::es().bits());
        
        self.ldtr_base = unsafe { Self::get_segment_base(gdt.base.as_u64() as _, dtables::ldtr().bits()) };
        self.tr_base = unsafe { Self::get_segment_base(gdt.base.as_u64() as _, task::tr().bits()) };

        // MSRs
        self.dbg_ctl = unsafe { msr::rdmsr(msr::IA32_DEBUGCTL) };
        self.sysenter_cs = unsafe { msr::rdmsr(msr::IA32_SYSENTER_CS) };
        self.sysenter_esp = unsafe { msr::rdmsr(msr::IA32_SYSENTER_ESP) };
        self.sysenter_eip = unsafe { msr::rdmsr(msr::IA32_SYSENTER_EIP) };

        self.fs_base = unsafe { msr::rdmsr(msr::IA32_FS_BASE) };
        self.gs_base = unsafe { msr::rdmsr(msr::IA32_GS_BASE) };
    }
    */

    fn segment_access_right(segment_selector: u16, gdt_base: u64) -> u16 {
        const RPL_MASK: u16 = 3;
        let descriptor = gdt_base + (segment_selector & !RPL_MASK) as u64;

        let descriptor = descriptor as *mut u64 as *mut SegmentDescriptor;
        let descriptor = unsafe { descriptor.read_volatile() };

        let mut attribute = SegmentAttribute(0);
        attribute.set_type(descriptor.get_type() as u16);
        attribute.set_system(descriptor.get_system() as u16);
        attribute.set_dpl(descriptor.get_dpl() as u16);
        attribute.set_present(descriptor.get_present() as u16);
        attribute.set_avl(descriptor.get_avl() as u16);
        attribute.set_long_mode(descriptor.get_long_mode() as u16);
        attribute.set_default_bit(descriptor.get_default_bit() as u16);
        attribute.set_granularity(descriptor.get_granularity() as u16);

        attribute.0
    }

    fn segment_limit(selector: u16) -> u32 {
        let limit: u32;
        unsafe {
            asm!("lsl {0:e}, {1:x}", out(reg) limit, in(reg) selector, options(nostack, nomem));
        }
        limit
    }

    pub fn get_segment_base(gdt_base: *const usize, segment_selector: u16) -> u64 {
        const RPL_MASK: u16 = 3;
    
        let mut segment_base = 0u64;
    
        if segment_selector == 0 {
            return segment_base;
        }
    
        let descriptor = gdt_base as u64 + ((segment_selector & !RPL_MASK) * 8) as u64;
    
        let descriptor = descriptor as *mut u64 as *mut SegmentDescriptor;
        let descriptor = unsafe { descriptor.read_volatile() };
    
        segment_base |= descriptor.get_base_low() as u64;
        segment_base |= descriptor.get_base_middle() << 16;
        segment_base |= descriptor.get_base_high() << 24;
    
        if descriptor.get_system() == 0 {
            let expanded_descriptor = unsafe {
                (gdt_base.wrapping_add((segment_selector & !RPL_MASK) as usize) as *const Descriptor)
                    .read_volatile()
            };
            segment_base |= (expanded_descriptor.lower as u64) << 32;
        }
    
        segment_base
    }
        
}