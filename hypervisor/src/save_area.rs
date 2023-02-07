use core::arch::asm;
use x86::{
    controlregs::{cr2, cr3},
    msr::{rdmsr, IA32_EFER, IA32_PAT},
};
use x86_64::{
    instructions::tables::{sgdt, sidt},
    registers::control::{Cr0, Cr4},
};

use crate::{context::Context, segmentation::{SegmentDescriptor, SegmentAttribute}, msr::DebugCtl};

#[repr(C)]
pub struct SaveArea {
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
    pub dbg_ctl: DebugCtl,

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
//const_assert_eq!(core::mem::size_of::<SaveArea>(), 0x298);

impl SaveArea {
    // See: https://github.com/tandasat/SimpleSvm/blob/master/SimpleSvm/SimpleSvm.cpp#L893
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

    // See: https://www.felixcloutier.com/x86/lsl
    fn segment_limit(selector: u16) -> u32 {
        let limit: u32;
        unsafe {
            asm!("lsl {0:e}, {1:x}", out(reg) limit, in(reg) selector, options(nostack, nomem));
        }
        limit
    }

    pub fn new(context: Context) -> Self {
        let gdt = sgdt();
        let idt = sidt();

        Self {
            gdtr_base: gdt.base.as_u64(),
            gdtr_limit: gdt.limit as _,

            idtr_base: idt.base.as_u64(),
            idtr_limit: idt.limit as _,

            cs_limit: Self::segment_limit(context.seg_cs),
            ds_limit: Self::segment_limit(context.seg_ds),
            es_limit: Self::segment_limit(context.seg_es),
            ss_limit: Self::segment_limit(context.seg_ss),

            cs_selector: context.seg_cs,
            ds_selector: context.seg_ds,
            es_selector: context.seg_es,
            ss_selector: context.seg_ss,

            cs_attrib: Self::segment_access_right(context.seg_cs, gdt.base.as_u64()),
            ds_attrib: Self::segment_access_right(context.seg_ds, gdt.base.as_u64()),
            es_attrib: Self::segment_access_right(context.seg_es, gdt.base.as_u64()),
            ss_attrib: Self::segment_access_right(context.seg_ss, gdt.base.as_u64()),

            gpat: unsafe { rdmsr(IA32_PAT) },
            efer: unsafe { rdmsr(IA32_EFER) },
            cr0: Cr0::read_raw(),
            cr2: unsafe { cr2() } as _,
            cr3: unsafe { cr3() },
            cr4: Cr4::read_raw(),
            rflags: context.e_flags as u64,
            rsp: context.rsp,
            rip: context.rip,

            ..Default::default()
        }
    }

    pub fn build(&mut self, context: Context) {
        // Like this: https://github.com/tandasat/SimpleSvm/blob/master/SimpleSvm/SimpleSvm.cpp#L1053

        // Capture the current GDT and IDT to use as initial values of the guest
        // mode.
        //
        // See:
        // - https://en.wikipedia.org/wiki/Global_Descriptor_Table
        // - https://en.wikipedia.org/wiki/Interrupt_descriptor_table
        //
        let gdt = sgdt();
        let idt = sidt();

        self.gdtr_base = gdt.base.as_u64();
        self.gdtr_limit = gdt.limit as _;

        self.idtr_base = idt.base.as_u64();
        self.idtr_limit = idt.limit as _;

        self.cs_limit = Self::segment_limit(context.seg_cs);
        self.ds_limit = Self::segment_limit(context.seg_ds);
        self.es_limit = Self::segment_limit(context.seg_es);
        self.ss_limit = Self::segment_limit(context.seg_ss);

        self.cs_selector = context.seg_cs;
        self.ds_selector = context.seg_ds;
        self.es_selector = context.seg_es;
        self.ss_selector = context.seg_ss;

        self.cs_attrib = Self::segment_access_right(context.seg_cs, gdt.base.as_u64());
        self.ds_attrib = Self::segment_access_right(context.seg_ds, gdt.base.as_u64());
        self.es_attrib = Self::segment_access_right(context.seg_es, gdt.base.as_u64());
        self.ss_attrib = Self::segment_access_right(context.seg_ss, gdt.base.as_u64());

        self.gpat = unsafe { rdmsr(IA32_PAT) };
        self.efer = unsafe { rdmsr(IA32_EFER) };
        self.cr0 = Cr0::read_raw();
        self.cr2 = unsafe { cr2() } as _;
        self.cr3 = unsafe { cr3() };
        self.cr4 = Cr4::read_raw();
        self.rflags = context.e_flags as u64;
        self.rsp = context.rsp;
        self.rip = context.rip;
    }
    
}

impl Default for SaveArea {
    fn default() -> Self {
        Self {
            es_selector: 0,
            es_attrib: 0,
            es_limit: 0,
            es_base: 0,
            cs_selector: 0,
            cs_attrib: 0,
            cs_limit: 0,
            cs_base: 0,
            ss_selector: 0,
            ss_attrib: 0,
            ss_limit: 0,
            ss_base: 0,
            ds_selector: 0,
            ds_attrib: 0,
            ds_limit: 0,
            ds_base: 0,
            fs_selector: 0,
            fs_attrib: 0,
            fs_limit: 0,
            fs_base: 0,
            gs_selector: 0,
            gs_attrib: 0,
            gs_limit: 0,
            gs_base: 0,
            gdtr_selector: 0,
            gdtr_attrib: 0,
            gdtr_limit: 0,
            gdtr_base: 0,
            ldtr_selector: 0,
            ldtr_attrib: 0,
            ldtr_limit: 0,
            ldtr_base: 0,
            idtr_selector: 0,
            idtr_attrib: 0,
            idtr_limit: 0,
            idtr_base: 0,
            tr_selector: 0,
            tr_attrib: 0,
            tr_limit: 0,
            tr_base: 0,
            reserved1: [0u8; 43],
            cpl: 0,
            reserved2: 0,
            efer: 0,
            reserved3: [0u8; 112],
            cr4: 0,
            cr3: 0,
            cr0: 0,
            dr7: 0,
            dr6: 0,
            rflags: 0,
            rip: 0,
            reserved4: [0u8; 88],
            rsp: 0,
            reserved5: [0u8; 24],
            rax: 0,
            star: 0,
            lstar: 0,
            cstar: 0,
            sf_mask: 0,
            kernel_gs_base: 0,
            sysenter_cs: 0,
            sysenter_esp: 0,
            sysenter_eip: 0,
            cr2: 0,
            reserved6: [0u8; 32],
            gpat: 0,
            dbg_ctl: DebugCtl(0),
            br_from: 0,
            br_to: 0,
            last_excep_from: 0,
            last_excep_to: 0,
        }
    }
}