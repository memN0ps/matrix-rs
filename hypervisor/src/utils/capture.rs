#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use {core::fmt, static_assertions::const_assert_eq};

#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy)]
pub struct XSAVE_FORMAT {
    pub ControlWord: u16,
    pub StatusWord: u16,
    pub TagWord: u8,
    pub Reserved1: u8,
    pub ErrorOpcode: u16,
    pub ErrorOffset: u32,
    pub ErrorSelector: u16,
    pub Reserved2: u16,
    pub DataOffset: u32,
    pub DataSelector: u16,
    pub Reserved3: u16,
    pub MxCsr: u32,
    pub MxCsr_Mask: u32,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 16],
    pub Reserved4: [u8; 96],
}

#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy)]
pub union CONTEXT_0 {
    pub FltSave: XSAVE_FORMAT,
    pub Anonymous: CONTEXT_0_0,
}

#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy)]
pub struct CONTEXT_0_0 {
    pub Header: [M128A; 2],
    pub Legacy: [M128A; 8],
    pub Xmm0: M128A,
    pub Xmm1: M128A,
    pub Xmm2: M128A,
    pub Xmm3: M128A,
    pub Xmm4: M128A,
    pub Xmm5: M128A,
    pub Xmm6: M128A,
    pub Xmm7: M128A,
    pub Xmm8: M128A,
    pub Xmm9: M128A,
    pub Xmm10: M128A,
    pub Xmm11: M128A,
    pub Xmm12: M128A,
    pub Xmm13: M128A,
    pub Xmm14: M128A,
    pub Xmm15: M128A,
}

pub type CONTEXT_FLAGS = u32;

#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy)]
pub struct CONTEXT {
    // https://docs.rs/windows-sys/0.52.0/windows_sys/Win32/System/Diagnostics/Debug/struct.CONTEXT.html
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: CONTEXT_FLAGS,
    pub MxCsr: u32,
    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: u32,
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,
    pub Rip: u64,
    pub Anonymous: CONTEXT_0,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

impl fmt::Debug for CONTEXT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CONTEXT {\n")?;

        // General-purpose registers and other fields in 4 columns
        write!(
            f,
            "  P1Home: {:#018x}, P2Home: {:#018x}, P3Home: {:#018x}, P4Home: {:#018x}\n",
            self.P1Home, self.P2Home, self.P3Home, self.P4Home
        )?;
        write!(
            f,
            "  P5Home: {:#018x}, P6Home: {:#018x}, ContextFlags: {:?}, MxCsr: {:#010x}\n",
            self.P5Home, self.P6Home, self.ContextFlags, self.MxCsr
        )?;
        write!(
            f,
            "  SegCs: {:#06x}, SegDs: {:#06x}, SegEs: {:#06x}, SegFs: {:#06x}\n",
            self.SegCs, self.SegDs, self.SegEs, self.SegFs
        )?;
        write!(
            f,
            "  SegGs: {:#06x}, SegSs: {:#06x}, EFlags: {:#010x}, Dr0: {:#018x}\n",
            self.SegGs, self.SegSs, self.EFlags, self.Dr0
        )?;
        write!(
            f,
            "  Dr1: {:#018x}, Dr2: {:#018x}, Dr3: {:#018x}, Dr6: {:#018x}\n",
            self.Dr1, self.Dr2, self.Dr3, self.Dr6
        )?;
        write!(
            f,
            "  Dr7: {:#018x}, Rax: {:#018x}, Rcx: {:#018x}, Rdx: {:#018x}\n",
            self.Dr7, self.Rax, self.Rcx, self.Rdx
        )?;
        write!(
            f,
            "  Rbx: {:#018x}, Rsp: {:#018x}, Rbp: {:#018x}, Rsi: {:#018x}\n",
            self.Rbx, self.Rsp, self.Rbp, self.Rsi
        )?;
        write!(
            f,
            "  Rdi: {:#018x}, R8: {:#018x}, R9: {:#018x}, R10: {:#018x}\n",
            self.Rdi, self.R8, self.R9, self.R10
        )?;
        write!(
            f,
            "  R11: {:#018x}, R12: {:#018x}, R13: {:#018x}, R14: {:#018x}\n",
            self.R11, self.R12, self.R13, self.R14
        )?;
        write!(
            f,
            "  R15: {:#018x}, Rip: {:#018x}, VectorControl: {:#018x}, DebugControl: {:#018x}\n",
            self.R15, self.Rip, self.VectorControl, self.DebugControl
        )?;
        write!(f, "  LastBranchToRip: {:#018x}, LastBranchFromRip: {:#018x}, LastExceptionToRip: {:#018x}, LastExceptionFromRip: {:#018x}\n", self.LastBranchToRip, self.LastBranchFromRip, self.LastExceptionToRip, self.LastExceptionFromRip)?;

        // Vector registers in 4 columns
        write!(f, "  Vector Registers:\n")?;
        for i in 0..26 {
            write!(
                f,
                "    VectorRegister[{}]: {:?}, ",
                i, self.VectorRegister[i]
            )?;
            if i % 4 == 3 {
                write!(f, "\n")?;
            }
        }
        if 26 % 4 != 0 {
            write!(f, "\n")?;
        }

        f.write_str("}")
    }
}

/// Represents the state of guest registers during a VM exit.
///
/// This structure is used to capture the state of all general-purpose registers,
/// of a virtualized guest when a VM exit occurs.
/// It allows the hypervisor to inspect or modify the guest's state as necessary
/// before resuming guest execution.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.4.1 Guest Register State
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct GuestRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    // XMM registers (each represented as two u64 for 16-byte alignment)
    pub xmm0: M128A,
    pub xmm1: M128A,
    pub xmm2: M128A,
    pub xmm3: M128A,
    pub xmm4: M128A,
    pub xmm5: M128A,
    pub xmm6: M128A,
    pub xmm7: M128A,
    pub xmm8: M128A,
    pub xmm9: M128A,
    pub xmm10: M128A,
    pub xmm11: M128A,
    pub xmm12: M128A,
    pub xmm13: M128A,
    pub xmm14: M128A,
    pub xmm15: M128A,
}
const_assert_eq!(
    core::mem::size_of::<GuestRegisters>(),
    0x190 /* 400 bytes */
);

#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy, Default)]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}

impl fmt::Debug for GuestRegisters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GuestRegisters {\n")?;

        // General-purpose registers in 4 columns
        write!(
            f,
            "  rax: {:#018x}, rbx: {:#018x}, rcx: {:#018x}, rdx: {:#018x}\n",
            self.rax, self.rbx, self.rcx, self.rdx
        )?;
        write!(
            f,
            "  rsi: {:#018x}, rdi: {:#018x}, rbp: {:#018x}, r8: {:#018x}\n",
            self.rsi, self.rdi, self.rbp, self.r8
        )?;
        write!(
            f,
            "  r9: {:#018x}, r10: {:#018x}, r11: {:#018x}, r12: {:#018x}\n",
            self.r9, self.r10, self.r11, self.r12
        )?;
        write!(
            f,
            "  r13: {:#018x}, r14: {:#018x}, r15: {:#018x}, rip: {:#018x}\n",
            self.r13, self.r14, self.r15, self.rip
        )?;
        write!(
            f,
            "  rsp: {:#018x}, rflags: {:#018x}\n",
            self.rsp, self.rflags
        )?;

        // XMM registers in 4 columns
        write!(
            f,
            "  xmm0: {:?}, xmm1: {:?}, xmm2: {:?}, xmm3: {:?}\n",
            self.xmm0, self.xmm1, self.xmm2, self.xmm3
        )?;
        write!(
            f,
            "  xmm4: {:?}, xmm5: {:?}, xmm6: {:?}, xmm7: {:?}\n",
            self.xmm4, self.xmm5, self.xmm6, self.xmm7
        )?;
        write!(
            f,
            "  xmm8: {:?}, xmm9: {:?}, xmm10: {:?}, xmm11: {:?}\n",
            self.xmm8, self.xmm9, self.xmm10, self.xmm11
        )?;
        write!(
            f,
            "  xmm12: {:?}, xmm13: {:?}, xmm14: {:?}, xmm15: {:?}\n",
            self.xmm12, self.xmm13, self.xmm14, self.xmm15
        )?;

        f.write_str("}")
    }
}

impl fmt::Debug for M128A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({:#018x}, {:#018x})", self.Low, self.High)
    }
}
