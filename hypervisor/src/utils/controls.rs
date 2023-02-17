use core::arch::asm;

pub fn vmx_adjust_entry_controls(msr: u32, controls: u32) -> u64 {
    let controls = u32::try_from(controls).expect("Controls should be a 32 bit field"); // 503 953 2390
    let pair = rdmsr(msr);
    let fixed0 = pair.edx;
    let fixed1 = pair.eax;
    if controls & fixed0 != controls {
        log::warn!(
            "Requested unsupported controls for msr {:?}, fixed0 {:x} fixed1 {:x} controls {:x}",
            msr, fixed0, fixed1, controls
        );
    }
    u64::from(fixed1 | (controls & fixed0))
}

/// Represents the value of an Model specific register.
/// rdmsr returns the value with the high bits of the MSR in edx and the low bits in eax.
/// wrmsr recieves the value similarly.
pub struct MsrValuePair {
    pub edx: u32,
    pub eax: u32,
}

/// Read a model specific register as a pair of two values.
pub fn rdmsr(msr: u32) -> MsrValuePair {
    let edx: u32;
    let eax: u32;
    unsafe {
        asm!(
        "rdmsr",
         lateout("eax")(eax),
          lateout("edx")(edx),
          in("ecx")(msr as u32)
        );
    }
    MsrValuePair { edx, eax }
}

pub fn segment_limit(selector: u16) -> u32 {
    let limit: u32;
    unsafe {
        asm!("lsl {0:e}, {1:x}", out(reg) limit, in(reg) selector, options(nostack, nomem));
    }
    limit
}