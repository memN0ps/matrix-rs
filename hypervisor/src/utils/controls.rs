use core::arch::asm;

pub fn vmx_adjust_entry_controls(cap_msr: u32, controls: u32) -> u64 {
    let capabilities = unsafe { x86::msr::rdmsr(cap_msr) };
    let allowed0 = capabilities as u32;
    let allowed1 = (capabilities >> 32) as u32;
    let mut effective_value = u32::try_from(controls).unwrap();
    effective_value |= allowed0;
    effective_value &= allowed1;
    u64::from(effective_value)
}

pub fn segment_limit(selector: u16) -> u32 {
    let limit: u32;
    unsafe {
        asm!("lsl {0:e}, {1:x}", out(reg) limit, in(reg) selector, options(nostack, nomem));
    }
    limit
}