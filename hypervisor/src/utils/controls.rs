use core::arch::asm;

//Credits: https://github.com/tandasat/Hypervisor-101-in-Rust/blob/main/hypervisor/src/hardware_vt/vmx.rs#L617

/// The types of the control field.
#[derive(Clone, Copy)]
pub enum VmxControl {
    PinBased,
    ProcessorBased,
    ProcessorBased2,
    VmExit,
    VmEntry,
}

pub fn adjust_vmx_controls(control: VmxControl, requested_value: u64) -> u64 {
    const IA32_VMX_BASIC_VMX_CONTROLS_FLAG: u64 = 1 << 55;

    let vmx_basic = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_BASIC) };
    let true_cap_msr_supported = (vmx_basic & IA32_VMX_BASIC_VMX_CONTROLS_FLAG) != 0;

    let cap_msr = match (control, true_cap_msr_supported) {
        (VmxControl::PinBased, true) => x86::msr::IA32_VMX_TRUE_PINBASED_CTLS,
        (VmxControl::PinBased, false) => x86::msr::IA32_VMX_PINBASED_CTLS,
        (VmxControl::ProcessorBased, true) => x86::msr::IA32_VMX_TRUE_PROCBASED_CTLS,
        (VmxControl::ProcessorBased, false) => x86::msr::IA32_VMX_PROCBASED_CTLS,
        (VmxControl::VmExit, true) => x86::msr::IA32_VMX_TRUE_EXIT_CTLS,
        (VmxControl::VmExit, false) => x86::msr::IA32_VMX_EXIT_CTLS,
        (VmxControl::VmEntry, true) => x86::msr::IA32_VMX_TRUE_ENTRY_CTLS,
        (VmxControl::VmEntry, false) => x86::msr::IA32_VMX_ENTRY_CTLS,
        // There is no TRUE MSR for IA32_VMX_PROCBASED_CTLS2. Just use
        // IA32_VMX_PROCBASED_CTLS2 unconditionally.
        (VmxControl::ProcessorBased2, _) => x86::msr::IA32_VMX_PROCBASED_CTLS2,
    };

    let capabilities = unsafe { x86::msr::rdmsr(cap_msr) };
    let allowed0 = capabilities as u32;
    let allowed1 = (capabilities >> 32) as u32;
    let mut effective_value = u32::try_from(requested_value).unwrap();
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
