use vmx::VMX;

mod vmx;

fn main() {
    //
    // 1) 24.6 Discover Support for Virtual Machine Extension (VMX)
    //

    let vmx = VMX::new();

    if !vmx.has_intel_cpu() {
        log::error!("[-] Error: Intel CPU is not detected");
    }

    if !vmx.has_vmx_support() {
        log::error!("[-] Error: VMX is not supported");
    }

    //
    // 2) 24.7 Enable and Enter VMX Operation
    //

    vmx.enable_vmx();

    vmx.set_cr0_bits();
    vmx.set_cr4_bits();

    if !vmx.set_feature_control_bits() {
        log::error!("[-] Error: VMX locked off in BIOS");
    }

    vmx.allocate_vmxon_region();
}
