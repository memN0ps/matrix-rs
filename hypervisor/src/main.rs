use vmx::VMX;

mod vmx;

fn main() {
    
    // 
    // 1. Discover Support for Virtual Machine Extension (VMX)
    //

    let vmx = VMX::new();

    if !vmx.has_intel_cpu() {
        println!("[-] Error: Intel CPU is not detected");
    }

    if !vmx.has_vmx_support() {
        println!("[-] Error: VMX is not supported");
    }


    //
    // 2. Enable and Enter VMX Operation
    //

    vmx.enable_vmx();

    vmx.set_cr4_bits();
    vmx.set_cr0_bits();

    if !vmx.set_feature_control_bits() {
        println!("[-] Error: VMX locked off in BIOS");
    }

    vmx.allocate_vmm_context();
}