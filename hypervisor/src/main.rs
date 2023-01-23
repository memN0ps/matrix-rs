#![feature(allocator_api)]
#![feature(new_uninit)]

use vmx::VMX;

mod alloc;
mod nt;
mod vmx;

fn main() {
    match init_vmm() {
        Ok(_) => log::info!("[+] VMM Initialized"),
        Err(err) => log::error!("[-] init_vmm failed: {}", err),
    }
}

fn init_vmm() -> Result<(), String> {
    //
    // 1) 24.6 Discover Support for Virtual Machine Extension (VMX)
    //

    let vmx = VMX::new();

    vmx.has_intel_cpu()?;
    log::info!("[+] CPU is Intel");

    vmx.has_vmx_support()?;
    log::info!("[+] Virtual Machine Extension (VMX) technology is supported");

    //
    // 2) 24.7 Enable and Enter VMX Operation
    //

    vmx.enable_vmx_operation()?;
    log::info!("[+] Virtual Machine Extensions (VMX) enabled");

    vmx.adjust_control_registers();

    let vmxon_pa = vmx.allocate_vmm_context()?;
    vmx.vmxon(vmxon_pa)?;
    log::info!("[+] VMXON successful!");

    //
    // 3) Load current VMCS pointer.
    //

    let vmptrld_pa = vmx.allocate_vmm_context()?;
    vmx.vmptrld(vmptrld_pa)?;
    log::info!("[+] VMPTRLD successful!");

    return Ok(());
}

//pub fn init_logical_processor() {}
