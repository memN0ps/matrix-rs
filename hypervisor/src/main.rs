use x86::{cpuid::CpuId, msr::{rdmsr, IA32_FEATURE_CONTROL, IA32_VMX_CR0_FIXED0, IA32_VMX_CR0_FIXED1, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1, IA32_VMX_BASIC}, current::vmx::vmxon};

fn main() {
    let cpuid = CpuId::new();
    
    // 
    // 1. Discover Support for Virtual Machine Extension (VMX)
    //

    if !is_intel_cpu(&cpuid) {
        println!("[-] Error: Intel CPU is not detected");
    }

    if !has_vmx_features(&cpuid) {
        println!("[-] Error: VMX is not supported");
    }

    //
    // 2. Enable and Enter VMX Operation
    //

    allocate_vmxon_region(vmx_region, 4000);
    set_cr0_bits();
    set_cr4_bits();
    
    unsafe { vmxon(addr) };

    //unsafe { rdmsr(IA32_FEATURE_CONTROL) };    
}

/// Check if current CPU is Intel
/// returns true if get_vendor_info() returns “GenuineIntel”, returns false otherwise
fn is_intel_cpu(cpuid: &CpuId) -> bool {
    if let Some(vi) = cpuid.get_vendor_info() {
        if vi.as_str() == "GenuineIntel" {
           return true;
        } 
    }
    return false;
}

/// Check to see if the processor supports Virtual Machine Extension (VMX) technology,
/// returns true if it does.
fn has_vmx_features(cpuid: &CpuId) -> bool {
    if let Some(fi) = cpuid.get_feature_info() {
        if fi.has_vmx() {
            return true;
        }
    }
    return false;
}

fn set_cr0_bits() {
    let fixed0 = unsafe { rdmsr(IA32_VMX_CR0_FIXED0) };
    let fixed1 = unsafe { rdmsr(IA32_VMX_CR0_FIXED1) };

    let mut cr0 = unsafe { x86::controlregs::cr0() };
    
    cr0 |= x86::controlregs::Cr0::from_bits_truncate(fixed0 as usize);
    cr0 &= x86::controlregs::Cr0::from_bits_truncate(fixed1 as usize);
    
    unsafe { x86::controlregs::cr0_write(cr0) };

}


fn set_cr4_bits() {

    /*
    A better way to do it. 
    ---start--
    */
    unsafe {
        let cr4 = x86::controlregs::cr4();
        let cr4 = cr4 | x86::controlregs::Cr4::CR4_ENABLE_PSE;
        x86::controlregs::cr4_write(x86::controlregs::Cr4::CR4_ENABLE_VMX);
    }
    /*
    --end--
    */

    unsafe { x86::controlregs::cr4_write(x86::controlregs::Cr4::CR4_ENABLE_VMX) };

    let fixed0 = unsafe { rdmsr(IA32_VMX_CR4_FIXED0) };
    let fixed1 = unsafe { rdmsr(IA32_VMX_CR4_FIXED1) };

    let mut cr4 = unsafe { x86::controlregs::cr4() };
    
    cr4 |= x86::controlregs::Cr4::from_bits_truncate(fixed0 as usize);
    cr4 &= x86::controlregs::Cr4::from_bits_truncate(fixed1 as usize);

    unsafe { x86::controlregs::cr4_write(cr4) };
}

fn allocate_vmxon_region(vmx_region: *mut u32, vmx_region_size: usize) {
    // allocate some memory below
    //MmAllocateContiguousMemory
    // zero out the memory

    //might need to zero it out using this or another way
    unsafe { 
        std::ptr::write_bytes(vmx_region, 0, vmx_region_size / core::mem::size_of::<u32>());
        std::ptr::write(vmx_region, get_vmcs_revision_id());
    }
}

/// gets the Virtual Machine Control Structure Identifier (VMCS ID)
fn get_vmcs_revision_id() -> u32 {
    let vmcs_id = unsafe { (rdmsr(IA32_VMX_BASIC)  as u32) & 0x7FFF_FFFF };
    return vmcs_id;
}

fn virtual_to_physical_address(va: *mut usize) -> u64 {
    //return MmGetPhysicalAddress().QuadPart;
}

fn physical_to_virtual_address(pa: u64) -> u64 {
    //return MmGetVirtualForPhysical();
    //let physical_address = unsafe { std::mem::zeroed::<PHYSICAL_ADDRESS>() };
}