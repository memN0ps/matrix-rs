use x86::{cpuid::CpuId, msr::{rdmsr, IA32_FEATURE_CONTROL, IA32_VMX_CR0_FIXED0, IA32_VMX_CR0_FIXED1, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1, IA32_VMX_BASIC, wrmsr}, current::vmx::vmxon, controlregs::{cr0_write, cr0, Cr0, Cr4, cr4, cr4_write}};

fn main() {
    let cpuid = CpuId::new();
    
    // 
    // 1. Discover Support for Virtual Machine Extension (VMX)
    //

    // Check for String “GenuineIntel”
    if !has_intel_cpu(&cpuid) {
        println!("[-] Error: Intel CPU is not detected");
    }

    // Check processor support for VMX (CPUID.1:ECX.VMX[bit 5] = 1)
    if !has_vmx_support(&cpuid) {
        println!("[-] Error: VMX is not supported");
    }


    //
    // 2. Enable and Enter VMX Operation
    //

    // Enable VMX (Set CR4 bits CR4.VMXE[bit 13] = 1)
    enable_vmx();

    set_cr4_bits();
    set_cr0_bits();

    // set feature control bits if they are not set
    if !set_feature_control_bits() {
        println!("[-] Error: VMX locked off in BIOS");
    }

    
    allocate_vmxon_region(vmx_region, 4000);
    
    // Enable VMX
    unsafe { vmxon(addr) };

    //unsafe { rdmsr(IA32_FEATURE_CONTROL) };    
}

/// Check if current CPU is Intel
/// returns true if get_vendor_info() returns “GenuineIntel”, returns false otherwise
fn has_intel_cpu(cpuid: &CpuId) -> bool {
    if let Some(vi) = cpuid.get_vendor_info() {
        if vi.as_str() == "GenuineIntel" {
           return true;
        } 
    }
    return false;
}

/// Check to see if the processor supports Virtual Machine Extension (VMX) technology,
/// returns true if it does.
fn has_vmx_support(cpuid: &CpuId) -> bool {
    if let Some(fi) = cpuid.get_feature_info() {
        if fi.has_vmx() {
            return true;
        }
    }
    return false;
}

fn enable_vmx() {
    unsafe {
        let cr4 = x86::controlregs::cr4();
        let cr4 = cr4 | x86::controlregs::Cr4::CR4_ENABLE_VMX;
        x86::controlregs::cr4_write(cr4);
    }
}


/// Set the mandatory bits in CR4 and clear bits that are mandatory zero
fn set_cr4_bits() {
    let ia32_vmx_cr4_fixed0 = unsafe { rdmsr(IA32_VMX_CR4_FIXED0) };
    let ia32_vmx_cr4_fixed1 = unsafe { rdmsr(IA32_VMX_CR4_FIXED1) };

    let mut cr4 = unsafe { x86::controlregs::cr4() };

    cr4 |= x86::controlregs::Cr4::from_bits_truncate(ia32_vmx_cr4_fixed0 as usize);
    cr4 &= x86::controlregs::Cr4::from_bits_truncate(ia32_vmx_cr4_fixed1 as usize);

    unsafe { x86::controlregs::cr4_write(cr4) };
}

/// Set the mandatory bits in CR0 and clear bits that are mandatory zero
fn set_cr0_bits() {
    let ia32_vmx_cr0_fixed0 = unsafe { rdmsr(IA32_VMX_CR0_FIXED0) };
    let ia32_vmx_cr0_fixed1 = unsafe { rdmsr(IA32_VMX_CR0_FIXED1) };

    let mut cr0 = unsafe { x86::controlregs::cr0() };

    cr0 |= x86::controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed0 as usize);
    cr0 &= x86::controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed1 as usize);

    unsafe { x86::controlregs::cr0_write(cr0) };
}


/// Check if we need to set bits in IA32_FEATURE_CONTROL
fn set_feature_control_bits() -> bool {
    const VMX_LOCK_BIT: u64 = 1 << 0;
    const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

    let ia32_feature_control = unsafe { rdmsr(IA32_FEATURE_CONTROL) };

    if (ia32_feature_control & VMX_LOCK_BIT) == 0 {
        // Lock bit not set, initialize IA32_FEATURE_CONTROL register
        unsafe { wrmsr(IA32_FEATURE_CONTROL, VMXON_OUTSIDE_SMX | VMX_LOCK_BIT | ia32_feature_control) };
    } else if (ia32_feature_control & VMXON_OUTSIDE_SMX) == 0 {
        return false; // double check if this should be true or false
    }

    return true; // double check this should be true or false
}


/// gets the Virtual Machine Control Structure Identifier (VMCS ID)
fn get_vmcs_revision_id() -> u32 {
    let vmcs_id = unsafe { (rdmsr(IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF };
    return vmcs_id;
}

/* 
fn virtual_to_physical_address(va: *mut usize) -> u64 {
    //return MmGetPhysicalAddress().QuadPart;
}

fn physical_to_virtual_address(pa: u64) -> u64 {
    //return MmGetVirtualForPhysical();
    //let physical_address = unsafe { std::mem::zeroed::<PHYSICAL_ADDRESS>() };
}
*/


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

