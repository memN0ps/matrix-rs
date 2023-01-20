use x86::{
    controlregs::{cr0, cr4, cr4_write, Cr0, Cr4},
    cpuid::CpuId,
    current::vmx::vmxon,
    msr::{
        rdmsr, wrmsr, IA32_FEATURE_CONTROL, IA32_VMX_BASIC, IA32_VMX_CR0_FIXED0,
        IA32_VMX_CR0_FIXED1, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1,
    },
};

pub struct VMX {
    cpuid: CpuId,
}

impl VMX {
    /// Create a new VMX instance.
    pub fn new() -> Self {
        Self {
            cpuid: CpuId::new(),
        }
    }

    /// Check to see if CPU is Intel (“GenuineIntel”).
    pub fn has_intel_cpu(&self) -> bool {
        if let Some(vi) = self.cpuid.get_vendor_info() {
            if vi.as_str() == "GenuineIntel" {
                return true;
            }
        }
        return false;
    }

    /// Check processor supports for Virtual Machine Extension (VMX) technology - CPUID.1:ECX.VMX\[bit 5] = 1 (Intel Manual: 24.6 Discovering Support for VMX)
    pub fn has_vmx_support(&self) -> bool {
        if let Some(fi) = self.cpuid.get_feature_info() {
            if fi.has_vmx() {
                return true;
            }
        }
        return false;
    }

    /// Enables Virtual Machine Extensions - CR4.VMXE\[bit 13] = 1 (Intel Manual: 24.7 Enabling and Entering VMX Operation)
    pub fn enable_vmx(&self) {
        let mut cr4 = unsafe { cr4() };
        cr4.set(Cr4::CR4_ENABLE_VMX, true);
        unsafe { cr4_write(cr4) };
    }

    /// Check if we need to set bits in IA32_FEATURE_CONTROL (Intel Manual: 24.7 Enabling and Entering VMX Operation)
    pub fn set_feature_control_bits(&self) -> bool {
        const VMX_LOCK_BIT: u64 = 1 << 0;
        const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

        let ia32_feature_control = unsafe { rdmsr(IA32_FEATURE_CONTROL) };

        if (ia32_feature_control & VMX_LOCK_BIT) == 0 {
            unsafe {
                wrmsr(
                    IA32_FEATURE_CONTROL,
                    VMXON_OUTSIDE_SMX | VMX_LOCK_BIT | ia32_feature_control,
                )
            };
        } else if (ia32_feature_control & VMXON_OUTSIDE_SMX) == 0 {
            return false;
        }

        return true;
    }

    /// Set the mandatory bits in CR0 and clear bits that are mandatory zero (Intel Manual: 24.8 Restrictions on VMX Operation)
    pub fn set_cr0_bits(&self) {
        let ia32_vmx_cr0_fixed0 = unsafe { rdmsr(IA32_VMX_CR0_FIXED0) };
        let ia32_vmx_cr0_fixed1 = unsafe { rdmsr(IA32_VMX_CR0_FIXED1) };

        let mut cr0 = unsafe { cr0() };

        cr0 |= Cr0::from_bits_truncate(ia32_vmx_cr0_fixed0 as usize);
        cr0 &= Cr0::from_bits_truncate(ia32_vmx_cr0_fixed1 as usize);

        unsafe { x86::controlregs::cr0_write(cr0) };
    }

    /// Set the mandatory bits in CR4 and clear bits that are mandatory zero (Intel Manual: 24.8 Restrictions on VMX Operation)
    pub fn set_cr4_bits(&self) {
        let ia32_vmx_cr4_fixed0 = unsafe { rdmsr(IA32_VMX_CR4_FIXED0) };
        let ia32_vmx_cr4_fixed1 = unsafe { rdmsr(IA32_VMX_CR4_FIXED1) };

        let mut cr4 = unsafe { cr4() };

        cr4 |= Cr4::from_bits_truncate(ia32_vmx_cr4_fixed0 as usize);
        cr4 &= Cr4::from_bits_truncate(ia32_vmx_cr4_fixed1 as usize);

        unsafe { cr4_write(cr4) };
    }

    /// Get the Virtual Machine Control Structure revision identifier (VMCS revision ID) (Intel Manual: 25.11.5 VMXON Region)
    pub fn get_vmcs_revision_id(&self) -> u32 {
        let vmcs_id = unsafe { (rdmsr(IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF };
        return vmcs_id;
    }

    /// Allocate a naturally aligned 4-KByte region of memory that a logical processor may use to support VMX operation (Intel Manual: 25.11.5 VMXON Region)
    pub fn allocate_vmxon_region(&self) {
        // allocate some memory below
        // MmAllocateContiguousMemory
        // zero out the memory

        //might need to zero it out using this or another way
        //std::ptr::write_bytes(vmx_region, 0, vmx_region_size / core::mem::size_of::<u32>());
        //std::ptr::write(vmx_region, get_vmcs_revision_id());

        self.get_vmcs_revision_id();
        // Enable VMX
        unsafe { vmxon(0x00).expect("Failed to call vmxon") }; //addy
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
}
