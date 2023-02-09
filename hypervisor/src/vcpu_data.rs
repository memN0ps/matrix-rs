use alloc::boxed::Box;
use bitfield::BitMut;
use kernel_alloc::PhysicalAllocator;
use crate::{vmxon_region::VmxonRegion, addresses::{physical_address}, error::HypervisorError, support, vmcs::vmcs_region::VmcsRegion};

pub const KERNEL_STACK_SIZE: usize = 0x6000;
pub const STACK_CONTENTS_SIZE: usize = KERNEL_STACK_SIZE;

#[derive(Clone, Copy)]
#[repr(C, align(4096))]
pub struct HostStackLayout {
    pub stack_contents: [u8; STACK_CONTENTS_SIZE],
    //pub self_data: *mut u64, // A pointer VcpuData
}

pub struct VcpuData {
    /// The virtual and physical address of the Vmcs naturally aligned 4-KByte region of memory
    pub vmcs_region: Box<VmcsRegion, PhysicalAllocator>,
    pub vmcs_region_physical_address: u64,

    /// The virtual and physical address of the Vmxon naturally aligned 4-KByte region of memory
    pub vmxon_region: Box<VmxonRegion, PhysicalAllocator>,
    pub vmxon_region_physical_address: u64,

    pub host_stack_layout: Box<HostStackLayout, PhysicalAllocator>,
}

impl VcpuData {
    pub fn new() -> Result<Box<Self>, HypervisorError> {
        
        let instance = Self {
            vmcs_region: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            vmcs_region_physical_address: 0,
            vmxon_region: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            vmxon_region_physical_address: 0,
            host_stack_layout: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
        };

        log::info!("[+] Box::new(instance)");
        let mut instance = Box::new(instance);

        //instance.host_stack_layout.self_data = &mut *instance as *mut _ as _;
                
        log::info!("[+] init_vmxon_region");
        instance.init_vmxon_region()?;

        log::info!("[+] init_vmcs_region");
        instance.init_vmcs_region()?;

        log::info!("[+] init_vmclear");
        instance.init_vmclear()?;

        log::info!("[+] init_vmptrld");
        instance.init_vmptrld()?;

        // Host and Guest Registers
        log::info!("[+] init_vmcs_control_values");
        instance.vmcs_region.vmcs_data.init_vmcs_control_values()?;

        log::info!("[+] init_guest_register_state");
        instance.vmcs_region.vmcs_data.init_guest_register_state()?;

        log::info!("[+] init_host_register_state");
        let stack = instance.host_stack_layout.as_mut() as *const _ as u64;
        instance.vmcs_region.vmcs_data.init_host_register_state(stack)?;


        Ok(instance)
    }

    /// Allocate a naturally aligned 4-KByte VMXON region of memory to enable VMX operation (Intel Manual: 25.11.5 VMXON Region)
    pub fn init_vmxon_region(&mut self) -> Result<(), HypervisorError> {
        self.vmxon_region_physical_address = physical_address(self.vmxon_region.as_ref() as *const _ as _).as_u64();

        if self.vmxon_region_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::info!("[+] VMXON Region Virtual Address: {:p}", self.vmxon_region);
        log::info!("[+] VMXON Region Physical Addresss: 0x{:x}", self.vmxon_region_physical_address);

        self.vmxon_region.revision_id = support::get_vmcs_revision_id();
        self.vmxon_region.as_mut().revision_id.set_bit(31, false);

        support::vmxon(self.vmxon_region_physical_address)?;
        log::info!("[+] VMXON successful!");

        Ok(())
    }

    /// Allocate a naturally aligned 4-KByte VMCS region of memory (Intel Manual: 25.11.5 VMCS Region)
    pub fn init_vmcs_region(&mut self) -> Result<(), HypervisorError> {
        self.vmcs_region_physical_address = physical_address(self.vmcs_region.as_ref() as *const _ as _).as_u64();

        if self.vmcs_region_physical_address == 0 {
            return Err(HypervisorError::VirtualToPhysicalAddressFailed);
        }

        log::info!("[+] VMCS Region Virtual Address: {:p}", self.vmcs_region);
        log::info!("[+] VMCS Region Physical Addresss: 0x{:x}", self.vmcs_region_physical_address);

        self.vmcs_region.revision_id = support::get_vmcs_revision_id();
        self.vmcs_region.as_mut().revision_id.set_bit(31, false);

        log::info!("[+] VMCS successful!");

        Ok(())
    }

    /// Ensures that VMCS data maintained on the processor is copied to the VMCS region located at 4KB-aligned physical address addr and initializes some parts of it. (Intel Manual: 25.11.3 Initializing a VMCS)
    pub fn init_vmclear(&mut self) -> Result<(), HypervisorError> {
        support::vmclear(self.vmcs_region_physical_address)?;
        log::info!("[+] VMCLEAR successful!");
        Ok(())
    }

    ///Load current VMCS pointer.
    pub fn init_vmptrld(&mut self) -> Result<(), HypervisorError> {
        support::vmptrld(self.vmcs_region_physical_address)?;
        log::info!("[+] VMPTRLD successful!");
        Ok(())
    }
}