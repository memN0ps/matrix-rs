use core::ptr;

use alloc::boxed::Box;
use bitfield::BitMut;
use kernel_alloc::PhysicalAllocator;
use x86::bits64::paging::BASE_PAGE_SIZE;
use crate::{vmcs_region::VmcsRegion, vmxon_region::VmxonRegion, addresses::{physical_address, PhysicalAddress}, context::Context, nt::KTRAP_FRAME, error::HypervisorError, support};

pub const KERNEL_STACK_SIZE: usize = 0x6000;
pub const STACK_CONTENTS_SIZE: usize = KERNEL_STACK_SIZE
    - (core::mem::size_of::<*mut u64>() * 6)
    - core::mem::size_of::<KTRAP_FRAME>();

#[repr(C, align(4096))]
pub struct HostStackLayout {
    pub stack_contents: [u8; STACK_CONTENTS_SIZE],
    //pub trap_frame: Box<KTRAP_FRAME, PhysicalAllocator>,

    /// HostRsp
    pub guest_vmcs_pa: u64,
    pub host_vmcs_pa: u64,

    pub self_data: *mut u64, // Needed for the `vmlaunch` assembly function
    //pub shared_data: NonNull<SharedData>,

    // To keep HostRsp 16 bytes aligned
    pub padding_1: u64,
    pub reserved_1: u64,
}

pub struct VcpuData {
    /// The virtual and physical address of the Vmcs naturally aligned 4-KByte region of memory
    pub vmcs_region: Box<VmcsRegion, PhysicalAllocator>,
    pub vmcs_region_physical_address: u64,

    /// The virtual and physical address of the Vmxon naturally aligned 4-KByte region of memory
    pub vmxon_region: Box<VmxonRegion, PhysicalAllocator>,
    pub vmxon_region_physical_address: u64,
}

impl VcpuData {
    pub fn new(context: Context) -> Result<Box<Self>, HypervisorError> {
        
        let instance = Self {
            vmcs_region: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            vmcs_region_physical_address: 0,
            vmxon_region: unsafe { Box::try_new_zeroed_in(PhysicalAllocator)?.assume_init() },
            vmxon_region_physical_address: 0,
        };

        log::info!("Box::new(instance)");
        let mut instance = Box::new(instance);

        //instance.host_stack_layout.self_data = &mut *instance as *mut _ as _;
                
        //instance.guest_vmcs.save_area.build(context);

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
}