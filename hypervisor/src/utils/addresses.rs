#![allow(dead_code)]

use {
    core::ops::{Deref, DerefMut},
    wdk_sys::{
        ntddk::{MmGetPhysicalAddress, MmGetVirtualForPhysical},
        PHYSICAL_ADDRESS,
    },
    x86::bits64::paging::{PAddr, BASE_PAGE_SHIFT},
};

pub struct PhysicalAddress(PAddr);

impl PhysicalAddress {
    pub fn from_pa(pa: u64) -> Self {
        Self(PAddr::from(pa))
    }

    pub fn from_pfn(pfn: u64) -> Self {
        Self(PAddr::from(pfn << BASE_PAGE_SHIFT))
    }

    pub fn from_va(va: u64) -> Self {
        Self(PAddr::from(Self::pa_from_va(va)))
    }

    pub fn va(&self) -> *mut u64 {
        Self::va_from_pa(self.0.as_u64()) as *mut u64
    }

    pub fn pfn(&self) -> u64 {
        self.0.as_u64() >> BASE_PAGE_SHIFT
    }

    pub fn pa(&self) -> u64 {
        self.0.as_u64()
    }

    pub fn pa_from_va(va: u64) -> u64 {
        unsafe { MmGetPhysicalAddress(va as _).QuadPart as u64 }
    }

    fn va_from_pa(pa: u64) -> u64 {
        let mut physical_address: PHYSICAL_ADDRESS = unsafe { core::mem::zeroed() };
        (physical_address.QuadPart) = pa as i64;

        unsafe { MmGetVirtualForPhysical(physical_address) as u64 }
    }
}

impl const Deref for PhysicalAddress {
    type Target = PAddr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl const DerefMut for PhysicalAddress {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
