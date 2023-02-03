use bitflags::bitflags;
use x86::{vmx::{vmcs::control::{EntryControls, PrimaryControls, SecondaryControls, ExitControls}, self}, msr::{IA32_VMX_BASIC}};

use crate::{support::Support, error::HypervisorError};

bitflags! {
    pub struct VmxBasicMsr: u64 {
        const VMCS_REVISION_IDENTIFIER = 1 << 0;
        const ALWAYS0 = 1 << 31;
        const VMXON_REGION_SIZE = 1 << 32;
        const RESERVED_1 = 1 << 45;
        const VMXON_PHYSICAL_ADDRESS_WIDTH = 1 << 48;
        const DUAL_MONITOR_SMI = 1 << 49;
        const MEMORY_TYPE = 1 << 50;
        const IO_INSTRUCTION_REPORTING = 1 << 54;
        const TRUE_CONTROLS = 1 << 55;
    }
}


#[repr(C, packed)]
#[derive(Copy, Clone)]
struct VmxTrueControlSettings {
    pub control: u64,
    pub allowed_0_settings: u32,
    pub allowed_1_settings: u32,
}

impl Default for VmxTrueControlSettings {
    fn default() -> Self {
        Self { control: Default::default(), allowed_0_settings: Default::default(), allowed_1_settings: Default::default() }
    }
}

fn vmx_adjust_cv(capability_msr: u32, value: u32) -> u32 {
    let mut cap = VmxTrueControlSettings::default();
    
    cap.control = unsafe { x86::msr::rdmsr(capability_msr) };
    let mut actual = value;

    actual |= cap.allowed_0_settings;
    actual &= cap.allowed_1_settings;

    actual
}

fn vmx_adjust_entry_controls(entry_control: u32) -> u16 {
    let basic = VmxBasicMsr::from_bits_truncate(unsafe {
        x86::msr::rdmsr(IA32_VMX_BASIC)
    });
    let capability_msr = if basic.contains(VmxBasicMsr::TRUE_CONTROLS) {
        x86::msr::IA32_VMX_TRUE_ENTRY_CTLS
    } else {
        x86::msr::IA32_VMX_ENTRY_CTLS
    };

    vmx_adjust_cv(capability_msr, entry_control) as u16
}

#[allow(dead_code)]

pub fn setup_vmcs_controls() -> Result<(), HypervisorError> {

    // PrimaryControls (x86::msr::IA32_VMX_PROCBASED_CTLS)
    Support::vmwrite(vmx::vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, 
        vmx_adjust_entry_controls(PrimaryControls::HLT_EXITING.bits() | PrimaryControls::SECONDARY_CONTROLS.bits()) as u64)?;
    
    // SecondaryControls (x86::msr::IA32_VMX_PROCBASED_CTLS2)
    Support::vmwrite(vmx::vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS, 
        vmx_adjust_entry_controls(SecondaryControls::ENABLE_RDTSCP.bits() /* | SecondaryControls::ENABLE_EPT.bits() */) as u64)?;
    
    // EntryControls (x86::msr::IA32_VMX_ENTRY_CTLS)
    Support::vmwrite(vmx::vmcs::control::VMENTRY_CONTROLS, 
        vmx_adjust_entry_controls(EntryControls::IA32E_MODE_GUEST.bits()) as u64)?;

    // ExitControls (x86::msr::IA32_VMX_EXIT_CTLS)
    Support::vmwrite(vmx::vmcs::control::VMEXIT_CONTROLS, 
        vmx_adjust_entry_controls(ExitControls::HOST_ADDRESS_SPACE_SIZE.bits() | ExitControls::ACK_INTERRUPT_ON_EXIT.bits()) as u64)?;

    // PinbasedControls (x86::msr::IA32_VMX_PINBASED_CTLS)
    Support::vmwrite(vmx::vmcs::control::PINBASED_EXEC_CONTROLS, 
        vmx_adjust_entry_controls(0) as u64)?;

    Ok(())
}