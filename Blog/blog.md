# Intel VT-x Hypervisor Development in Rust

This article will cover the development of a minimalistic Intel VT-x research hypervisor in Rust, code-named [SecretVisor](https://github.com/thesecretclub/SecretVisor), which can be found on Secret Club's GitHub. We will use the [x86 crate](https://crates.io/crates/x86) and [documentation](https://docs.rs/x86/latest/x86/), which help simplify the code.

The knowledge acquired to make this hypervisor was from reading blogs and code, notably the two excellent free hypervisor development series by [@daax_rynd](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/) and [@Intel80x86](https://rayanfam.com/). The motivation came shortly [@not_matthias](https://github.com/not-matthias/amd_hypervisor) released an AMD (SVM) Hypervisor in Rust, and the majority of the hypervisor was already developed before the legendary [@tandasat](https://github.com/tandasat/Hypervisor-101-in-Rust) released Hypervisor 101 in Rust.

## Virtual Machine Architecture

`Virtual Machine Monitor (VMM):` By abstracting and dividing the underlying hardware resources, a virtual machine monitor (VMM) is a software layer that generates and controls virtual machines (VMs), enabling several operating systems to operate on the same physical computer.

`Guest Software:` Any software that runs inside a virtual machine (VM) that is controlled by a virtual machine monitor (VMM) or hypervisor is referred to as guest software.


## Introduction to Virtual Machine Extension (VMX) Operation

An operation that the Virtual Machine Monitor (VMM) does to enter or depart a virtual machine execution mode is referred to as a VMX operation. The host system's standard operating mode and the virtualized operating mode of the guest system executing within the VM are switched via the VMX procedure. The virtualization technology in the processor supports the low-level VMX operation, which enables the VMM to construct and manage virtual machines.

## Life Cycle of Virtual Machine Monitor (VMM) Software

The Virtual Machine Monitor (VMM) can enter and leave the execution mode of virtual machines (VMs) using low-level hardware operations called `VM ENTRY` and `VM EXIT`.

Other low-level hardware operations, such as `VMXON` and `VMXOFF`, enable and disable the VMX operation, the processor's implementation of hardware virtualization that supports VMMs, respectively.

In essence, `VMXON` and `VMXOFF` allow the VMM to construct and operate virtual machines, whereas `VM ENTRY` and `VM EXIT` enable the VMM to move between the host system and the guest system.

![Interaction of a Virtual-Machine Monitor and Guests](./pictures/Interaction_of_a_Virtual-Machine_Monitor_and_Guests.png)

*Credits: Intel® 64 and IA-32 Architectures Software Developer Manual*


## Virtual-Machine Control Structure (VMCS)

A virtual machine's execution is managed and controlled by the Virtual Machine Monitor (VMM) via a virtual machine control structure (VMCS).
The virtual machine's state, the settings for the virtual processor, and the mapping between the virtual and physical resources are all contained in the VMCS.

The VMM employs a collection of low-level instructions to control the VMCS. The Virtual-Machine Control Structure Pointer (VMCS pointer), which enables the VMM to access the VMCS for a particular VM, can be read using VMPTRST and loaded using `VMPTRLD`. The VMM can alter the virtual machine's state or obtain details regarding its present state by using the commands `VMREAD` and `VMWRITE`, which are used to read and write values from and to the VMCS, respectively. When a virtual machine is terminated, or its state needs to be reset, `VMCLEAR` is used to clear the contents of the VMCS.

Each of the VMCSs assigned to a physical computer's logical processors corresponds to a particular virtual machine. As a result, the VMM can oversee and administer numerous virtual machines on a single physical device. In order to generate, monitor, and manage the execution of virtual machines on logical processors, the VMCS and related instructions give the VMM essential control and management capabilities.


## Discovering Support for Virtual Machine Extension (VMX)

When developing a hypervisor, it's crucial to determine whether Intel or AMD built the CPU because each manufacturer has a unique virtualization technology with unique capabilities and instructions. It is vital to identify the processor type and employ the proper approaches to use these technologies and guarantee that the hypervisor functions on various systems.

The CPUID instruction can be used to determine whether Virtual Machine Extension (VMX) / Intel Virtualization Technology is supported. The processor will reveal information about its features, including whether it supports VMX, when the CPUID instruction is run with the EAX register set to 1. The EAX, EBX, ECX, and EDX registers store the CPUID data for the processor. If VMX is supported by the processor, bit 5 of ECX will be set to 1. The processor does not support VMX if the bit is not set, making virtualization unavailable.


**Rust**: We check whether Intel makes the CPU by examining the `CPUID` information using the Rust x86 crate. Specifically, we check the vendor information returned by the CPUID instruction to see if it equals `"GenuineIntel"`. If the vendor information indicates an Intel CPU, we return an `Ok` result; otherwise, we return an error indicating that the hypervisor does not support the CPU.

```rust
/// Check to see if CPU is Intel (“GenuineIntel”).
pub fn has_intel_cpu() -> Result<(), HypervisorError> {
    let cpuid = CpuId::new();
    if let Some(vi) = cpuid.get_vendor_info() {
        if vi.as_str() == "GenuineIntel" {
            return Ok(());
        }
    }
    Err(HypervisorError::CPUUnsupported)
}
```

**Rust**: We check whether the processor supports Virtual Machine Extension (VMX) technology by checking if the bit 5 in the `ECX` register is set to 1 using the `CPUID` instruction. We use the Rust x86 crate to get the CPUID information and check whether the processor has VMX support by reading the feature information. If the processor supports VMX, we return an `Ok` result; otherwise, we return an error indicating that VMX is not supported.

```rust
/// Check processor supports for Virtual Machine Extension (VMX) technology - CPUID.1:ECX.VMX[bit 5] = 1 (Intel Manual: 24.6 Discovering Support for VMX)
pub fn has_vmx_support() -> Result<(), HypervisorError> {
    let cpuid = CpuId::new();
    if let Some(fi) = cpuid.get_feature_info() {
        if fi.has_vmx() {
            return Ok(());
        }
    }
    Err(HypervisorError::VMXUnsupported)
}
```

**Rust**: We use a custom `HypervisorError` enum to handle errors, which was made using [thiserror-no-std](https://crates.io/crates/thiserror-no-std) crate.

```rust
use thiserror_no_std::Error;

#[derive(Error, Debug)]
pub enum HypervisorError {
    #[error("Intel CPU not found")]
    CPUUnsupported,
    
    #[error("VMX is not supported")]
    VMXUnsupported,
    
    #[error("VMX locked off in BIOS")]
    VMXBIOSLock,
    
    #[error("Failed allocate memory via PhysicalAllocator")]
    MemoryAllocationFailed(#[from] core::alloc::AllocError),
    
    #[error("Failed to convert from virtual address to physical address")]
    VirtualToPhysicalAddressFailed,
    
    #[error("Failed to execute VMXON")]
    VMXONFailed,
    
    #[error("Failed to execute VMXOFF")]
    VMXOFFFailed,
    
    #[error("Failed to execute VMCLEAR")]
    VMCLEARFailed,

    #[error("Failed to execute VMPTRLD")]
    VMPTRLDFailed,
    
    #[error("Failed to execute VMREAD")]
    VMREADFailed,
    
    #[error("Failed to execute VMWRITE")]
    VMWRITEFailed,
    
    #[error("Failed to execute VMLAUNCH")]
    VMLAUNCHFailed,

    #[error("Failed to execute VMRESUME")]
    VMRESUMEFailed,
    
    #[error("Failed to switch processor")]
    ProcessorSwitchFailed,
    
    #[error("Failed to access VCPU table")]
    VcpuIsNone,
}
```

The CPU must operate in a hardware virtualization mode to execute virtual machines, made possible by Virtual Machine Extensions (VMX). System software initially sets the `CR4.VMXE[bit 13]` to 1 to enable VMX. This bit is found in the control register `CR4`, which regulates the processor's multiple operating modes. The system software can execute the `VMXON` instruction to enter VMX operating mode once the VMX bit has been set.

Yet when `VMXON` is attempted to be executed with `CR4.VMXE = 0`, an invalid-opcode exception (`#UD`) is raised. Because VMX is not enabled, the CPU does not recognize the `VMXON` instruction, which leads to this exception. After the processor switches to VMX operation mode, the `CR4.VMXE` bit cannot be cleared. Because of this, system software must exit VMX operating mode with the `VMXOFF` instruction before `CR4.VMXE` may be cleared.

**Rust**: We have a function called `enable_vmx_operation()` that enables virtual machine extensions (VMX). We do this by setting a specific bit (bit 13) in the CR4 control register to 1. We first read the current value of `CR4` using the `controlregs::cr4()` function, then set the appropriate bit using the `set()` method of the `Cr4` struct, and finally, write the updated value back to `CR4` using the `controlregs::cr4_write()` function.

In addition to setting the `CR4` bit, we call the `set_lock_bit()` function, which sets a lock bit via the `IA32_FEATURE_CONTROL` register and logs a message indicating that the lock bit has been set. If everything goes well, we return a `Result` with an `Ok` value indicating success. If an error occurs, we return a `Result` with an `Err` value containing a `HypervisorError`.

```rust
/// Enables Virtual Machine Extensions - CR4.VMXE[bit 13] = 1 (Intel Manual: 24.7 Enabling and Entering VMX Operation)
pub fn enable_vmx_operation() -> Result<(), HypervisorError> {
    let mut cr4 = unsafe { controlregs::cr4() };
    cr4.set(controlregs::Cr4::CR4_ENABLE_VMX, true);
    unsafe { controlregs::cr4_write(cr4) };

    set_lock_bit()?;
    log::info!("[+] Lock bit set via IA32_FEATURE_CONTROL");

    Ok(())
}
```

The `IA32_FEATURE_CONTROL` MSR is a model-specific register that controls the processor's features, including VMX capability. This register is zeroed when a logical processor is reset. Bits 0 through 1 and 2 are crucial for `VMXON`. Whether it can be updated depends on the lock bit in the MSR. If the lock bit is not set, `VMXON` execution will fail, and the MSR cannot be modified until after a power-up reset. The lock bit, bit 1, bit 2, or both can be changed in the BIOS to deactivate VMX capability.

* Bit 1 activates `VMXON` in SMX mode, providing a more secure setting. If this bit is not set, `VMXON` execution in SMX mode will encounter an error.

* Bit 2 permits `VMXON` execution while SMX mode is not active. A general protection exception is triggered when this bit is attempted to be set on logical processors that cannot support VMX operation.

The `IA32_FEATURE_CONTROL` MSR and control bits in `CR4` need to be set in order to activate VMX. The lock bit, bit 1, and bit 2 enable VMX. Once enabled, processors can enter the VMX operating mode and operate virtual machines using VMX instructions.

**Rust**: We first check the current value of the `IA32_FEATURE_CONTROL` MSR register to see if the lock bit is already set. If it's not set, then we set the lock bit along with the `VMXON_OUTSIDE_SMX` bit and write the new value to the `IA32_FEATURE_CONTROL MSR` register. If the lock bit is already set, but the `VMXON_OUTSIDE_SMX` bit is not set, we then return an error indicating that the BIOS has locked the VMX feature.

```rust
/// Check if we need to set bits in IA32_FEATURE_CONTROL (Intel Manual: 24.7 Enabling and Entering VMX Operation)
fn set_lock_bit() -> Result<(), HypervisorError> {
    const VMX_LOCK_BIT: u64 = 1 << 0;
    const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

    let ia32_feature_control = unsafe { rdmsr(msr::IA32_FEATURE_CONTROL) };

    if (ia32_feature_control & VMX_LOCK_BIT) == 0 {
        unsafe {
            msr::wrmsr(
                msr::IA32_FEATURE_CONTROL,
                VMXON_OUTSIDE_SMX | VMX_LOCK_BIT | ia32_feature_control,
            )
        };
    } else if (ia32_feature_control & VMXON_OUTSIDE_SMX) == 0 {
        return Err(HypervisorError::VMXBIOSLock);
    }

    Ok(())
}
```