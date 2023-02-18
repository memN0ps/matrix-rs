# Hypervisor Development in Rust

This article will cover the development of a minimalistic Intel VT-x research hypervisor in Rust, code-named [SecretVisor](https://github.com/thesecretclub/SecretVisor), which can be found on Secret Club's GitHub. We will use the [x86 crate](https://crates.io/crates/x86) and [documentation](https://docs.rs/x86/latest/x86/), which help simplify the code.

The knowledge acquired to make this hypervisor was from reading blogs and code, notably the two excellent free hypervisor development series by [@daax_rynd](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/) and [@Intel80x86](https://rayanfam.com/). The motivation came shortly [@not_matthias](https://github.com/not-matthias/amd_hypervisor) released an AMD (SVM) Hypervisor in Rust, and the majority of the hypervisor was already developed before the legendary [@tandasat](https://github.com/tandasat/Hypervisor-101-in-Rust) released Hypervisor 101 in Rust.

* https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/
* https://rayanfam.com/
* https://github.com/not-matthias/amd_hypervisor

## Virtual Machine Architecture

**Virtual Machine Monitor (VMM):** By abstracting and dividing the underlying hardware resources, a virtual machine monitor (VMM) is a software layer that generates and controls virtual machines (VMs), enabling several operating systems to operate on the same physical computer.

**Guest Software:** Any software that runs inside a virtual machine (VM) that is controlled by a virtual machine monitor (VMM) or hypervisor is referred to as guest software.


## Introduction to Virtual Machine Extension (VMX) Operation

An operation that the Virtual Machine Monitor (VMM) does to enter or depart a virtual machine execution mode is referred to as a VMX operation. The host system's standard operating mode and the virtualized operating mode of the guest system executing within the VM are switched via the VMX procedure. The virtualization technology in the processor supports the low-level VMX operation, which enables the VMM to construct and manage virtual machines.

## Life Cycle of Virtual Machine Monitor (VMM) Software

The Virtual Machine Monitor (VMM) can enter and leave the execution mode of virtual machines (VMs) using low-level hardware operations called VM ENTRY and VM EXIT.

Other low-level hardware operations, such as VMXON and VMXOFF, enable and disable the VMX operation, the processor's implementation of hardware virtualization that supports VMMs, respectively.

In essence, VMXON and VMXOFF allow the VMM to construct and operate virtual machines, whereas VM ENTRY and VM EXIT enable the VMM to move between the host system and the guest system.

![Interaction of a Virtual-Machine Monitor and Guests](./pictures/Interaction_of_a_Virtual-Machine_Monitor_and_Guests.png)
*Credits: Intel® 64 and IA-32 Architectures Software Developer Manuals*


## Virtual-Machine Control Structure (VMCS)

A virtual machine's execution is managed and controlled by the Virtual Machine Monitor (VMM) via a virtual machine control structure (VMCS).
The virtual machine's state, the settings for the virtual processor, and the mapping between the virtual and physical resources are all contained in the VMCS.

The VMM employs a collection of low-level instructions to control the VMCS. The Virtual-Machine Control Structure Pointer (VMCS pointer), which enables the VMM to access the VMCS for a particular VM, can be read using VMPTRST and loaded using VMPTRLD. The VMM can alter the virtual machine's state or obtain details regarding its present state by using the commands VMREAD and VMWRITE, which are used to read and write values from and to the VMCS, respectively. When a virtual machine is terminated, or its state needs to be reset, VMCLEAR is used to clear the contents of the VMCS.

Each of the VMCSs assigned to a physical computer's logical processors corresponds to a particular virtual machine. As a result, the VMM can oversee and administer numerous virtual machines on a single physical device. In order to generate, monitor, and manage the execution of virtual machines on logical processors, the VMCS and related instructions give the VMM essential control and management capabilities.


## Discovering Support for Virtual Machine Extension (VMX)

The CPUID instruction can be used to determine whether Virtual Machine Extension (VMX) / Intel Virtualization Technology is supported. The processor will reveal information about its features, including whether it supports VMX, when the CPUID instruction is run with the EAX register set to 1. The EAX, EBX, ECX, and EDX registers store the CPUID data for the processor. If VMX is supported by the processor, bit 5 of ECX will be set to 1. The processor does not support VMX if the bit is not set, making virtualization unavailable.

We can use the x86 crate to create a new [CpuId struct](https://docs.rs/x86/latest/x86/cpuid/index.html), call [`get_feature_info()`](https://docs.rs/x86/latest/x86/cpuid/struct.CpuId.html#method.get_feature_info) function, which will query a set of features that are available on this CPU and then call [`has_vmx()`](https://docs.rs/x86/latest/x86/cpuid/struct.FeatureInfo.html#method.has_vmx) function, which will return a value of 1, indicating that the processor supports this technology.

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

A `Result` is a type that represents either success ([`Ok`]) or failure ([`Err`]). Please note that the `HyperVisorError` enum is custom-made.