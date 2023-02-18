# SecretVisor - A minimalistic Intel VT-x research hypervisor in Rust

## Features

Virtualize All Logical Processors:

* Check for Intel CPU
* Check for VMX Support
* Enable VMX
* Set Lock Bit
* Adjust Control Registers (set/clear CR0 and CR4)
* Initialize VMXON (VMXON Region)
* Initialize VMCS (VMCS Region)
* Initialize VMCLEAR
* Initialize VMPTRLD
* Initialize VMCS Control Values
* Initialize Guest Register State
* Initialize Host Register State
* Initialize VMLAUNCH
* Handle VMEXITS / VMRESUME / VMXOFF
* EPT (TODO)
* MSR Bitmaps (TODO)
* Changing IRQL (TODO)

## Build

### [Install Rust](https://www.rust-lang.org/tools/install)

To start using Rust, [download the installer](https://www.rust-lang.org/tools/install), then run the program and follow the onscreen instructions. You may need to install the [Visual Studio C++ Build tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) when prompted to do so.


### [Install and change to Rust nightly](https://rust-lang.github.io/rustup/concepts/channels.html)

```
rustup toolchain install nightly
rustup default nightly
```

### [Install cargo-make](https://github.com/sagiegurari/cargo-make)

```
cargo install cargo-make
```

### [Install WDK/SDK](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

* Step 1: Install Visual Studio 2022
* Step 2: Install Windows 11, version 22H2 SDK
* Step 3: Install Windows 11, version 22H2 WDK

### Build Driver

Change directory to `.\driver\` and build driver and hypervisor

```
cargo make sign
```

## Enable `Test Mode` or `Test Signing` Mode 

```
bcdedit /set testsigning on
```

### [Optional] Debug via Windbg

```
bcdedit /debug on
bcdedit /dbgsettings net hostip:<IP> port:<PORT>
```

### [Optional] Debug Print Filter

* Navigate to: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager`
* Create a new Key called `Debug Print Filter`
* Create a new `DWORD (32) Value`
* Give it the name `DEFAULT`
* Give it the `Value data: 8`

## Create / Start Service

```
sc.exe create SecretVisor type= kernel binPath= C:\Windows\System32\drivers\SecretVisor.sys
sc.exe query SecretVisor
sc.exe start SecretVisor
```

## Credits / References / Motivation / Thanks

* [@daax_rynd](https://twitter.com/daax_rynd)
* [@vm_call](https://twitter.com/vm_call)
* [@Intel80x86](https://twitter.com/Intel80x86)
* [@not_matthias](https://twitter.com/not_matthias)
* [@_xeroxz / @IDontCode](https://twitter.com/_xeroxz)
* [@medievalghoul](https://twitter.com/medievalghoul)
* [@felix-rs / @joshuа](https://github.com/felix-rs)
* [@standa_t](https://twitter.com/standa_t)
* [@rmccrystal](https://github.com/rmccrystal)
* [@aionescu](https://twitter.com/aionescu)
* [@rmccrystal](https://github.com/rmccrystal)
* [@wbenny](https://github.com/wbenny)
* [@DarthTon](https://github.com/DarthTon/HyperBone)
* [@UnKnoWnCheaTs](https://www.unknowncheats.me/forum/index.php)
* [@Secret Club](https://secret.club/)
* [@Guided Hacking](https://guidedhacking.com/)


* https://revers.engineering/day-0-virtual-environment-setup-scripts-and-windbg/
* https://revers.engineering/day-1-introduction-to-virtualization/
* https://revers.engineering/day-2-entering-vmx-operation/
* https://revers.engineering/day-3-multiprocessor-initialization-error-handling-the-vmcs/
* https://revers.engineering/day-4-vmcs-segmentation-ops/
* https://revers.engineering/day-5-vmexits-interrupts-cpuid-emulation/


* https://rayanfam.com/topics/hypervisor-from-scratch-part-1/
* https://rayanfam.com/topics/hypervisor-from-scratch-part-2/
* https://rayanfam.com/topics/hypervisor-from-scratch-part-3/
* https://rayanfam.com/topics/hypervisor-from-scratch-part-4/
* https://rayanfam.com/topics/hypervisor-from-scratch-part-5/
* https://rayanfam.com/topics/hypervisor-from-scratch-part-6/
* https://rayanfam.com/topics/hypervisor-from-scratch-part-7/
* https://rayanfam.com/topics/hypervisor-from-scratch-part-8/
* https://nixhacker.com/developing-hypervisior-from-scratch-part-1/
* https://nixhacker.com/developing-hypervisor-from-scratch-part-2/
* https://nixhacker.com/developing-hypervisor-from-scratch-part-3/
* https://nixhacker.com/developing-hypervisor-from-scratch-part-4/
* https://secret.club/2020/01/12/battleye-hypervisor-detection.html
* https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html
* https://git.back.engineering/_xeroxz/bluepill/
* https://back.engineering/04/08/2022/
* https://guidedhacking.com/threads/intro-to-hypervisors-for-game-hacking.20145/
* https://guidedhacking.com/threads/virtualized-game-hacking-1-0-introduction.20180/
* https://guidedhacking.com/threads/virtualized-game-hacking-1-1-virtual-memory-page-tables.20214/
* https://howtohypervise.blogspot.com/
* https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html (Intel® 64 and IA-32 Architectures Software Developer's Manual Volume 3C: System Programming Guide, Part 3)
* https://wiki.osdev.org/VMX
* https://codemachine.com/
* https://github.com/not-matthias/rdtsc_bench
* https://not-matthias.github.io/posts/rust-kernel-adventures/
* https://not-matthias.github.io/posts/kernel-driver-with-rust-2022/
* https://not-matthias.github.io/posts/kernel-driver-with-rust/

## Hypervisors in C/C++

* https://github.com/tandasat/HyperPlatform
* https://github.com/tandasat/DdiMon
* https://github.com/tandasat/SimpleSvmHook
* https://github.com/wbenny/hvpp
* https://github.com/ionescu007/SimpleVisor
* https://github.com/DarthTon/HyperBone/
* https://git.back.engineering/_xeroxz/bluepill/

## Hypervisors in Rust

* Hypervisor-101-in-Rust: https://github.com/tandasat/Hypervisor-101-in-Rust
* amd_hypervisor: https://github.com/not-matthias/amd_hypervisor/
* RustyVisor: https://github.com/iankronquist/rustyvisor/
* RVM1.5: https://github.com/rcore-os/RVM1.5/
* Barbervisor: https://github.com/Cisco-Talos/Barbervisor/
* Orange Slice: https://github.com/gamozolabs/orange_slice
* Orange Slice: Writing the Hypervisor: https://www.youtube.com/watch?v=WabeOICAOq4&list=PLSkhUfcCXvqFJAuFbABktmLaQvJwKxJ3i