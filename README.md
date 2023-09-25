# Windows Blue Pill Type-2 Hypervisor in Rust (Codename: Matrix)

* Blog: https://memn0ps.github.io/hypervisor-development-in-rust-part-1/

This project is a Rust-based research hypervisor for Intel VT-x and AMD-v (SVM) virtualization, designed to be lightweight and focused on studying the core concepts. While it currently lacks a memory management unit (MMU) for virtualization using Intel's Extended Page Tables (EPT) and AMD's Nested Page Tables (NPT), these features are planned for future implementation.

Big thanks to [@daax_rynd](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/), [@Intel80x86](https://github.com/SinaKarvandi/Hypervisor-From-Scratch/), [@not_matthias](https://github.com/not-matthias/amd_hypervisor), and [@standa_t](https://github.com/tandasat/Hypervisor-101-in-Rust) for their awesome blogs and code. They’ve been incredibly helpful!

I was inspired to start this project after seeing [@not_matthias](https://github.com/not-matthias/amd_hypervisor)’s project and reading some insightful articles by [Secret Club](https://twitter.com/the_secret_club) and the unveiling of [DarthTon's HyperBone](https://github.com/DarthTon/HyperBone) (based on the legendary [Alex Ionescu's](https://github.com/ionescu007/SimpleVisor) version) on [UnknownCheats](https://www.unknowncheats.me/forum/c-and-c-/173560-hyperbone-windows-hypervisor.html). Here are some of them if you want to check them out:

- [BattlEye Hypervisor Detection](https://secret.club/2020/01/12/battleye-hypervisor-detection.html)
- [BottlEye](https://secret.club/2020/07/06/bottleye.html)
- [How Anti-Cheats Detect System Emulation](https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html)

I’ve also been learning a lot by preparing for the legendary [Satoshi Tanda's Hypervisor Development for Security Researchers training](https://tandasat.github.io/Hypervisor_Development_for_Security_Researchers.html) and exploring other projects and blogs, like [BluePill by @_xeroxz (IDontCode)](https://git.back.engineering/_xeroxz/bluepill) and [AMD-V Hypervisor Development](https://blog.back.engineering/04/08/2022/) by [Back Engineering Labs](https://back.engineering/). They've provided lots of inspiration and knowledge, encouraging me to dive deeper into this field.

## Features

### **Current Developments:**
- **Type-2 Intel VT-x Hypervisor:**
   - **Status:** Under Development.
   - **In Progress:**
     - Extended Page Tables (EPT).
     - Various bug fixes.
   - **Objective:** Actively working to support Intel VT-x virtualization technology.

### **Planned Developments:**
- **Type-2 AMD-v (SVM) Hypervisor:**
   - **Status:** Integration planned for future development.
   - **Objective:** To extend support to AMD-v (SVM) virtualization technology.

### **Overall Goal:**
   - To combine the above features and create a comprehensive hypervisor solution that supports both Intel VT-x and AMD SVM virtualization technologies.

## Important Notes

- Implementing your own IDT, GDT, and page tables is crucial when developing a hypervisor, especially to protect against potentially malicious guests. [Learn More](https://www.unknowncheats.me/forum/2779560-post4.html). This task is on the TODO list and will be addressed at the end of the development process."

## Install

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

## Build

Change directory to `.\driver\` and build driver and hypervisor

### Development

```
cargo make sign
```

### Production

```
cargo make --profile production sign
```

### Enable `Test Mode` or `Test Signing` Mode 

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
sc.exe create matrix type= kernel binPath= C:\Windows\System32\drivers\matrix.sys
sc.exe query matrix
sc.exe start matrix
```

## Credits / References / Thanks / Motivation

* 7 Days to Virtualization: A Series on Hypervisor Development: https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/

* Hypervisor From Scratch: https://rayanfam.com/tutorials/

* AMD Hypervisor: https://github.com/not-matthias/amd_hypervisor/

* Hypervisor 101 in Rust: https://github.com/tandasat/Hypervisor-101-in-Rust

* RustyVisor: https://github.com/iankronquist/rustyvisor/

* RVM1.5: https://github.com/rcore-os/RVM1.5/

* Barbervisor: https://github.com/Cisco-Talos/Barbervisor/

* Orange Slice: https://github.com/gamozolabs/orange_slice

* Orange Slice: Writing the Hypervisor: https://www.youtube.com/watch?v=WabeOICAOq4&list=PLSkhUfcCXvqFJAuFbABktmLaQvJwKxJ3i

* Mythril: https://github.com/mythril-hypervisor/mythril/

* BluePill: https://git.back.engineering/_xeroxz/bluepill

* AMD-V Hypervisor Development: https://blog.back.engineering/04/08/2022/

* Hyperbone: https://github.com/DarthTon/HyperBone/

* UnknownCheats: https://www.unknowncheats.me/forum/c-and-c-/173560-hyperbone-windows-hypervisor.html

* DdiMon: https://github.com/tandasat/DdiMon

* Hvpp: https://github.com/wbenny/hvpp

* SimpleVisor: https://github.com/ionescu007/SimpleVisor

* HyperHide: https://github.com/Air14/HyperHide

* AetherVisor: https://github.com/MellowNight/AetherVisor

* KasperskyHook: https://github.com/iPower/KasperskyHook

* https://secret.club/2020/07/06/bottleye.html

* https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html

* https://secret.club/2020/01/12/battleye-hypervisor-detection.html

* Thanks [@not_matthias](https://twitter.com/not_matthias) [@rmccrystal](https://github.com/rmccrystal), `@jessiep_`, [@felix-rs / @joshuа](https://github.com/felix-rs), `@vmprotect` and [Christopher aka Kharosx0](https://twitter.com/Kharosx0) for helping me out with some concepts, code and errors.

* https://stackoverflow.com/questions/3149175/what-is-the-difference-between-trap-and-interrupt/37558741#37558741

* Thanks [@namazso](https://github.com/namazso) for https://www.unknowncheats.me/forum/2779560-post4.html