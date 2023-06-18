# Windows Blue Pill Type-2 Hypervisor in Rust (Codename: Matrix)

Blog: https://memn0ps.github.io/hypervisor-development-in-rust-part-1/

This is a Rust-based research hypervisor for Intel VT-x virtualization, designed to be lightweight and focused on studying the core concepts. While it currently lacks memory management unit (MMU) virtualization using Intel Extended Page Tables (EPT), this feature is planned for future implementation.

Credit and gratitude are extended to the following individuals and their respective repositories for their invaluable contributions and references: [@daax_rynd](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/), [@Intel80x86](https://github.com/SinaKarvandi/Hypervisor-From-Scratch/), [@not_matthias](https://github.com/not-matthias/amd_hypervisor), and [@standa_t](https://github.com/tandasat/Hypervisor-101-in-Rust).


The inspiration for this endeavor emerged shortly after the release of [@not_matthias](https://github.com/not-matthias/amd_hypervisor)'s AMD (SVM) Hypervisor in Rust, as well as the enlightening articles by [Secret Club](https://twitter.com/the_secret_club) and the unveiling of [DarthTon's HyperBone](https://github.com/DarthTon/HyperBone) (based on the legendary [Alex Ionescu's](https://github.com/ionescu007/SimpleVisor) version) on [UnknownCheats](https://www.unknowncheats.me/forum/c-and-c-/173560-hyperbone-windows-hypervisor.html).

- [BattlEye Hypervisor Detection](https://secret.club/2020/01/12/battleye-hypervisor-detection.html)
- [BottlEye](https://secret.club/2020/07/06/bottleye.html)
- [How Anti-Cheats Detect System Emulation](https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html)

Furthermore, in my pursuit of knowledge and expertise, I have been preparing for the [legendary Satoshi Tanda's Hypervisor Development for Security Researchers](https://tandasat.github.io/Hypervisor_Development_for_Security_Researchers.html) training, which has further fueled my determination to embark on this captivating journey of hypervisor development. 

Additionally, I have gained valuable insights and knowledge from the exploration of [BluePill by @_xeroxz (IDontCode)](https://git.back.engineering/_xeroxz/bluepill) and various blog posts, such as [AMD-V Hypervisor Development](https://blog.back.engineering/04/08/2022/) and [Voyager - A Hyper-V Hacking Framework](https://blog.back.engineering/20/04/2021). The talented individuals at [Back Engineering Labs](https://back.engineering/) have been instrumental in providing a wealth of information and expertise. Their contributions have served as a valuable reference, further enriching my understanding and inspiring me to delve deeper into this field.

## Features

- Type-2 Intel VT-x Hypervisor (under development): This hypervisor is being developed with a focus on Intel VT-x virtualization. The following features are currently in progress:
    - Extended Page Tables (EPT)
    - Model Specific Register (MSR) Bitmaps

- Type-2 AMD SVM Hypervisor Integration: Integration of AMD SVM (Secure Virtual Machine) hypervisor support is planned for future development.

By combining these features, my goal is to create a comprehensive hypervisor solution that supports both Intel VT-x and AMD SVM virtualization technologies. I'm actively working on the Intel VT-x hypervisor and have plans to integrate the AMD SVM hypervisor in the future.

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

```
cargo make sign
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

* Thanks [@rmccrystal](https://github.com/rmccrystal), `@jessiep_`, [@felix-rs / @joshuа](https://github.com/felix-rs) and [Christopher aka Kharosx0](https://twitter.com/Kharosx0) for helping me out with some concepts, code and errors.