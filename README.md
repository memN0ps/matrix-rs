# Windows Blue Pill Type-2 Hypervisor in Rust (Codename: Matrix)

Blog: https://memn0ps.github.io/hypervisor-development-in-rust-part-1/

I made this hypervisor for learning and fun in Dec/Jan/Feb 2023, and the original plan was to release it as a bug-free minimalistic hypervisor with hooks. However, I got a little tired, took a break, and coded a UEFI Bootkit in Rust to load the hypervisor Windows kernel driver by disabling or bypassing security protections before the OS boots. I'll return to this later if I ever get the time and implement Extended Page Table (EPT). The legendary [Satoshi Tanda (@tandasat)](https://github.com/tandasat) released [Hypervisor 101 in Rust](https://github.com/tandasat/Hypervisor-101-in-Rust), a fuzzing hypervisor for UEFI on Intel/AMD, while I was developing this Intel Type-2 VT-x hypervisor, both of which are different.

This project follows a similar neat structure to the [amd_hypervisor made by @not-matthias](https://github.com/not-matthias/amd_hypervisor), which will help integrate the open-source projects if required.

The primary motivation came shortly after [@not_matthias](https://github.com/not-matthias/amd_hypervisor) released an AMD (SVM) Hypervisor in Rust and from [Secret Club's](https://twitter.com/the_secret_club) excellent articles:

* https://secret.club/2020/01/12/battleye-hypervisor-detection.html 
* https://secret.club/2020/07/06/bottleye.html 
* https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html

## Features

TODO: **Development in progress**

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

Thanks to [@daax_rynd](https://twitter.com/daax_rynd), [@Intel80x86](https://twitter.com/Intel80x86), [@not_matthias](https://twitter.com/not_matthias), [@standa_t](https://twitter.com/standa_t), and [@felix-rs / @joshuа](https://github.com/felix-rs)

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

* Hyperbone: https://github.com/DarthTon/HyperBone/

* DdiMon: https://github.com/tandasat/DdiMon

* Hvpp: https://github.com/wbenny/hvpp

* SimpleVisor: https://github.com/ionescu007/SimpleVisor

* HyperHide: https://github.com/Air14/HyperHide

* AetherVisor: https://github.com/MellowNight/AetherVisor

* KasperskyHook: https://github.com/iPower/KasperskyHook

* https://secret.club/2020/07/06/bottleye.html

* https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html

* https://secret.club/2020/01/12/battleye-hypervisor-detection.html

* Thanks for helping me with some errors: [Christopher aka Kharosx0](https://twitter.com/Kharosx0)