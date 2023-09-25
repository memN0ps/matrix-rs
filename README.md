# Windows Blue Pill Type-2 Hypervisor in Rust (Codename: Matrix)

Blog: https://memn0ps.github.io/hypervisor-development-in-rust-part-1/

This project is a Rust-based research hypervisor for Intel VT-x and AMD-v (SVM) virtualization, designed to be lightweight and focused on studying the core concepts. While it currently lacks a memory management unit (MMU) for virtualization using Intel's Extended Page Tables (EPT) and AMD's Nested Page Tables (NPT), these features are planned for future implementation.

Big thanks to [@daax_rynd](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/), [@Intel80x86](https://github.com/SinaKarvandi/Hypervisor-From-Scratch/), [@not_matthias](https://github.com/not-matthias/amd_hypervisor), and [@standa_t](https://github.com/tandasat/Hypervisor-101-in-Rust) for their awesome blogs and code. They’ve been incredibly helpful!

I was inspired to start this project after seeing [@not_matthias](https://github.com/not-matthias/amd_hypervisor)’s project and reading some insightful articles by [Secret Club](https://secret.club/) and the unveiling of [DarthTon's HyperBone](https://github.com/DarthTon/HyperBone) (based on the legendary [Alex Ionescu's](https://github.com/ionescu007/SimpleVisor) version) on [UnknownCheats](https://www.unknowncheats.me/forum/c-and-c-/173560-hyperbone-windows-hypervisor.html). Here are some of them if you want to check them out:

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

- Implementing your own IDT, GDT, and page tables is crucial when developing a hypervisor, especially to protect against potentially malicious guests. [Learn More](https://www.unknowncheats.me/forum/2779560-post4.html). This task is on the TODO list and will be addressed at the end of the development process.

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

### Development

```
cargo make --cwd .\driver\ --profile development sign
```

### Production

```
cargo make --cwd .\driver\ --profile production sign
```

## Debugging (Optional)

### 1. [Enabling Test Mode or Test Signing Mode](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)

To enable `Test Mode` or `Test Signing Mode`, open an elevated command prompt and enter the following command:

```
bcdedit.exe /set testsigning on
```

### 2. [Enabling Debugging of Windows Boot Manager (bootmgfw.efi), Windows OS Boot Loader (winload.efi), and Windows Kernel (ntoskrnl.exe)](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--bootdebug)

The commands below enable debugging for the Windows Boot Manager, the boot loader, and the operating system's kernel. Using this combination allows for debugging at every startup stage. If activated, the target computer will break into the debugger three times: when the Windows Boot Manager loads, when the boot loader loads, and when the operating system starts. Enter the following commands in an elevated command prompt:

```
bcdedit.exe /bootdebug {bootmgr} on
bcdedit.exe /bootdebug on
bcdedit.exe /debug on
```

### 3. [Setting Up Network Debugging for Windbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-a-network-debugging-connection)

To set up network debugging, open an elevated command prompt and enter the command below. Replace `w.x.y.z` with the IP address of the host computer and `n` with your chosen port number:

```
bcdedit.exe /dbgsettings net hostip:w.x.y.z port:n
```

### 4. [Setting Up Debug Print Filter](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/reading-and-filtering-debugging-messages#setting-the-component-filter-mask)

Open the Windows registry editor by entering the following command in an elevated command prompt:

```
regedit.exe
```

For more focused and efficient kernel development troubleshooting, set up filters to selectively display debugging messages by following these steps:

1. Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager`.
2. Create a new key named `Debug Print Filter`.
3. Inside this key, create a new `DWORD (32) Value`.
4. Name it `DEFAULT`.
5. Set its `Value data` to `8`.

### 5. [Creating and Starting a Service](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create)

```
sc.exe create matrix type= kernel binPath= C:\Windows\System32\drivers\matrix.sys
sc.exe query matrix
sc.exe start matrix
```

## Acknowledgments & References

This project has been inspired, influenced, and supported by numerous individuals and resources. A huge shout-out and thank you to everyone listed below:

### Tutorials & Articles
- **Daax Rynd**: [7 Days to Virtualization: A Series on Hypervisor Development](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/)
- **Sina Karvandi**: [Hypervisor From Scratch](https://rayanfam.com/tutorials/)
- **Back Engineering Labs**: [AMD-V Hypervisor Development](https://blog.back.engineering/04/08/2022/)
- **Secret Club**:
  - [BottlEye](https://secret.club/2020/07/06/bottleye.html)
  - [How Anti-Cheats Detect System Emulation](https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html)
  - [BattlEye Hypervisor Detection](https://secret.club/2020/01/12/battleye-hypervisor-detection.html)
- **MellowNight**: [AetherVisor](https://mellownight.github.io/AetherVisor)
- **Momo5502**: [Detecting Hypervisor-Assisted Hooking](https://momo5502.com/posts/2022-05-02-detecting-hypervisor-assisted-hooking/)
- **Joanna Rutkowska**: [Introducing Blue Pill](https://blog.invisiblethings.org/2006/06/22/introducing-blue-pill.html)
- **Intel Corporation**: [Intel Software Developer's Manual](https://www.intel.com/)
- **Advanced Micro Devices, Inc. (AMD)**: [AMD Software Developer's Manual](https://www.amd.com/)

### Projects & Repositories
- **Matthias**: [AMD Hypervisor](https://github.com/not-matthias/amd_hypervisor/)
- **Satoshi Tanda**:
  - [Hypervisor 101 in Rust](https://github.com/tandasat/Hypervisor-101-in-Rust)
  - [Hello-VT-rp](https://github.com/tandasat/Hello-VT-rp)
  - [DdiMon](https://github.com/tandasat/DdiMon)
  - [HyperPlatform](https://github.com/tandasat/HyperPlatform)
  - [MiniVisorPkg](https://github.com/tandasat/MiniVisorPkg)
  - [SimpleSvmHook](https://github.com/tandasat/SimpleSvmHook)
- **Ian Kronquist**: [RustyVisor](https://github.com/iankronquist/rustyvisor/)
- **RCore Team**: [RVM1.5](https://github.com/rcore-os/RVM1.5/)
- **Cisco Talos**: [Barbervisor](https://github.com/Cisco-Talos/Barbervisor/)
- **Gamozo Labs**: [Orange Slice](https://github.com/gamozolabs/orange_slice)
- **Mythril Team**: [Mythril](https://github.com/mythril-hypervisor/mythril/)
- **Hermit OS Team**: [uhyve](https://github.com/hermit-os/uhyve)
- **_xeroxz (IDontCode)_**: [BluePill](https://git.back.engineering/_xeroxz/bluepill)
- **DarthTon**: [Hyperbone](https://github.com/DarthTon/HyperBone/)
- **Satoshi Tanda**: [DdiMon](https://github.com/tandasat/DdiMon)
- **wbenny**: [Hvpp](https://github.com/wbenny/hvpp)
- **Alex Ionescu**: [SimpleVisor](https://github.com/ionescu007/SimpleVisor)
- **Air14**: [HyperHide](https://github.com/Air14/HyperHide)
- **MellowNight**: [AetherVisor](https://github.com/MellowNight/AetherVisor)
- **iPower**: [KasperskyHook](https://github.com/iPower/KasperskyHook)

### Videos
- **Gamozo Labs**: [Orange Slice: Writing the Hypervisor](https://www.youtube.com/watch?v=WabeOICAOq4&list=PLSkhUfcCXvqFJAuFbABktmLaQvJwKxJ3i)

### Forums & Communities
- [UnknownCheats](https://www.unknowncheats.me/forum/c-and-c-/173560-hyperbone-windows-hypervisor.html)

### Special Thanks
- [@not_matthias](https://twitter.com/not_matthias)
- [@rmccrystal](https://github.com/rmccrystal)
- `@jessiep_ aka Jess`
- [@felix-rs / @joshuа](https://github.com/felix-rs)
- `@vmprotect aka Jim Colerick`
- [Christopher aka Kharosx0](https://twitter.com/Kharosx0)
- [@namazso](https://github.com/namazso) for [this post](https://www.unknowncheats.me/forum/2779560-post4.html)

### Conceptual Clarifications
- [Difference between Trap and Interrupt](https://stackoverflow.com/questions/3149175/what-is-the-difference-between-trap-and-interrupt/37558741#37558741)