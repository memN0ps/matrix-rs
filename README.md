# Windows Blue Pill Type-2 Hypervisor in Rust (Codename: Matrix)

![Build Status](https://github.com/memN0ps/hypervisor-rs/actions/workflows/github-actions.yml/badge.svg)
![License](https://img.shields.io/github/license/memN0ps/hypervisor-rs)
![Issues](https://img.shields.io/github/issues/memN0ps/hypervisor-rs)
![Forks](https://img.shields.io/github/forks/memN0ps/hypervisor-rs)
![Stars](https://img.shields.io/github/stars/memN0ps/hypervisor-rs)

A lightweight, memory-safe, and blazingly fast Rust-based type-2 research hypervisor for Intel VT-x, focused on studying the core concepts of virtualization.

## Features

- **Efficient VM Exit Handling**: Implements optimized handling for various VM exit reasons like `Cpuid`, `Rdmsr`, `Wrmsr`, `Invd`, `Rdtsc`, `EptViolation`, `EptMisconfiguration`, `Invept`, `Invvpid`, `Xsetbv`. This ensures minimal performance overhead and responsive virtual machine operations.

- **Robust Isolation Mechanisms**: Custom Global Descriptor Table (GDT), Interrupt Descriptor Table (IDT), and Page Tables are used for enhanced security. This design decision prevents potential vulnerabilities from using the host's `ntoskrnl.exe` `CR3` or a usermode process's `CR3`, fortifying the hypervisor against sophisticated attacks. [Further reading on the importance of these structures](https://www.unknowncheats.me/forum/2779560-post4.html).

- **Integrated Extended Page Tables (EPT)**: Incorporates Memory Type Range Registers (MTRR) with EPT for efficient memory mapping and management. This feature ensures that memory types are correctly identified and handled, optimizing performance and stability in virtualized environments.


## Planned Enhancements

- **Enhanced VM Exit Instruction Handling**: Future updates aim to include advanced handling for instructions like `Getsec`, and VMX instructions (`Vmcall`, `Vmclear`, `Vmlaunch`, `Vmptrld`, `Vmptrst`, `Vmresume`, `Vmxoff`, `Vmxon`). This will extend the hypervisor's capability to manage more complex virtual machine operations and scenarios.

- **EPT Hook Development**: Planning to implement EPT hooks for sophisticated memory control and monitoring within guest VMs. This will allow for more granular memory management and potentially enable advanced features like memory introspection or modification.

- **Stability Enhancements**: Addressing the `CRITICAL_PROCESS_DIED (ef)` BSOD issue is a top priority.

## Installation

1. Install Rust from [here](https://www.rust-lang.org/tools/install).
2. Switch to Rust Nightly: `rustup toolchain install nightly` and `rustup default nightly`.
3. Install LLVM: `winget install LLVM.LLVM`.
4. Install Tools: `cargo-make`, `cargo-expand`, `cargo-edit`, and `cargo-workspaces`.
5. Install WDK/SDK/EWDK: Steps [here](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk).

## Building the Project

- Development: `cargo make --profile development`.
- Production: `cargo make --profile release`.

## Debugging

### Enabling Debug Modes

- Test Mode: Activate test signing with `bcdedit.exe /set testsigning on`.
- Windows Debugging: Follow the steps in this [Microsoft guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--bootdebug).

```powershell
bcdedit.exe /bootdebug {bootmgr} on
bcdedit.exe /bootdebug on
bcdedit.exe /debug on
```

### Network Debugging with Windbg

Setup: `bcdedit.exe /dbgsettings net hostip:w.x.y.z port:n`.

### Debug Print Filter

1. Open `regedit.exe`.
2. Go to `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`.
3. Create `Debug Print Filter` with `DEFAULT` DWORD = `8`.

### VMware Serial Port Debugging

1. Add Serial Port in VMware: 'Use output file'.
2. Configure in Windows VM: `$serialPort = New-Object System.IO.Ports.SerialPort COM2,9600,None,8,One; $serialPort.Open()`.

### Service Management

Use Service Controller (`sc.exe`) to create and manage the hypervisor service:

```powershell
sc.exe create matrix type= kernel binPath= C:\Windows\System32\drivers\matrix.sys
sc.exe query matrix
sc.exe start matrix
```

## Acknowledgments, References, and Motivation

Big thanks to the amazing people and resources that have shaped this project. A special shout-out to everyone listed below. While I didn't use all these resources in my work, they've been goldmines of information, super helpful for anyone diving into hypervisor development, including me.

- **[Daax Rynd (@daaximus)](https://github.com/daaximus), [Aidan Khoury (@ajkhoury)](https://github.com/ajkhoury), [Nick Peterson (@everdox)](https://github.com/everdox)**: For their comprehensive series on hypervisor development:
  - [7 Days to Virtualization](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/)
  - [MMU Virtualization via Intel EPT](https://revers.engineering/mmu-virtualization-via-intel-ept-index/)
  - [Patchguard: Hypervisor Based Introspection [P1]](https://revers.engineering/patchguard-detection-of-hypervisor-based-instrospection-p1/)
  - [Patchguard: Hypervisor Based Introspection [P2]](https://revers.engineering/patchguard-detection-of-hypervisor-based-instrospection-p2/)

- **[Sina Karvandi (@Intel80x86)](https://github.com/SinaKarvandi)**: For the extensive Hypervisor From Scratch series:
  - [Tutorial Series](https://rayanfam.com/tutorials/)
  - [GitHub Repository](https://github.com/SinaKarvandi/Hypervisor-From-Scratch/)

- **[Satoshi Tanda(@tandasat)](https://github.com/tandasat/)**: His work has significantly influenced this project:
  - [Hypervisor Development for Security Researchers](https://tandasat.github.io/Hypervisor_Development_for_Security_Researchers.html)
  - [Hypervisor 101 in Rust](https://github.com/tandasat/Hypervisor-101-in-Rust)
  - Additional Projects: [Hello-VT-rp](https://github.com/tandasat/Hello-VT-rp), [DdiMon](https://github.com/tandasat/DdiMon), [HyperPlatform](https://github.com/tandasat/HyperPlatform), [MiniVisorPkg](https://github.com/tandasat/MiniVisorPkg)
 
- **[Matthias @not-matthias](https://github.com/not-matthias/amd_hypervisor)**: For his impactful work on the [amd_hypervisor](https://github.com/not-matthias/amd_hypervisor) project, which greatly inspired and influenced this research.

### Community and Technical Resources

- **[Secret Club](https://github.com/thesecretclub)**: Insights into anti-cheat systems and hypervisor detection, which also inspired this project:
  - [System emulation detection](https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html) by [@Daax](https://github.com/daaximus), [@iPower](https://github.com/iPower), [@ajkhoury](https://github.com/ajkhoury), [@drew](https://github.com/drew-gpf)
  - [BattlEye hypervisor detection](https://secret.club/2020/01/12/battleye-hypervisor-detection.html) by [@vmcall](https://github.com/vmcall), [@Daax](https://github.com/daaximus)

- **Other Essential Resources**:
  - [Intel's Software Developer's Manual](https://www.intel.com/)
  - [Maurice Heumann's (@momo5502)](https://github.com/momo5502/) [Detecting Hypervisor-Assisted Hooking](https://momo5502.com/posts/2022-05-02-detecting-hypervisor-assisted-hooking/)
  - [Guided Hacking's](https://guidedhacking.com/) [x64 Virtual Address Translation](https://www.youtube.com/watch?v=W3o5jYHMh8s) on YouTube
  - [UnKnoWnCheaTs](https://unknowncheats.me/) [forum post](https://www.unknowncheats.me/forum/2779560-post4.html) by [@namazso](https://github.com/namazso)
  - [RVM1.5](https://github.com/rcore-os/RVM1.5), [Barbervisor](https://github.com/Cisco-Talos/Barbervisor), [rustyvisor](https://github.com/iankronquist/rustyvisor), [orange_slice](https://github.com/gamozolabs/orange_slice), [mythril](https://github.com/mythril-hypervisor/mythril), [uhyve](https://github.com/hermit-os/uhyve), [maystorm](https://github.com/neri/maystorm)
  - [AMD-V Hypervisor Development by Back Engineering](https://blog.back.engineering/04/08/2022), [bluepill by @_xeroxz](https://git.back.engineering/_xeroxz/bluepill)
  - [hvpp by @wbenny](https://github.com/wbenny/hvpp)
  - [HyperHide by @Air14](https://github.com/Air14/HyperHide)
  - [How AetherVisor works under the hood by M3ll0wN1ght](https://mellownight.github.io/AetherVisor)
  - [Rust library to use x86 (amd64) specific functionality and registers (x86 crate for Rust)](https://github.com/gz/rust-x86)
  - [DarthTon's HyperBone](https://github.com/DarthTon/HyperBone) (based on the legendary [Alex Ionescu's](https://github.com/ionescu007/SimpleVisor) version) on [UnknownCheats](https://www.unknowncheats.me/forum/c-and-c-/173560-hyperbone-windows-hypervisor.html).
  - [Joanna Rutkowska: Pioneering the Blue Pill Hypervisor Concept, one of the earliest proofs of concept](https://blog.invisiblethings.org/2006/06/22/introducing-blue-pill.html)

### Helpers and Collaborators

Special thanks to:
- [Daax Rynd](https://revers.engineering/)
- [Satoshi Tanda](https://github.com/tandasat)
- [Drew (@drew)](https://github.com/drew-gpf)
- [Matthias @not-matthias](https://github.com/not-matthias/)
- [@felix-rs / @joshuа](https://github.com/felix-rs)
- `@jessiep_ aka Jess`
- [Ryan McCrystal (@rmccrystal)](https://github.com/rmccrystal)
- [Jim Colerick (@vmprotect)](https://github.com/thug-shaker)
- [Christopher (@Kharosx0)](https://twitter.com/Kharosx0)

## License

This project is licensed under the MIT License. For more information, see the [MIT License details](./LICENSE).
