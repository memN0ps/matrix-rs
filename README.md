# Windows Blue Pill Type-2 Hypervisor in Rust (Codename: Matrix)

![Build Status](https://img.shields.io/github/workflow/status/memN0ps/hypervisor-rs/Rust)
![License](https://img.shields.io/github/license/memN0ps/hypervisor-rs)
![Issues](https://img.shields.io/github/issues/memN0ps/hypervisor-rs)
![Forks](https://img.shields.io/github/forks/memN0ps/hypervisor-rs)
![Stars](https://img.shields.io/github/stars/memN0ps/hypervisor-rs)

This project is a Rust-based research hypervisor (type-2) for Intel VT-x virtualization, designed to be lightweight and focused on studying the core concepts.

## Features

- **Vmexit Management for Optimized Virtualization**:
  - **CPUID**: Efficient handling of CPUID vmexits.
  - **RDMSR & WRMSR**: Supports Read and Write operations for Model-Specific Registers, including synthetic MSRs.
  - **INVD**: Implements INVD vmexits for cache invalidation.
  - **RDTSC**: Manages RDTSC instruction vmexits for accurate time-stamp counter values.
  - **XSETBV**: Manages Extended State Save/Restore (xsetbv) vmexits.
- **GDT and IDT Implementation**: Custom development of the Global Descriptor Table and Interrupt Descriptor Table, vital for safeguarding against malicious guests. [Learn more](https://www.unknowncheats.me/forum/2779560-post4.html).
- **Future Development Plans**:
  - **VM Exit Instruction Handling**: Including GETSEC and VMX instructions (INVEPT, INVVPID, VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, VMXON).
  - **Extended Page Tables (EPT)**: For advanced memory management.

## Installation

1. **Install Rust**: Follow the instructions [here](https://www.rust-lang.org/tools/install).
2. **Switch to Rust Nightly**: Run `rustup toolchain install nightly` and `rustup default nightly` in PowerShell.
3. **Install LLVM**: Required for `bindgen`. Install via `winget install LLVM.LLVM`.
4. **Install Additional Tools**: `cargo-make`, `cargo-expand`, `cargo-edit`, and `cargo-workspaces` (optional but recommended for enhanced development experience).
5. **Install WDK/SDK/EWDK**: Necessary for Windows drivers. Follow the steps [here](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk).

## Building the Project

- **Development Build**: Run `cargo make --profile development` in PowerShell.
- **Production Build**: Run `cargo make --profile release` in PowerShell.

## Debugging

### Enabling Debugging Modes

- **Test Mode**: Activate by running `bcdedit.exe /set testsigning on` in an elevated command prompt.
- **Windows Boot Debugging**: Enable debugging for key Windows components - Boot Manager, Boot Loader, and Kernel. This setup triggers a debugger break at three critical startup stages. For detailed instructions, see [Windows Hardware Drivers documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--bootdebug):

```powershell
  bcdedit.exe /bootdebug {bootmgr} on
  bcdedit.exe /bootdebug on
  bcdedit.exe /debug on
```

### Network Debugging with Windbg

Set up network debugging by specifying the host computer's IP and port:

```powershell
bcdedit.exe /dbgsettings net hostip:w.x.y.z port:n
```

### Setting Up Debug Print Filter

To focus debugging messages:

1. Open Registry Editor: `regedit.exe`.
2. Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager`.
3. Create a `Debug Print Filter` key with a `DEFAULT` DWORD value set to `8`.

### Configuring Serial Port for VMware Debugging

Set up serial port communication in VMware for detailed debugging:

1. Add a Serial Port in VMware settings, set to 'Use output file'.
2. In Windows VM, use PowerShell to configure the serial port (e.g., `COM2`, 9600 baud rate). Scripts provided for one-liner:

```powershell
$serialPort = New-Object System.IO.Ports.SerialPort COM2,9600,None,8,One; $serialPort.Open()
```

### Creating and Starting a Service

Use Service Controller (`sc.exe`) to create and manage the hypervisor service:

```
sc.exe create matrix type= kernel binPath= C:\Windows\System32\drivers\matrix.sys
sc.exe query matrix
sc.exe start matrix
```

## Acknowledgments, References, and Motivation

Big thanks to the amazing people and resources that have shaped this project. A special shout-out to everyone listed below. While I didn't use all these resources in my work, they've been goldmines of information, super helpful for anyone diving into hypervisor development, including me.

- **Daax Rynd, Aidan Khoury, and Nick Peterson**
  - [7 Days to Virtualization: A Series on Hypervisor Development](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/)
  - [MMU Virtualization via Intel EPT](https://revers.engineering/mmu-virtualization-via-intel-ept-index/)
  - [Patchguard: Detection Of Hypervisor Based Introspection [P1]](https://revers.engineering/patchguard-detection-of-hypervisor-based-instrospection-p1/)
  - [Patchguard: Detection Of Hypervisor Based Introspection [P2]](https://revers.engineering/patchguard-detection-of-hypervisor-based-instrospection-p2/)
- **Sina Karvandi**
  - [Hypervisor From Scratch Part 1-8 Series](https://rayanfam.com/tutorials/) and [Hypervisor From Scratch Code](https://github.com/SinaKarvandi/Hypervisor-From-Scratch/)
- **Satoshi Tanda**
  - Working on this project has been a fantastic learning journey, perfectly setting me up for the legendary Satoshi Tanda's well-known [Hypervisor Development for Security Researchers](https://tandasat.github.io/Hypervisor_Development_for_Security_Researchers.html) training.
  - [Hypervisor 101 in Rust](https://github.com/tandasat/Hypervisor-101-in-Rust)
  - [Hello-VT-rp](https://github.com/tandasat/Hello-VT-rp)
  - [DdiMon](https://github.com/tandasat/DdiMon)
  - [HyperPlatform](https://github.com/tandasat/HyperPlatform)
  - [MiniVisorPkg](https://github.com/tandasat/MiniVisorPkg)
- **Matthias**
  - [AMD Hypervisor](https://github.com/not-matthias/amd_hypervisor/)
- **Secret Club**
  - [How anti-cheats detect system emulation](https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html) by [@Daax](https://github.com/daaximus), [@iPower](https://github.com/iPower), [@ajkhoury](https://github.com/ajkhoury), [@drew](https://github.com/drew-gpf)
  - [BattlEye hypervisor detection](https://secret.club/2020/01/12/battleye-hypervisor-detection.html) by [@vmcall](https://github.com/vmcall), [@Daax](https://github.com/daaximus)
- **Others**
  - **Intel Corporation**: [Intel Software Developer's Manual](https://www.intel.com/)
  - **MellowNight**: [AetherVisor](https://mellownight.github.io/AetherVisor)
  - **Momo5502**: [Detecting Hypervisor-Assisted Hooking](https://momo5502.com/posts/2022-05-02-detecting-hypervisor-assisted-hooking/)
  - **RCore Team**: [RVM1.5](https://github.com/rcore-os/RVM1.5/)
  - **Cisco Talos**: [Barbervisor](https://github.com/Cisco-Talos/Barbervisor/)
  - **Ian Kronquist**: [RustyVisor](https://github.com/iankronquist/rustyvisor/)
  - **Gamozo Labs**: [Orange Slice](https://github.com/gamozolabs/orange_slice) and [Orange Slice: Writing the Hypervisor](https://www.youtube.com/watch?v=WabeOICAOq4&list=PLSkhUfcCXvqFJAuFbABktmLaQvJwKxJ3i)
  - **Guided Hacking**: [Guided Hacking](https://guidedhacking.com/) YouTube [x64 Virtual Address Translation](https://www.youtube.com/watch?v=W3o5jYHMh8s)
  - **UnKnoWnCheaTs**: [UnKnoWnCheaTs](https://www.unknowncheats.me/) post [Creating new GDT / IDT and Page Tables](https://www.unknowncheats.me/forum/2779560-post4.html) by [@namazso](https://github.com/namazso)
  - **Helpers**: [@not-matthias](https://github.com/not-matthias/), [@felix-rs / @joshuа](https://github.com/felix-rs), `@jessiep_ aka Jess`, [@rmccrystal](https://github.com/rmccrystal), [@vmprotect aka Jim Colerick](https://github.com/thug-shaker), [Christopher aka @Kharosx0](https://twitter.com/Kharosx0)

## License

This project is licensed under MIT License. See the [MIT License](./LICENSE) for details.