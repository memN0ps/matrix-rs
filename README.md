# Windows Blue Pill Type-2 Hypervisor in Rust (Codename: Matrix)

Blog: https://memn0ps.github.io/hypervisor-development-in-rust-part-1/

This project is a Rust-based research hypervisor for Intel VT-x and AMD-v (SVM) virtualization, designed to be lightweight and focused on studying the core concepts. While it currently lacks a memory management unit (MMU) for virtualization using Intel's Extended Page Tables (EPT) and AMD's Nested Page Tables (NPT), these features are planned for future implementation.

Big thanks to [@daax_rynd](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/), [@Intel80x86](https://github.com/SinaKarvandi/Hypervisor-From-Scratch/), [@not_matthias](https://github.com/not-matthias/amd_hypervisor), and [@standa_t](https://github.com/tandasat/Hypervisor-101-in-Rust) for their awesome blogs and code. They've been incredibly helpful!

I was inspired to start this project after seeing [@not_matthias](https://github.com/not-matthias/amd_hypervisor)'s project and reading some insightful articles by [Secret Club](https://secret.club/) and the unveiling of [DarthTon's HyperBone](https://github.com/DarthTon/HyperBone) (based on the legendary [Alex Ionescu's](https://github.com/ionescu007/SimpleVisor) version) on [UnknownCheats](https://www.unknowncheats.me/forum/c-and-c-/173560-hyperbone-windows-hypervisor.html). Here are some of them if you want to check them out:

- [BattlEye Hypervisor Detection](https://secret.club/2020/01/12/battleye-hypervisor-detection.html)
- [BottlEye](https://secret.club/2020/07/06/bottleye.html)
- [How Anti-Cheats Detect System Emulation](https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html)

I've also been learning a lot by preparing for the legendary [Satoshi Tanda's Hypervisor Development for Security Researchers training](https://tandasat.github.io/Hypervisor_Development_for_Security_Researchers.html) and exploring other projects and blogs, like [BluePill by @_xeroxz (IDontCode)](https://git.back.engineering/_xeroxz/bluepill) and [AMD-V Hypervisor Development](https://blog.back.engineering/04/08/2022/) by [Back Engineering Labs](https://back.engineering/). They've provided lots of inspiration and knowledge, encouraging me to dive deeper into this field.

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

### Install [Rust](https://www.rust-lang.org/tools/install)

To start using Rust, [download the installer](https://www.rust-lang.org/tools/install), then run the program and follow the onscreen instructions. You may need to install the [Visual Studio C++ Build tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) when prompted to do so.


### Install and change to [Rust nightly](https://rust-lang.github.io/rustup/concepts/channels.html)

Execute the following commands to switch to the nightly version of Rust:

```powershell
rustup toolchain install nightly
rustup default nightly
```

### Install [LLVM](https://github.com/llvm/llvm-project)

The LLVM Toolkit is essential for generating bindings via `bindgen` due to its dependency on `libclang`. For Windows users, the recommended method to install LLVM and acquire `libclang` is through the `winget` package manager. Execute the following command to install:

```powershell
winget install LLVM.LLVM
```

### Install [cargo-make](https://github.com/sagiegurari/cargo-make)

Install the `cargo-make` tool with the following command:

```powershell
cargo install --locked cargo-make --no-default-features --features tls-native
```

### Install [cargo-expand](https://github.com/dtolnay/cargo-expand), [cargo-edit](https://github.com/killercup/cargo-edit), and [cargo-workspaces](https://github.com/pksunkara/cargo-workspaces) (Optional)

While it's not mandatory to install `cargo-expand`, `cargo-edit`, and `cargo-workspaces`, doing so can enhance your Rust development experience. Use the command below to install them:

```powershell
cargo install cargo-expand cargo-edit cargo-workspaces
```

### [Install WDK/SDK/EWDK](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

- Step 1: Install Visual Studio 2022
- Step 2: Install Windows 11, version 22H2 SDK
- Step 3: Install Windows 11, version 22H2 WDK
- Step 4: Set the `WDKContentRoot` environment variable to point to your WDK installation path, If it hasn't been set automatically during the WDK installation: 

```powershell
[System.Environment]::SetEnvironmentVariable("WDKContentRoot", "C:\Program Files (x86)\Windows Kits\10", [System.EnvironmentVariableTarget]::User)
```

- Step 5 (Optional) Alternative Method - Install Windows 11, version 22H2 (updated May 2023) EWDK with Visual Studio Build Tools
  - Expand the `.zip/.iso` file into an appropriately named directory, such as `d:\ewdk`.
  - Expand the `.zip/.iso` file into an appropriately named directory, such as `d:\ewdk`.
  - From an Administrator command prompt, navigate to the expanded folder in the previous step, and then run `LaunchBuildEnv.cmd` to create the build environment. For example: `D:\ewdk\LaunchBuildEnv.cmd`

## Build

### Development

```powershell
cargo make --profile development
```

### Production

```powershell
cargo make --profile release
```

## Debugging (Optional)

### 1. [Enabling Test Mode or Test Signing Mode](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)

To enable `Test Mode` or `Test Signing Mode`, open an elevated command prompt and enter the following command:

```powershell
bcdedit.exe /set testsigning on
```

### 2. [Enabling Debugging of Windows Boot Manager (bootmgfw.efi), Windows OS Boot Loader (winload.efi), and Windows Kernel (ntoskrnl.exe)](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--bootdebug)

The commands below enable debugging for the Windows Boot Manager, the boot loader, and the operating system's kernel. Using this combination allows for debugging at every startup stage. If activated, the target computer will break into the debugger three times: when the Windows Boot Manager loads, when the boot loader loads, and when the operating system starts. Enter the following commands in an elevated command prompt:

```powershell
bcdedit.exe /bootdebug {bootmgr} on
bcdedit.exe /bootdebug on
bcdedit.exe /debug on
```

### 3. [Setting Up Network Debugging for Windbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-a-network-debugging-connection)

To set up network debugging, open an elevated command prompt and enter the command below. Replace `w.x.y.z` with the IP address of the host computer and `n` with your chosen port number:

```powershell
bcdedit.exe /dbgsettings net hostip:w.x.y.z port:n
```

### 4. [Setting Up Debug Print Filter](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/reading-and-filtering-debugging-messages#setting-the-component-filter-mask)

Open the Windows registry editor by entering the following command in an elevated command prompt:

```powershell
regedit.exe
```

For more focused and efficient kernel development troubleshooting, set up filters to selectively display debugging messages by following these steps:

1. Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager`.
2. Create a new key named `Debug Print Filter`.
3. Inside this key, create a new `DWORD (32) Value`.
4. Name it `DEFAULT`.
5. Set its `Value data` to `8`.

### 5. [Configuring Serial Port Communication for Debugging](https://learn.microsoft.com/en-us/dotnet/api/system.io.ports.serialport?view=dotnet-plat-ext-7.0)

Efficient debugging in a hypervisor environment often requires capturing detailed debugging information from the virtualized system. To achieve this with VMware Workstation:

1. Navigate to `VM` -> `Settings`.
2. Click `Add` and select `Serial Port`.
3. Choose the option `Use output file` and specify the desired path for your log file.
4. Ensure the `Yield CPU on poll` checkbox is checked for optimal performance.

Once these settings are configured in VMware, proceed to set up the serial port within the Windows VM using the provided PowerShell script. With everything in place, running the hypervisor will log the output directly to the specified file on your host OS, streamlining the debugging process. You can opt for the succinct one-liner or the multi-line script, depending on your preference.

One-liner Script:

```powershell
$serialPort = New-Object System.IO.Ports.SerialPort COM2,9600,None,8,One; $serialPort.Open()
```

Multi-line Script:

```powershell
# Create a new instance of the SerialPort class
$serialPort = New-Object System.IO.Ports.SerialPort

# Specify the name of the serial port (COM2 in this case)
# COM ports are communication interfaces on a Windows system.
# COM2 refers to the second serial communication port.
$serialPort.PortName = "COM2"

# Set the baud rate to 9600
# The baud rate represents the number of bits transmitted per second.
# Both the sending and receiving devices must agree on the baud rate.
$serialPort.BaudRate = 9600

# Set parity to None
# Parity is an error-checking mechanism. "None" means no parity bit is added or checked.
# Depending on the reliability of your communication channel, you might choose to use parity.
$serialPort.Parity = "None"

# Set the number of data bits in each byte of the transmitted or received data to 8
# It determines the structure of the byte being sent or received.
# Both devices (sender and receiver) must agree on the number of data bits.
$serialPort.DataBits = 8

# Set the stop bits to One
# Stop bits indicate the end of a byte of data.
# It ensures synchronization between sender and receiver.
$serialPort.StopBits = "One"

# Open the serial port to start communication
$serialPort.Open()
```

### 6. [Creating and Starting a Service](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create)

```
sc.exe create matrix type= kernel binPath= C:\Windows\System32\drivers\matrix.sys
sc.exe query matrix
sc.exe start matrix
```

## Acknowledgments & References

This project has been inspired, influenced, and supported by numerous individuals and resources. A huge shout-out and thank you to everyone listed below:

### Tutorials & Articles

- **Daax Rynd**:
  - [7 Days to Virtualization: A Series on Hypervisor Development](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/)
  - [MMU Virtualization via Intel EPT](https://revers.engineering/mmu-virtualization-via-intel-ept-index/)
- **Sina Karvandi**: [Hypervisor From Scratch](https://rayanfam.com/tutorials/)
- **Secret Club**:
  - [BottlEye](https://secret.club/2020/07/06/bottleye.html)
  - [How Anti-Cheats Detect System Emulation](https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html)
  - [BattlEye Hypervisor Detection](https://secret.club/2020/01/12/battleye-hypervisor-detection.html)
- **Drew**: [HowToHypervise](https://howtohypervise.blogspot.com/)
- **Back Engineering Labs**: [AMD-V Hypervisor Development](https://blog.back.engineering/04/08/2022/)
- **MellowNight**: [AetherVisor](https://mellownight.github.io/AetherVisor)
- **Momo5502**: [Detecting Hypervisor-Assisted Hooking](https://momo5502.com/posts/2022-05-02-detecting-hypervisor-assisted-hooking/)
- **Joanna Rutkowska**: [Introducing Blue Pill](https://blog.invisiblethings.org/2006/06/22/introducing-blue-pill.html)
- **gerhart01**: [HyperResearchesHistory](https://github.com/gerhart01/Hyper-V-Internals/blob/master/HyperResearchesHistory.md)
- **gerhart01**: [HvInternals](https://hvinternals.blogspot.com/)
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
- **RCore Team**: [RVM1.5](https://github.com/rcore-os/RVM1.5/)
- **Cisco Talos**: [Barbervisor](https://github.com/Cisco-Talos/Barbervisor/)
- **Ian Kronquist**: [RustyVisor](https://github.com/iankronquist/rustyvisor/)
- **Mythril Team**: [Mythril](https://github.com/mythril-hypervisor/mythril/)
- **Hermit OS Team**: [uhyve](https://github.com/hermit-os/uhyve)
- **Gamozo Labs**: [Orange Slice](https://github.com/gamozolabs/orange_slice)
- **xeroxz (IDontCode)**: [BluePill](https://git.back.engineering/_xeroxz/bluepill)
- **DarthTon**: [Hyperbone](https://github.com/DarthTon/HyperBone/)
- **wbenny**: [Hvpp](https://github.com/wbenny/hvpp)
- **Alex Ionescu**: [SimpleVisor](https://github.com/ionescu007/SimpleVisor)
- **Air14**: [HyperHide](https://github.com/Air14/HyperHide)
- **MellowNight**: [AetherVisor](https://github.com/MellowNight/AetherVisor)
- **iPower**: [KasperskyHook](https://github.com/iPower/KasperskyHook)

### Videos

- **Gamozo Labs**: [Orange Slice: Writing the Hypervisor](https://www.youtube.com/watch?v=WabeOICAOq4&list=PLSkhUfcCXvqFJAuFbABktmLaQvJwKxJ3i)
- **Guided Hacking**: [x64 Virtual Address Translation](https://www.youtube.com/watch?v=W3o5jYHMh8s)

### Forums & Communities

- [UnKnoWnCheaTs](https://www.unknowncheats.me/)
- [Guided Hacking](https://guidedhacking.com/)

### Special Thanks

- **[Daax Rynd (@daaximus / @daax_rynd)](https://github.com/daaximus)** for:
  - [7 Days to Virtualization: A Series on Hypervisor Development](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/)
  - [MMU Virtualization via Intel EPT](https://revers.engineering/mmu-virtualization-via-intel-ept-index/)
- **[Sina Karvandi (@SinaKarvandi / @Intel80x86)](https://github.com/SinaKarvandi)** for: 
  - [Hypervisor From Scratch](https://rayanfam.com/tutorials/)
- [@not_matthias](https://twitter.com/not_matthias) for your project, answering a lot questions, helping in some errors, and being really helpful.
- `@vmprotect aka Jim Colerick` for helping in some errors, answering a lot questions, providing code snippets, and being really helpful.
- [@felix-rs / @joshuа](https://github.com/felix-rs) for answering a lot questions, helping in some errors, and being really helpful.
- `@jessiep_ aka Jess` for answering a lot of questions.
- [@rmccrystal](https://github.com/rmccrystal) for answering a few questions.
- [Christopher aka Kharosx0](https://twitter.com/Kharosx0) for answering a couple of questions.
- [@namazso](https://github.com/namazso) for [this post](https://www.unknowncheats.me/forum/2779560-post4.html).

### Conceptual Clarifications

- [Difference between Trap and Interrupt](https://stackoverflow.com/questions/3149175/what-is-the-difference-between-trap-and-interrupt/37558741#37558741)
