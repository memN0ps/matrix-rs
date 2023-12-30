/// Credits to Matthias: https://github.com/not-matthias/amd_hypervisor/blob/main/hypervisor/src/utils/function_hook.rs

use {
    alloc::{boxed::Box, vec, vec::Vec},
    wdk_sys::{
        ntddk::{
            IoAllocateMdl, IoFreeMdl, KeInvalidateAllCaches, MmProbeAndLockPages, MmUnlockPages,
        },
        _LOCK_OPERATION::IoReadAccess, _MODE::KernelMode, PMDL,
    },
    x86::bits64::paging::BASE_PAGE_SIZE,
    crate::{error::HypervisorError, utils::nt::RtlCopyMemory},
    iced_x86::{BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, FlowControl, InstructionBlock},
};

pub const JMP_SHELLCODE_LEN: usize = 14;
pub const BP_SHELLCODE_LEN: usize = 1;

pub enum HookType {
    Jmp,
    Breakpoint,
}

pub struct FunctionHook {
    trampoline: Box<[u8]>,

    /// Address where the inline hook has been written to (shadow page)
    hook_address: u64,
    handler: u64,

    mdl: PMDL,

    hook_type: HookType,
}

impl FunctionHook {
    /// Creates a new inline hook (not yet enabled) for the specified function.
    ///
    /// ## Parameters
    ///
    ///
    ///
    /// ## Note
    ///
    /// Note: We have to allocate a new instance here, so that it's valid after
    /// the virtualization. Otherwise, all the addresses would be 0x0.
    pub fn new(original_address: u64, hook_address: u64, handler: *const ()) -> Option<Self> {
        log::info!(
            "Creating a new inline hook. Address: {:x}, handler: {:x}",
            hook_address,
            handler as u64
        );

        // Create the different trampolines. There's a few different ones available:
        // - 1 Byte: CC shellcode
        // - 14 Bytes: JMP shellcode
        //
        #[cfg(feature = "shellcode-hook")]
            let (hook_type, trampoline) = match Self::trampoline_shellcode(
            original_address,
            hook_address as u64,
            JMP_SHELLCODE_LEN,
        ) {
            Ok(trampoline) => (HookType::Jmp, trampoline),
            Err(error) => {
                log::warn!("Failed to create jmp trampoline: {:?}", error);

                // If jmp trampoline didn't work, let's try this one:
                //
                let trampoline = Self::trampoline_shellcode(
                    original_address,
                    hook_address as u64,
                    BP_SHELLCODE_LEN,
                )
                    .map_err(|e| {
                        log::warn!("Failed to create bp trampoline: {:?}", e);
                        e
                    })
                    .ok()?;

                (HookType::Breakpoint, trampoline)
            }
        };

        #[cfg(not(feature = "shellcode-hook"))]
            let (hook_type, trampoline) = {
            let trampoline =
                Self::trampoline_shellcode(original_address, hook_address, BP_SHELLCODE_LEN)
                    .map_err(|e| {
                        log::warn!("Failed to create bp trampoline: {:?}", e);
                        e
                    })
                    .ok()?;

            (HookType::Breakpoint, trampoline)
        };

        // Lock the virtual address. The specified hook address can/will be tradable
        // pagable memory or where its physical address can be changed by the
        // Memory Manager at any time. We need to prevent that because we assume
        // permanent 1:1 mapping of the hook virtual and physical addresses.
        //
        let mdl = unsafe {
            IoAllocateMdl(
                original_address as _,
                BASE_PAGE_SIZE as _,
                0,
                0,
                0 as _,
            )
        };
        if mdl.is_null() {
            log::warn!("Failed to allocate mdl");
            return None;
        }
        unsafe { MmProbeAndLockPages(mdl, KernelMode as _, IoReadAccess) };

        Some(Self {
            trampoline,
            hook_type,
            hook_address,
            mdl,
            handler: handler as u64,
        })
    }

    pub fn enable(&self) {
        let jmp_to_handler = match self.hook_type {
            HookType::Jmp => Self::jmp_shellcode(self.handler).to_vec(),
            HookType::Breakpoint => vec![0xCC_u8],
        };

        log::info!(
            "Writing the shellcode {:x?} to {:p}",
            jmp_to_handler,
            self.trampoline_address(),
        );

        // Note: In order for this to work, we have to use an heap allocated instance
        // instead of a stack allocated one. Otherwise, the stack will be
        // invalidated after the virtualization of the current processor. After
        // that, all the variables will be set to 0.
        //
        unsafe {
            RtlCopyMemory(
                self.hook_address as *mut u64,
                jmp_to_handler.as_ptr() as _,
                jmp_to_handler.len(),
            );
        }

        unsafe { KeInvalidateAllCaches() };
    }

    /// Creates the jmp shellcode.
    ///
    /// ## How it works.
    ///
    /// We are using the following assembly shellcode:
    /// ```asm
    /// jmp [rip+00h]
    /// 0xDEADBEEF
    /// ```
    ///
    /// Or in a different format:
    ///
    /// ```asm
    /// jmp qword ptr cs:jmp_add
    /// jmp_addr: dq 0xDEADBEEF
    /// ```
    ///
    /// The core premise behind it is, that we jump to the address that is right
    /// after the current instruction.
    ///
    /// ## Why use this instead of `mov rax, jmp rax`?
    ///
    /// This shellcode has one very important feature: **It doesn't require any
    /// registers to store the jmp address**. And because of that, we don't
    /// have to fear overwriting some register values.
    fn jmp_shellcode(target_address: u64) -> [u8; 14] {
        log::info!(
            "Creating the jmp shellcode for address: {:#x}",
            target_address
        );

        // Create the shellcode. See function documentation for more information.
        //
        let mut shellcode = [
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        ];
        unsafe {
            (shellcode.as_mut_ptr().add(6) as *mut u64).write_volatile(target_address)
        };
        log::info!("Jmp shellcode: {:x?}", shellcode);

        shellcode
    }

    /// Creates a trampoline shellcode that jumps to the original function.
    ///
    /// NOTE: The trampoline doesn't support RIP-relative instructions. If any
    /// of these relative instructions are found,
    /// `InlineHookError::RelativeInstruction` will be returned.
    ///
    /// ## Parameters
    ///
    /// - `original_address`: The address of the original function (on the real
    ///   page).
    /// - `address`: The address of function in the copied page.
    /// - `size`: The minimum size of the trampoline.
    ///
    /// ## Returns
    ///
    /// The trampoline shellcode.
    fn trampoline_shellcode(
        original_address: u64, address: u64, required_size: usize,
    ) -> Result<Box<[u8]>, HypervisorError> {
        log::info!("Creating the trampoline for function: {:#x}", address);

        // Read bytes from function and decode them. Read 2 times the amount needed, in
        // case there are bigger instructions that take more space. If there's
        // only 1 byte needed, we read 15 bytes instead so that we can find the
        // first few valid instructions.
        //
        let bytes = unsafe {
            core::slice::from_raw_parts(address as *mut u8, usize::max(required_size * 2, 15))
        };
        let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);

        let mut total_bytes = 0;
        let mut trampoline = Vec::new();
        for instr in &mut decoder {
            if instr.is_invalid() {
                return Err(HypervisorError::InvalidBytes);
            }

            if total_bytes >= required_size {
                break;
            }

            if instr.is_ip_rel_memory_operand() {
                return Err(HypervisorError::RelativeInstruction);
            }

            // Create the new trampoline instruction
            //
            match instr.flow_control() {
                FlowControl::Next | FlowControl::Return => {
                    total_bytes += instr.len();
                    trampoline.push(instr);
                }
                FlowControl::Call
                | FlowControl::ConditionalBranch
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectCall => {
                    return Err(HypervisorError::RelativeInstruction);
                }
                FlowControl::IndirectBranch
                | FlowControl::Interrupt
                | FlowControl::XbeginXabortXend
                | FlowControl::Exception => return Err(HypervisorError::UnsupportedInstruction),
            };
        }

        if total_bytes < required_size {
            return Err(HypervisorError::NotEnoughBytes);
        }

        if trampoline.is_empty() {
            return Err(HypervisorError::NoInstructions);
        }

        // Allocate new memory for the trampoline and encode the instructions.
        //
        let mut memory = Box::new_uninit_slice(total_bytes + JMP_SHELLCODE_LEN);
        log::info!("Allocated trampoline memory at {:p}", memory.as_ptr());

        let block = InstructionBlock::new(&trampoline, memory.as_mut_ptr() as _);
        let mut encoded = BlockEncoder::encode(decoder.bitness(), block, BlockEncoderOptions::NONE)
            .map(|b| b.code_buffer)
            .map_err(|_| HypervisorError::EncodingFailed)?;
        log::info!("Encoded trampoline: {:x?}", encoded);

        // Add jmp to the original function at the end. We can't use `address` for this,
        // because the page will probably contain rip-relative instructions. And
        // we already switch the page So the shadow page will be at the address
        // of the original page.
        //
        let jmp_back_address = original_address + encoded.len() as u64;
        let jmp_shellcode = Self::jmp_shellcode(jmp_back_address);
        encoded.extend_from_slice(jmp_shellcode.as_slice());

        // Copy the encoded bytes and return the allocated memory.
        //
        unsafe {
            core::ptr::copy_nonoverlapping(
                encoded.as_ptr(),
                memory.as_mut_ptr() as _,
                encoded.len(),
            )
        };

        Ok(unsafe { memory.assume_init() })
    }

    pub const fn trampoline_address(&self) -> *mut u64 {
        self.trampoline.as_ptr() as _
    }

    pub const fn handler_address(&self) -> u64 {
        self.handler
    }
}

impl Drop for FunctionHook {
    fn drop(&mut self) {
        if !self.mdl.is_null() {
            unsafe {
                MmUnlockPages(self.mdl);
                IoFreeMdl(self.mdl);
            };
        }
    }
}