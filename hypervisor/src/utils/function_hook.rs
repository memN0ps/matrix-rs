//! Provides utilities for inline hooking of functions, allowing redirection of function calls.
//! It includes creating and managing hooks with support for different types, enabling and disabling hooks,
//! and managing the necessary memory and page table entries.
//! Credits to Matthias: https://github.com/not-matthias/amd_hypervisor/blob/main/hypervisor/src/utils/function_hook.rs

use {
    crate::{error::HypervisorError, utils::nt::RtlCopyMemory},
    alloc::{boxed::Box, vec, vec::Vec},
    iced_x86::{
        BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, InstructionBlock,
    },
    wdk_sys::{
        ntddk::{IoAllocateMdl, IoFreeMdl, MmProbeAndLockPages, MmUnlockPages},
        PMDL,
        _LOCK_OPERATION::IoReadAccess,
        _MODE::KernelMode,
    },
    x86::bits64::paging::BASE_PAGE_SIZE,
};

/// Length of JMP shellcode.
pub const JMP_SHELLCODE_LEN: usize = 14;

/// Length of Breakpoint shellcode.
pub const BP_SHELLCODE_LEN: usize = 1;

/// Define the types of hooks available: JMP for jump-based hooks, Breakpoint for hooks that use breakpoints.
pub enum HookType {
    /// Jump-based hook.
    Jmp,

    /// Breakpoint-based hook.
    Breakpoint,
}

/// Represents a function hook with the capability to enable inline hooking.
pub struct FunctionHook {
    /// The trampoline code to execute the original function.
    trampoline: Box<[u8]>,

    /// The address where the hook is installed.
    hook_address: u64,

    /// The address of the handler function.
    handler: u64,

    /// Memory descriptor list for the hook address.
    mdl: PMDL,

    /// Type of the hook (Jmp or Breakpoint).
    hook_type: HookType,
}

impl FunctionHook {
    /// Creates a new inline hook for a given function. It prepares the necessary trampoline and other components but doesn't enable the hook.
    ///
    /// ## Parameters
    /// - `original_address`: The original address of the function to be hooked.
    /// - `hook_address`: The address where the hook will be placed.
    /// - `handler`: Pointer to the handler function that will be called instead of the original.
    ///
    /// ## Returns
    /// Returns an Option containing the new FunctionHook if successful, or None if failed.
    ///
    /// ## Safety
    /// This function allocates memory and manipulates page table entries. Incorrect use may lead to system instability.
    pub fn new(original_address: u64, hook_address: u64, handler: *const ()) -> Option<Self> {
        // Create the different trampolines. There's a few different ones available:
        // - 1 Byte: CC shellcode
        // - 14 Bytes: JMP shellcode
        //
        #[cfg(feature = "shellcode-hook")]
        let (hook_type, trampoline) =
            match Self::trampoline_shellcode(original_address, hook_address, JMP_SHELLCODE_LEN) {
                Ok(trampoline) => (HookType::Jmp, trampoline),
                Err(error) => {
                    log::warn!("Failed to create jmp trampoline: {:?}", error);

                    // If jmp trampoline didn't work, let's try this one:
                    //
                    let trampoline = Self::trampoline_shellcode(
                        original_address,
                        hook_address,
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

        // Allocate and lock the memory descriptor list for the page where the hook is installed.
        // This ensures the memory doesn't get paged out and is accessible when needed.
        let mdl = unsafe {
            IoAllocateMdl(
                original_address as _,
                BASE_PAGE_SIZE as _,
                false as _,
                false as _,
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

    /// Enables the hook by writing the jmp or breakpoint shellcode at the hook address.
    ///
    /// ## Details
    /// Depending on the hook type, it writes the appropriate shellcode to jump to the handler or to trigger a breakpoint.
    ///
    /// ## Safety
    /// This function modifies the instruction at the hook address. Ensure that this doesn't corrupt the program flow or overlap with critical instructions.
    pub fn enable(&self) {
        let jmp_to_handler = match self.hook_type {
            HookType::Jmp => Self::jmp_shellcode(self.handler).to_vec(),
            HookType::Breakpoint => vec![0xCC_u8], // 0xCC is the opcode for INT3, a common breakpoint instruction.
        };

        log::info!(
            "Writing the shellcode {:x?} to {:p}",
            jmp_to_handler,
            self.trampoline_address(),
        );

        // Write the shellcode to the hook address. Note that after virtualization of the current processor,
        // all variables are set to 0 due to stack invalidation. Hence, heap allocation is used instead.
        unsafe {
            RtlCopyMemory(
                self.hook_address as *mut u64,
                jmp_to_handler.as_ptr() as _,
                jmp_to_handler.len(),
            );
        }

        // Invalidate all processor caches to ensure the new instructions are used. (Will use invept instead of this later)
        //unsafe { KeInvalidateAllCaches() };
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

        unsafe { (shellcode.as_mut_ptr().add(6) as *mut u64).write_volatile(target_address) };

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
    /// - `original_function_address`: The address of the original function (on the real page).
    /// - `copied_function_address`: The address of the copied function (on the fake page)
    /// - `required_size`: The minimum size of the trampoline.
    ///
    /// ## Returns
    ///
    /// The trampoline shellcode.
    #[rustfmt::skip]
    fn trampoline_shellcode(original_function_address: u64, copied_function_address: u64, required_size: usize) -> Result<Box<[u8]>, HypervisorError> {
        // Read the bytes from the original function.
        let bytes = unsafe { core::slice::from_raw_parts(copied_function_address as *mut u8, usize::max(required_size * 2, 15) ) };

        // Decode the instructions at the original function's address.
        let decoder = Decoder::with_ip(64, bytes, copied_function_address, DecoderOptions::NONE);

        // Convert the decoder into an iterator and collect the instructions into a vector.
        let instructions: Vec<_> = decoder.into_iter().collect();

        // Allocate memory for the trampoline executable NonPagedPool pool.
        let mut memory = Box::new_uninit_slice(instructions.len() + JMP_SHELLCODE_LEN);
        log::info!("Allocated trampoline memory at {:p}", memory.as_ptr());

        let block = InstructionBlock::new(&instructions, memory.as_mut_ptr() as _);

        // Re-encode the instructions for the new location (trampoline) using BlockEncoder.
        let mut encoded = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE).map(|b| b.code_buffer)
            .map_err(|_| HypervisorError::EncodingFailed)?;

        // Calculate the address to jump back to after the trampoline
        let jump_back_address = original_function_address + encoded.len() as u64;

        // Create the jump back shellcode
        let jump_back_shellcode = Self::jmp_shellcode(jump_back_address);

        // Append the jump back shellcode to the trampoline
        encoded.extend_from_slice(jump_back_shellcode.as_slice());

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

    /// Provides a constant function to retrieve the address of the trampoline.
    ///
    /// ## Returns
    /// Returns the address of the trampoline as a mutable pointer to a 64-bit unsigned integer.
    pub const fn trampoline_address(&self) -> *mut u64 {
        self.trampoline.as_ptr() as _
    }

    /// Provides a constant function to retrieve the address of the handler.
    ///
    /// ## Returns
    /// Returns the address of the handler function as a 64-bit unsigned integer.
    pub const fn handler_address(&self) -> u64 {
        self.handler
    }
}

/// Implementation of the Drop trait for FunctionHook.
/// Ensures that when a FunctionHook is dropped, it unlocks and frees the pages associated with the hook.
impl Drop for FunctionHook {
    fn drop(&mut self) {
        if !self.mdl.is_null() {
            unsafe {
                // Unlock pages that were locked for this hook and free the memory descriptor list.
                MmUnlockPages(self.mdl);
                IoFreeMdl(self.mdl);
            };
        }
    }
}
