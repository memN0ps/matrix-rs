//! This module provides functionalities for creating and managing hooks in a hypervisor environment.
//! It includes support for function hooks and page hooks, allowing manipulation and monitoring
//! of system behavior at a low level. The module is designed for use in scenarios requiring direct
//! interaction with system internals, such as in kernel and hypervisor development.
//!
//! Credits to Matthias: https://github.com/not-matthias/amd_hypervisor/blob/main/hypervisor/src/hook.rs

use {
    crate::{
        error::HypervisorError,
        intel::ept::paging::{AccessType, Ept},
        utils::{
            addresses::PhysicalAddress,
            alloc::PhysicalAllocator,
            function_hook::FunctionHook,
            nt::{get_ntoskrnl_export, RtlCopyMemory},
        },
    },
    alloc::{boxed::Box, vec::Vec},
    x86::current::paging::{PAddr, VAddr, BASE_PAGE_SIZE},
    x86_64::instructions::interrupts::without_interrupts,
};

/// Enum representing different types of hooks that can be applied.
pub enum HookType {
    /// Hook for intercepting and possibly modifying function execution.
    Function { inline_hook: FunctionHook },

    /// Hook for hiding or monitoring access to a specific page.
    Page,
}

/// Represents a hook in the system, either on a function or a page.
pub struct Hook {
    /// Original virtual address of the target function or page.
    pub original_va: u64,

    /// Original physical address of the target function or page.
    pub original_pa: PhysicalAddress,

    /// Virtual address where the hook is placed.
    pub hook_va: u64,

    /// Physical address of the hook.
    pub hook_pa: PhysicalAddress,

    /// Contents of the original page where the hook is placed.
    pub page: Box<[u8]>,

    /// Virtual address of the page containing the hook.
    pub page_va: u64,

    /// Physical address of the page containing the hook.
    pub page_pa: PhysicalAddress,

    /// Type of the hook (Function or Page).
    pub hook_type: HookType,
}

impl Hook {
    /// Creates a copy of a page in memory.
    ///
    /// This is necessary to ensure that the code operates on valid memory even if the original
    /// page is paged out. It's particularly important in kernel mode where page faults
    /// cannot be easily recovered.
    ///
    /// # Arguments
    ///
    /// * `va` - Virtual address of the page to copy.
    ///
    /// # Returns
    ///
    /// * `Option<Box<[u8]>>` - A boxed slice containing the copied page data.
    ///
    /// Reference: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/when-should-code-and-data-be-pageable-
    fn copy_page(address: u64) -> Option<Box<[u8]>> {
        log::info!("Creating a copy of the page at address: {:#x}", address);

        let page_address = PAddr::from(address).align_down_to_base_page();
        if page_address.is_zero() {
            log::error!("Invalid page address: {:#x}", address);
            return None;
        }
        let mut page = Box::new_uninit_slice(BASE_PAGE_SIZE);

        // Perform the memory copy operation without interruptions.
        without_interrupts(|| {
            unsafe {
                RtlCopyMemory(
                    page.as_mut_ptr() as _,
                    page_address.as_u64() as *mut u64,
                    BASE_PAGE_SIZE,
                )
            };
        });

        Some(unsafe { page.assume_init() })
    }

    /// Calculates the address of a function within the copied page.
    ///
    /// # Arguments
    ///
    /// * `page_start` - The start address of the copied page.
    /// * `address` - The original address of the function.
    ///
    /// # Returns
    ///
    /// * `u64` - The adjusted address of the function within the new page.
    fn address_in_page(page_start: u64, address: u64) -> u64 {
        let base_offset = VAddr::from(address).base_page_offset();
        page_start + base_offset
    }

    /// Creates a hook on a function by its pointer.
    ///
    /// This function sets up a hook directly using the function's pointer. It copies the page where the function resides,
    /// installs a hook on that page, and then returns a `Hook` struct representing this setup.
    ///
    /// # Arguments
    ///
    /// * `function_ptr` - The pointer to the function to be hooked.
    /// * `handler` - A pointer to the handler function that will be called instead of the original function.
    ///
    /// # Returns
    ///
    /// * `Option<Self>` - An instance of `Hook` if successful, or `None` if an error occurred.
    pub fn hook_function_ptr(function_ptr: u64, handler: *const ()) -> Option<Self> {
        let original_pa = PhysicalAddress::from_va(function_ptr);
        log::info!("Obtained physical address: {:#x}", original_pa.as_u64());

        // Copy the page where the function resides to prevent modifying the original page.
        let page = Self::copy_page(function_ptr)?;
        let page_va = page.as_ptr() as *mut u64 as u64;
        let page_pa = PhysicalAddress::from_va(page_va);

        // Calculate the virtual and physical address of the function in the copied page.
        let hook_va = Self::address_in_page(page_va, function_ptr);
        let hook_pa = PhysicalAddress::from_va(hook_va);

        // Create an inline hook at the new address in the copied page.
        let inline_hook = FunctionHook::new(function_ptr, hook_va, handler)?;

        Some(Self {
            original_va: function_ptr,
            original_pa,
            hook_va,
            hook_pa,
            page,
            page_va,
            page_pa,
            hook_type: HookType::Function { inline_hook },
        })
    }

    /// Creates a hook on a function by its name.
    ///
    /// This function looks up the address of a named function within the NT kernel, and then
    /// uses that address to set up a hook, similar to `hook_function_ptr`.
    ///
    /// # Arguments
    ///
    /// * `function_name` - The name of the function to be hooked.
    /// * `handler` - A pointer to the handler function.
    ///
    /// # Returns
    ///
    /// * `Option<Self>` - An instance of `Hook` if successful, or `None` if the function cannot be found or an error occurred.
    pub fn hook_function(function_name: &str, handler: *const ()) -> Option<Self> {
        // Obtain the address of the NT kernel function by its name.
        let address = get_ntoskrnl_export(function_name);

        // Error handling if the function address could not be retrieved.
        if address.is_null() {
            log::error!("Failed to find function: {}", function_name);
            return None;
        }

        log::info!("Address of function {}: {:p}", function_name, address);

        // Utilize the previously defined function for hooking by address.
        Self::hook_function_ptr(address as u64, handler)
    }

    /// Creates a hook on a specific page.
    ///
    /// This function sets up a hook on a specific memory page, allowing for monitoring or altering the page's content.
    ///
    /// # Arguments
    ///
    /// * `address` - The address of the page to be hooked.
    ///
    /// # Returns
    ///
    /// * `Option<Self>` - An instance of `Hook` if successful, or `None` if an error occurred.
    pub fn hook_page(address: u64) -> Option<Self> {
        let original_pa = PhysicalAddress::from_va(address);

        // Copy the target page for hooking.
        let page = Self::copy_page(address)?;
        let page_va = page.as_ptr() as *mut u64 as u64;
        let page_pa = PhysicalAddress::from_va(page_va);

        // In case of a page hook, the virtual and physical addresses are the same as the copied page.
        Some(Self {
            original_va: address,
            original_pa,
            page_va,
            page_pa,
            hook_va: page_va,
            hook_pa: page_pa,
            page,
            hook_type: HookType::Page,
        })
    }
}

/// Manages the lifecycle and control of various hooks.
///
/// `HookManager` is a container for multiple hooks and provides an interface
/// to enable or disable these hooks as a group. It's primarily responsible for
/// modifying the Extended Page Tables (EPT) to facilitate the hooking mechanism.
pub struct HookManager {
    /// A collection of hooks managed by the HookManager.
    pub hooks: Vec<Hook>,
}

impl HookManager {
    /// Constructs a new `HookManager` with a given set of hooks.
    ///
    /// # Arguments
    ///
    /// * `hooks` - A vector of `Hook` instances to be managed.
    pub fn new(hooks: Vec<Hook>) -> Self {
        Self { hooks }
    }

    /// Enables all the hooks managed by the `HookManager`.
    ///
    /// It sets the necessary permissions on the primary and secondary Extended Page Tables (EPTs)
    /// to intercept execution and data access at specific memory locations. This function is
    /// particularly used to switch between primary and secondary EPTs when executing hooked functions.
    ///
    /// # Arguments
    ///
    /// * `primary_ept` - A mutable reference to the primary EPT, typically representing the normal memory view.
    /// * `secondary_ept` - A mutable reference to the secondary EPT, typically representing the altered memory view for hooks.
    ///
    /// # Errors
    ///
    /// Returns `HypervisorError` if any operations on the EPTs fail.
    ///
    /// # Notes
    ///
    /// This method assumes that the necessary secondary EPT setup is already done and that the EPTs provided
    /// are correctly initialized and represent the actual memory views intended for the normal execution and
    /// for the execution when hooks are active, respectively.
    ///
    /// Reference: https://tandasat.github.io/VXCON/AMD-V_for_Hackers.pdf
    pub fn enable_hooks(
        &self,
        primary_ept: &mut Box<Ept, PhysicalAllocator>,
        secondary_ept: &mut Box<Ept, PhysicalAllocator>,
    ) -> Result<(), HypervisorError> {
        for hook in &self.hooks {
            // Enable the hook if it is a function hook, which involves
            // modifying the targeted function's instructions.
            if let HookType::Function { inline_hook } = &hook.hook_type {
                inline_hook.enable();
            }

            // let page = hook.original_pa.align_down_to_large_page().as_u64();
            // let hook_page = hook.hook_pa.align_down_to_large_page().as_u64();

            // log::info!("Splitting 2MB page to 4KB pages for Primary EPT: {:#x}", page);
            // primary_ept.split_2mb_to_4kb(page)?;

            // log::info!("Splitting 2MB page to 4KB pages for Secondary EPT: {:#x}", hook_page);
            // secondary_ept.split_2mb_to_4kb(hook_page)?;

            // Align addresses to their base page sizes for accurate permission modification.
            let page = hook.original_pa.align_down_to_base_page().as_u64();
            let hook_page = hook.hook_pa.align_down_to_base_page().as_u64();

            log::info!(
                "Changing permissions for page to Read-Write (RW) only: {:#x}",
                page
            );

            // Modify the page permission in the primary EPT to ReadWrite.
            primary_ept.change_page_flags(page, AccessType::READ_WRITE)?;

            log::info!(
                "Changing permissions for hook page to Execute (X) only: {:#x}",
                hook_page
            );

            // Modify the page permission in the secondary EPT to Execute for the hook page.
            secondary_ept.change_page_flags(hook_page, AccessType::EXECUTE)?;
        }

        Ok(())
    }
}
