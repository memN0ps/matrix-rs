/// Credits to Matthias: https://github.com/not-matthias/amd_hypervisor/blob/main/hypervisor/src/hook.rs
use {
    crate::{
        intel::{
            ept::{access::AccessType, paging::Ept},
            invept::invept_all_contexts,
        },
        utils::{
            addresses::PhysicalAddress,
            function_hook::FunctionHook,
            nt::{get_ntoskrnl_export, RtlCopyMemory},
        },
    },
    alloc::{boxed::Box, vec::Vec},
    x86::current::paging::{PAddr, VAddr, BASE_PAGE_SIZE},
    x86_64::instructions::interrupts::without_interrupts,
};

/// Hook type.
pub enum HookType {
    /// Creates a shadow page to hook a function.
    Function { inline_hook: FunctionHook },

    /// Creates a shadow page to hide some utils.
    Page,
}

/// A hook.
pub struct Hook {
    /// The original virtual address of the hooked function / page.
    pub original_va: u64,

    /// The original physical address of the hooked function / page.
    pub original_pa: PhysicalAddress,

    /// The virtual address of the hook.
    pub hook_va: u64,

    /// The physical address of the hook.
    pub hook_pa: PhysicalAddress,

    /// The original bytes of the hooked function / page.
    pub page: Box<[u8]>,

    /// The virtual address of the page that contains the hook.
    pub page_va: u64,

    /// The physical address of the page that contains the hook.
    pub page_pa: PhysicalAddress,

    /// The type of the hook.
    pub hook_type: HookType,
}

impl Hook {
    /// Creates a copy of the specified page.
    ///
    /// Why does this code have to be paged? Because otherwise the code could be paged out, which will result in a
    /// page fault. We must make sure, that this code must be called at IRQL
    /// < DISPATCH_LEVEL.
    ///
    /// For more information, see the official docs:https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/when-should-code-and-data-be-pageable-
    ///
    /// # Arguments
    ///
    /// * `va` - The address of the page to copy.
    ///
    /// # Returns
    ///
    /// * `Option<Box<[u8]>>` - The copied page.
    fn copy_page(address: u64) -> Option<Box<[u8]>> {
        log::info!("Creating a copy of the page");

        let page_address = PAddr::from(address).align_down_to_base_page();
        if page_address.is_zero() {
            log::error!("Invalid address: {:#x}", address);
            return None;
        }
        let mut page = Box::new_uninit_slice(BASE_PAGE_SIZE);

        log::info!("Page address: {:#x}", page_address);

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

    /// Returns the address of the specified function in the copied page.
    ///
    /// # Arguments
    ///
    /// * `page_start` - The address of the copied page.
    /// * `address` - The address of the function.
    ///
    /// # Returns
    ///
    /// * `u64` - The address of the function in the copied page.
    fn address_in_page(page_start: u64, address: u64) -> u64 {
        let base_offset = VAddr::from(address).base_page_offset();

        page_start + base_offset
    }

    pub fn hook_function_ptr(function_ptr: u64, handler: *const ()) -> Option<Self> {
        let original_pa = PhysicalAddress::from_va(function_ptr);
        log::info!("Physical address: {:#x}", original_pa.as_u64());

        let page = Self::copy_page(function_ptr)?;
        let page_va = page.as_ptr() as *mut u64 as u64;
        let page_pa = PhysicalAddress::from_va(page_va);

        let hook_va = Self::address_in_page(page_va, function_ptr);
        let hook_pa = PhysicalAddress::from_va(hook_va);

        // Install inline hook on the **copied** page (not the original one).
        //
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

    pub fn hook_function(function_name: &str, handler: *const ()) -> Option<Self> {
        let address = get_ntoskrnl_export(function_name);

        if address.is_null() {
            log::error!("Could not find function: {}", function_name);
            return None;
        }

        log::info!("Found function address of {}: {:p}", function_name, address);

        Self::hook_function_ptr(address as u64, handler)
    }

    pub fn hook_page(address: u64) -> Option<Self> {
        let original_pa = PhysicalAddress::from_va(address);

        let page = Self::copy_page(address)?;
        let page_va = page.as_ptr() as *mut u64 as u64;
        let page_pa = PhysicalAddress::from_va(page_va);

        let hook_va = page_va;
        let hook_pa = PhysicalAddress::from_va(hook_va);

        Some(Self {
            original_va: address,
            original_pa,
            page_va,
            page_pa,
            hook_va,
            hook_pa,
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
    /// Constructs a new HookManager with a given set of hooks.
    ///
    /// # Arguments
    ///
    /// * `hooks` - A vector of Hook instances to be managed.
    pub fn new(hooks: Vec<Hook>) -> Self {
        Self { hooks }
    }

    /// Enables all the hooks managed by the HookManager.
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
    /// For each hook, it:
    /// - Enables the inline hook if it's a function hook.
    /// - Changes the page permission of the original page in the primary EPT to RW.
    /// - Changes the page permission of the hooked page in the secondary EPT to RWX.
    ///
    /// # Notes
    ///
    /// This method assumes that the necessary secondary EPT setup is already done and that the EPTs provided
    /// are correctly initialized and represent the actual memory views intended for the normal execution and
    /// for the execution when hooks are active, respectively.
    ///
    /// Detailed documentation and examples of this technique are available in: [AMD-V for Hackers](https://tandasat.github.io/VXCON/AMD-V_for_Hackers.pdf)
    pub fn enable_hooks(&self, primary_ept: &mut Ept, secondary_ept: &mut Ept) {
        for hook in &self.hooks {
            // Enable the hook if it is a function hook. This might involve
            // rewriting the targeted function's prologue with a jump to the handler.
            if let HookType::Function { inline_hook } = &hook.hook_type {
                inline_hook.enable()
            }

            // Align the original and hooked page addresses down to their base page sizes.
            // This ensures that we're modifying the permissions for the entire page where the
            // hook is applied.
            let page = hook.original_pa.align_down_to_base_page().as_u64();
            let hook_page = hook.hook_pa.align_down_to_base_page().as_u64();

            // Change the page permission in the primary EPT to Execute. This is done to
            // ensure that when the guest tries to read/write from this page, a page fault occurs,
            // and the handler can switch to the secondary EPT.
            primary_ept.change_page_flags(page, AccessType::ReadWrite);

            // In the secondary EPT, change the permission of the hook page to Read-Write.
            // This is where the actual hook resides, and read/write should proceed normally when
            // this page is active.
            secondary_ept.change_page_flags(hook_page, AccessType::Execute);

            // Invalidate the EPT translation cache (INVEPT)
            invept_all_contexts();
        }
    }
}
