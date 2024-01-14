//! # Crate Description
//! This crate provides utilities for working with kernel stack expansions in Rust,
//! leveraging the Windows Driver Kit (WDK). It offers a safe interface to expand the
//! kernel stack and execute closures with extended stack space.

use alloc::boxed::Box;
use wdk_sys::{ntddk::KeExpandKernelStackAndCallout, NTSTATUS, PVOID, STATUS_SUCCESS};

/// Represents a context for closure execution with expanded stack space.
struct ClosureContext {
    /// The closure to be executed. It's an `Option` to allow taking it out in a safe manner.
    closure: Option<Box<dyn FnOnce() -> NTSTATUS>>,
    /// The status returned by the closure or the kernel function.
    status: NTSTATUS,
}

/// Executes a given closure with an expanded kernel stack.
///
/// This function safely expands the kernel stack before executing the provided closure.
/// It's designed to prevent stack overflows when running large computations or deeply
/// nested calls in kernel mode.
///
/// # Arguments
///
/// * `closure` - A closure that returns an `NTSTATUS`. The closure is executed with
/// expanded stack space.
///
/// # Returns
///
/// * `NTSTATUS` - The status code returned by the closure, or by the kernel stack
/// expansion process if it fails.
///
/// # Examples
///
/// ```
/// let result = with_expanded_stack(|| {
///     // Perform heavy computation or deep recursion
///     STATUS_SUCCESS
/// });
/// ```
pub fn with_expanded_stack<F>(closure: F) -> NTSTATUS
where
    F: FnOnce() -> NTSTATUS + 'static,
{
    let mut context = ClosureContext {
        closure: Some(Box::new(closure)),
        status: STATUS_SUCCESS, // Default success status, adjust as needed
    };

    // Unsafe call to expand the kernel stack and execute the closure within that context
    let status = unsafe {
        KeExpandKernelStackAndCallout(Some(call_closure), &mut context as *mut _ as PVOID, 0x10000)
    };

    context.status = status;

    context.status
}

/// An unsafe extern "C" function that is called by `KeExpandKernelStackAndCallout`.
///
/// This function takes a pointer to a `ClosureContext`, extracts the closure, and executes it.
///
/// # Safety
///
/// This function is unsafe as it deals with raw pointers and manual closure execution.
///
/// # Arguments
///
/// * `context` - A raw pointer to `ClosureContext`.
unsafe extern "C" fn call_closure(context: PVOID) {
    let context = &mut *(context as *mut ClosureContext);
    let closure = context.closure.take().unwrap(); // Take the closure out of the context
    context.status = closure(); // Execute the closure and store the returned status
}
