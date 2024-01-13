use alloc::boxed::Box;
use wdk_sys::{ntddk::KeExpandKernelStackAndCallout, NTSTATUS, PVOID, STATUS_SUCCESS};

struct ClosureContext {
    closure: Option<Box<dyn FnOnce() -> NTSTATUS>>,
    status: NTSTATUS,
}

pub fn with_expanded_stack<F>(closure: F) -> NTSTATUS
where
    F: FnOnce() -> NTSTATUS + 'static,
{
    let mut context = ClosureContext {
        closure: Some(Box::new(closure)),
        status: STATUS_SUCCESS, // Default success status, adjust as needed
    };

    let status = unsafe {
        KeExpandKernelStackAndCallout(Some(call_closure), &mut context as *mut _ as PVOID, 0x10000)
    };

    context.status = status;

    context.status
}

unsafe extern "C" fn call_closure(context: PVOID) {
    let context = &mut *(context as *mut ClosureContext);
    let closure = context.closure.take().unwrap();
    context.status = closure();
}
