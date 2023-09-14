use crate::x86_64::intel::vmexit::vmlaunch_failed;

/// Runs the guest until VM-exit occurs.
pub unsafe extern "C" fn launch_vm() -> ! {
    core::arch::asm!(
        "nop",
        // Save current (host) general purpose registers onto stack
        //save_general_purpose_registers_to_stack!(),

        // Launch the VM until a VM-exit occurs
        "vmlaunch",

        // call vmlaunch_failed as we should never execution here
        "call   {0}",

        sym vmlaunch_failed,
        options(noreturn),
    );
}
