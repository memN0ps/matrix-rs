// Full Credits to Jim Colerick (@vmprotect) for all of the serial.rs code below:

pub const SERIAL_PORT: u16 = 0x2f8;
use core::sync::atomic::AtomicBool;

/// Provides mutual exclusion for the serial port
pub static mut SERIAL_LOCK: AtomicBool = AtomicBool::new(false);

unsafe fn out8(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(preserves_flags, nomem));
}

unsafe fn in8(port: u16) -> u8 {
    let val;
    core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(preserves_flags, nomem));
    val
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        use $crate::print;
        print!("{}\n", format_args!($($arg)*));
    }};
}

#[macro_export]
// No locking, in case panic happened during lock
macro_rules! panic_println {
    ($($arg:tt)*) => {{
        use $crate::panic_print;
        panic_print!("{}\n", format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! panic_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut serial = $crate::serial::Serial($crate::serial::SERIAL_PORT);
        // Format to a string to get the entire output as once
        // This is because with write fmt the lock will be acquired for each
        // string fragment which causes the format arguments not to be outputted
        // as a single line

        // Acquire lock here instead of using a string buffer as,
        // ExAllocatePoolWithTag does not behave correctly at IPI_LEVEL

        serial.write_fmt(format_args!($($arg)*)).unwrap(); // Never fails

    }};
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut serial = $crate::serial::Serial($crate::serial::SERIAL_PORT);
        // Format to a string to get the entire output as once
        // This is because with write fmt the lock will be acquired for each
        // string fragment which causes the format arguments not to be outputted
        // as a single line

        // Acquire lock here instead of using a string buffer as,
        // ExAllocatePoolWithTag does not behave correctly at IPI_LEVEL

        unsafe {
            // Get the lock
            while $crate::serial::SERIAL_LOCK.fetch_or(true, core::sync::atomic::Ordering::Acquire) {
                core::hint::spin_loop();
            }
        }

            serial.write_fmt(format_args!($($arg)*)).unwrap(); // Never fails

        unsafe {
            // Release the lock
            $crate::serial::SERIAL_LOCK.store(false, core::sync::atomic::Ordering::Release);
        }
    }};
}

/// Struct represention a serial port with a given io base address
pub struct Serial(pub u16);

impl core::fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        unsafe { serial_out(self.0, s) };
        Ok(())
    }
}
/// Tests whether the serial port at io base address `port` is clear to send
unsafe fn serial_clear_to_send(port: u16) -> bool {
    (in8(port + 5) & 0x20) != 0
}

#[allow(clippy::identity_op)]
/// Initialize the serial port, `port` contains the io base address for
/// the port to be initialized
unsafe fn serial_init(port: u16) {
    // Make sure the serial port is setup correctly
    out8(port + 1, 0x00); // Disable all interrupts
    out8(port + 3, 0x80); // DLAB
    out8(port + 0, 0x01); // Set divisor LOW
    out8(port + 1, 0x00); // Set divisor HIGH
    out8(port + 3, 0x03); // 8 data bits, 1 stop bit, no parity, DISABLE DLAB
    out8(port + 2, 0x00); // Clear fifo reg
    out8(port + 4, 0x03); // Request to send, Data terminal ready
}

/// Write `bytes` to the serial port at io base address `port`
unsafe fn serial_out(port: u16, bytes: impl AsRef<[u8]>) {
    // Force the port to be correctly setup
    serial_init(port);

    // Send out the bytes
    let slice = bytes.as_ref();

    for b in slice.iter().cloned() {
        while !serial_clear_to_send(port) {}
        out8(port, b);
    }
}
