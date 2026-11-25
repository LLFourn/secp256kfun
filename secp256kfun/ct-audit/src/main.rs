#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(feature = "std")]
mod taint;

#[cfg(feature = "std")]
fn main() {
    taint::run();
}

#[cfg(not(feature = "std"))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    core::hint::black_box(secp256kfun_ct_audit::audit_mul_base as *const () as usize);
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(all(not(feature = "std"), feature = "alloc"))]
mod arena {
    use core::alloc::{GlobalAlloc, Layout};

    struct Arena;
    static mut SPACE: [u8; 131072] = [0; 131072];
    static mut NEXT: usize = 0;

    // This image is never executed on a device. A real bounded arena prevents LTO from
    // replacing allocation-dependent arithmetic with an unconditional allocation failure.
    unsafe impl GlobalAlloc for Arena {
        #[inline(never)]
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe {
                let base = (&raw mut SPACE).cast::<u8>() as usize;
                let aligned = (base + NEXT + layout.align() - 1) & !(layout.align() - 1);
                let end = aligned - base + layout.size();
                if end > 131072 {
                    return core::ptr::null_mut();
                }
                NEXT = end;
                aligned as *mut u8
            }
        }
        unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
    }

    #[global_allocator]
    static ALLOCATOR: Arena = Arena;
}
