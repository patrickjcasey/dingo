#![no_std]
#![no_main]

use core::alloc::GlobalAlloc;
use dingo_proto::Message;

struct Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        unsafe { libc::malloc(layout.size()).cast() }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        unsafe {
            libc::free(ptr.cast());
        }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: Allocator = Allocator;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        libc::abort();
    }
}

#[unsafe(no_mangle)]
extern "C" fn main(_argc: libc::c_uint, _argv: *const *const u8) -> libc::c_uint {
    #[rustfmt::skip]
        let packet = [
            // Header
            0x12, 0x34,             // ID = 0x1234
            0x01, 0x00,             // Flags: RD=1 (standard query with recursion desired)
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x00,             // ANCOUNT = 0
            0x00, 0x00,             // NSCOUNT = 0
            0x00, 0x00,             // ARCOUNT = 0
            // Question section
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01,             // QTYPE = A (1)
            0x00, 0x01,             // QCLASS = IN (1)
        ];
    Message::parse(&packet).unwrap();
    0
}
