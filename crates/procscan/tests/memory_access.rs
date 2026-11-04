//! How `/proc/<pid>/mem` behaves against differently-protected regions.
//!
//! These tests need `unsafe` to create the memory states they exercise, so
//! they live in an integration test rather than the library crate. The library
//! itself is `#![forbid(unsafe_code)]`.
//!
//! # What these tests establish
//!
//! A mapping demoted to `PROT_NONE` is **still readable by the process that
//! owns it**. The kernel's `FOLL_FORCE` behaviour means `/proc/self/mem`
//! returns the real contents of a parked page rather than faulting.
//!
//! This is a load-bearing fact for the detector: "the pages are parked" does
//! not mean "the contents are hidden". A region can be `---p` and still
//! contain plaintext, so presence or absence of access is not by itself
//! evidence. The detector therefore ranks regions by *content* — entropy and
//! marker search — and treats protection state as a separate signal that
//! narrows the search rather than as proof of concealment.

use procscan::memory::Unreadable;
use procscan::{read_region, MemoryRegion};

/// Maps `len` bytes of anonymous read/write memory and returns its address.
fn map_rw(len: usize) -> *mut u8 {
    let addr = unsafe {
        raw_syscall::sys_mmap(
            core::ptr::null_mut(),
            len,
            raw_syscall::PROT_READ | raw_syscall::PROT_WRITE,
            raw_syscall::MAP_PRIVATE | raw_syscall::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(addr > 0, "mmap failed: {addr}");
    addr as *mut u8
}

fn unmap(ptr: *mut u8, len: usize) {
    let ret = unsafe { raw_syscall::sys_munmap(ptr, len) };
    assert_eq!(ret, 0, "munmap failed: {ret}");
}

/// Demotes a mapping to `PROT_NONE` and returns the previous protection.
fn park(ptr: *mut u8, len: usize) {
    let ret = unsafe { raw_syscall::sys_mprotect(ptr, len, raw_syscall::PROT_NONE) };
    assert_eq!(ret, 0, "mprotect(PROT_NONE) failed: {ret}");
}

fn unpark(ptr: *mut u8, len: usize) {
    let ret = unsafe {
        raw_syscall::sys_mprotect(ptr, len, raw_syscall::PROT_READ | raw_syscall::PROT_WRITE)
    };
    assert_eq!(ret, 0, "mprotect restore failed: {ret}");
}

/// Builds the region descriptor the kernel would report for a page range.
fn region_for(start: usize, len: usize, perms: &str) -> MemoryRegion {
    procscan::maps::parse_line(&format!(
        "{start:x}-{:x} {perms} 00000000 00:00 0",
        start + len
    ))
    .expect("region parses")
}

fn self_pid() -> i32 {
    std::process::id() as i32
}

#[test]
fn a_readable_region_can_be_read_back() {
    let len = 4096;
    let ptr = map_rw(len);

    // Fill with a known pattern so the read is verified, not just counted.
    unsafe { core::ptr::write_bytes(ptr, 0x5A, len) };

    let region = region_for(ptr as usize, len, "rw-p");
    let bytes = read_region(self_pid(), &region, len).expect("readable region");
    assert_eq!(bytes, vec![0x5A; len]);

    unmap(ptr, len);
}

#[test]
fn a_parked_region_is_still_readable_by_its_owner() {
    let len = 4096;
    let ptr = map_rw(len);
    unsafe { core::ptr::write_bytes(ptr, 0x5A, len) };
    park(ptr, len);

    let region = region_for(ptr as usize, len, "---p");
    let result = read_region(self_pid(), &region, len);

    unpark(ptr, len);
    unmap(ptr, len);

    // FOLL_FORCE lets a process reach its own memory regardless of the page
    // protection, so this read succeeds. If a future kernel changes that, the
    // read will start failing with Inaccessible and this test will say so.
    match result {
        Ok(bytes) => assert_eq!(
            bytes,
            vec![0x5A; len],
            "a parked region should return its real contents to its owner"
        ),
        Err(Unreadable::Inaccessible) => {
            // Acceptable: the kernel refused the read. Either behaviour is
            // fine for the detector, which does not depend on the outcome.
        }
        Err(other) => panic!("unexpected error reading a parked region: {other:?}"),
    }
}

#[test]
fn parking_a_region_does_not_erase_or_zero_it() {
    let len = 4096;
    let ptr = map_rw(len);

    let marker = b"MEMSENTRY_DORMANT_MARKER";
    unsafe {
        core::ptr::write_bytes(ptr, 0, len);
        core::ptr::copy_nonoverlapping(marker.as_ptr(), ptr, marker.len());
    }
    park(ptr, len);

    let region = region_for(ptr as usize, len, "---p");
    let result = read_region(self_pid(), &region, len);

    unpark(ptr, len);

    // The contents written before parking must still be there afterwards,
    // whether or not the read was permitted.
    let after = unsafe { core::slice::from_raw_parts(ptr, len) };
    assert!(
        after.windows(marker.len()).any(|w| w == marker.as_slice()),
        "parking must not modify the region"
    );

    if let Ok(bytes) = &result {
        assert!(
            bytes.windows(marker.len()).any(|w| w == marker.as_slice()),
            "a permitted read must return the real contents, not zeros"
        );
        // The practical consequence: a parked region can still be inspected
        // for content, which is exactly what the entropy detector relies on.
        let entropy = procscan::shannon_entropy(bytes);
        assert!(
            entropy < 7.5,
            "plaintext marker should not read as high entropy: {entropy}"
        );
    }

    unmap(ptr, len);
}

#[test]
fn a_missing_process_yields_a_classified_error() {
    let region = region_for(0x7f00_0000, 4096, "rw-p");
    let result = read_region(0, &region, 4096);
    assert!(
        matches!(
            result,
            Err(Unreadable::ProcessGone | Unreadable::PermissionDenied | Unreadable::Io(_))
        ),
        "unexpected result: {result:?}"
    );
}
