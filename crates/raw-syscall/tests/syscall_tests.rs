use raw_syscall::*;

#[test]
fn test_direct_getpid_matches() {
    let raw_pid = unsafe { sys_getpid() };
    assert!(raw_pid > 0);
    let std_pid = std::process::id() as i32;
    assert_eq!(raw_pid, std_pid);
}

#[test]
fn test_direct_getrandom() {
    let mut buf = [0u8; 32];
    let ret = unsafe { sys_getrandom(buf.as_mut_ptr(), buf.len(), 0) };
    assert_eq!(ret, 32);
    // Ensure not all bytes are zero
    assert!(buf.iter().any(|&b| b != 0));
}

#[test]
fn test_direct_nanosleep() {
    let req = TimeSpec {
        tv_sec: 0,
        tv_nsec: 10_000_000, // 10ms
    };
    let mut rem = TimeSpec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let start = std::time::Instant::now();
    let ret = unsafe { sys_nanosleep(&req, &mut rem) };
    assert_eq!(ret, 0);
    assert!(start.elapsed() >= std::time::Duration::from_millis(9));
}

#[test]
fn test_direct_memfd_and_write() {
    let name = b"syscall_test_fd\0";
    let fd = unsafe { sys_memfd_create(name.as_ptr(), MFD_CLOEXEC) };
    assert!(fd > 0);

    let test_bytes = b"RAW_SYSCALL_IO_TEST";
    let written = unsafe { sys_write(fd, test_bytes.as_ptr(), test_bytes.len()) };
    assert_eq!(written, test_bytes.len() as isize);

    let closed = unsafe { sys_close(fd) };
    assert_eq!(closed, 0);
}

#[test]
fn test_direct_mprotect_cycle() {
    let len = 4096usize;
    let addr = unsafe {
        sys_mmap(
            core::ptr::null_mut(),
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(addr > 0, "mmap failed: {addr}");
    let ptr = addr as *mut u8;

    unsafe {
        core::ptr::write_bytes(ptr, 0xAB, len);
    }

    let ret = unsafe { sys_mprotect(ptr, len, PROT_NONE) };
    assert_eq!(ret, 0, "mprotect(PROT_NONE) failed");

    let maps = std::fs::read_to_string("/proc/self/maps").expect("read maps");
    let line = maps
        .lines()
        .find(|line| range_contains(line, addr as usize, len))
        .expect("mapping present in /proc/self/maps");
    let perms = line.split_whitespace().nth(1).unwrap_or("");
    assert_eq!(perms, "---p", "unexpected page permissions: {line}");

    let ret = unsafe { sys_mprotect(ptr, len, PROT_READ | PROT_WRITE) };
    assert_eq!(ret, 0, "mprotect(RW) failed");

    for i in 0..len {
        assert_eq!(unsafe { *ptr.add(i) }, 0xAB, "data corrupted at offset {i}");
    }

    let ret = unsafe { sys_munmap(ptr, len) };
    assert_eq!(ret, 0, "munmap failed");
}

#[test]
fn test_direct_fcntl_getfl() {
    const F_GETFL: i32 = 3;
    let flags = unsafe { sys_fcntl(1, F_GETFL, 0) };
    assert!(flags >= 0, "fcntl(F_GETFL) failed: {flags}");
}

#[test]
fn test_direct_openat_read_comm() {
    let path = b"/proc/self/comm\0";
    let fd = unsafe { sys_openat(AT_FDCWD, path.as_ptr(), O_RDONLY | O_CLOEXEC, 0) };
    assert!(fd >= 0, "openat(/proc/self/comm) failed: {fd}");

    let mut buf = [0u8; 64];
    let n = unsafe { sys_read(fd, buf.as_mut_ptr(), buf.len()) };
    assert!(n > 0, "read(comm) failed: {n}");

    let closed = unsafe { sys_close(fd) };
    assert_eq!(closed, 0);
}

fn range_contains(line: &str, addr: usize, len: usize) -> bool {
    let Some(range) = line.split_whitespace().next() else {
        return false;
    };
    let mut parts = range.split('-');
    let start = usize::from_str_radix(parts.next().unwrap_or(""), 16).unwrap_or(0);
    let end = usize::from_str_radix(parts.next().unwrap_or(""), 16).unwrap_or(0);
    addr >= start && addr.checked_add(len).is_some_and(|top| top <= end)
}
