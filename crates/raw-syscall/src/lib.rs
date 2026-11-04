//! # raw-syscall
//!
//! Direct x86_64 Linux syscall primitives, with no libc linkage.
//!
//! A process-inspection tool needs to observe kernel state that the standard
//! library does not expose: the exact `errno` from an `mprotect` attempt, the
//! seals on a `memfd`, the raw bytes of a `ptrace` read from the
//! debug-register area, or whether a `getrandom` call actually filled its
//! buffer. Calling the kernel directly returns those values unmodified and
//! keeps this crate `no_std`-compatible.
//!
//! Conforms to the System V AMD64 ABI:
//! - Syscall number: `%rax`
//! - Arguments: `%rdi`, `%rsi`, `%rdx`, `%r10`, `%r8`, `%r9`
//! - Instruction: `syscall`
//! - Return: `%rax`, where values in `[-4095, -1]` denote `-errno`
//!
//! ## Scope
//!
//! This crate is a thin, mechanical layer. It contains no policy: it does not
//! decide what to read, what to trust, or what to do with the result. The
//! wrappers are `unsafe` because their contracts are the kernel's contracts —
//! a bad pointer or a misused request is undefined behaviour, exactly as it
//! would be in C.
//!
//! Only the x86_64 ABI is implemented. Other architectures are not supported.

#![no_std]

use core::arch::asm;

// Linux x86_64 System Call Numbers
pub const SYS_READ: usize = 0;
pub const SYS_WRITE: usize = 1;
pub const SYS_OPEN: usize = 2;
pub const SYS_CLOSE: usize = 3;
pub const SYS_MMAP: usize = 9;
pub const SYS_MPROTECT: usize = 10;
pub const SYS_MUNMAP: usize = 11;
pub const SYS_RT_SIGPROCMASK: usize = 14;
pub const SYS_PIPE: usize = 22;
pub const SYS_NANOSLEEP: usize = 35;
pub const SYS_GETPID: usize = 39;
pub const SYS_SOCKET: usize = 41;
pub const SYS_CONNECT: usize = 42;
pub const SYS_CLONE: usize = 56;
pub const SYS_FORK: usize = 57;
pub const SYS_EXECVE: usize = 59;
pub const SYS_EXIT: usize = 60;
pub const SYS_WAIT4: usize = 61;
pub const SYS_KILL: usize = 62;
pub const SYS_FCNTL: usize = 72;
pub const SYS_PTRACE: usize = 101;
pub const SYS_GETPPID: usize = 110;
pub const SYS_PRCTL: usize = 157;
pub const SYS_OPENAT: usize = 257;
pub const SYS_GETRANDOM: usize = 318;
pub const SYS_MEMFD_CREATE: usize = 319;
pub const SYS_EXECVEAT: usize = 322;

// Memory Protection Flags
pub const PROT_NONE: i32 = 0x0;
pub const PROT_READ: i32 = 0x1;
pub const PROT_WRITE: i32 = 0x2;
pub const PROT_EXEC: i32 = 0x4;

// mmap Flags
pub const MAP_PRIVATE: i32 = 0x02;
pub const MAP_ANONYMOUS: i32 = 0x20;

// open/openat Flags
pub const O_RDONLY: i32 = 0x0;
pub const O_WRONLY: i32 = 0x1;
pub const O_RDWR: i32 = 0x2;
pub const O_CLOEXEC: i32 = 0x80000;

// execveat Flags
pub const AT_EMPTY_PATH: i32 = 0x1000;
pub const AT_FDCWD: i32 = -100;

// Memfd Flags
pub const MFD_CLOEXEC: u32 = 0x0001;
pub const MFD_ALLOW_SEALING: u32 = 0x0002;

// Fcntl Sealing Flags
pub const F_ADD_SEALS: i32 = 1033;
pub const F_GET_SEALS: i32 = 1034;
pub const F_SEAL_SEAL: i32 = 0x0001;
pub const F_SEAL_SHRINK: i32 = 0x0002;
pub const F_SEAL_GROW: i32 = 0x0004;
pub const F_SEAL_WRITE: i32 = 0x0008;

// Prctl Operations
pub const PR_SET_NAME: i32 = 15;
pub const PR_SET_DUMPABLE: i32 = 4;
/// Allows the process with the given pid to `ptrace` this one.
pub const PR_SET_PTRACER: i32 = 0x5961_6d61;

// Ptrace Operations
pub const PTRACE_TRACEME: usize = 0;
/// Reads a word from the tracee's `struct user` area through `data`.
pub const PTRACE_PEEKUSER: usize = 3;
/// Attaches the caller as the tracer of `pid`.
pub const PTRACE_ATTACH: usize = 16;
/// Detaches the caller from the tracee and resumes it.
pub const PTRACE_DETACH: usize = 17;

/// Linux Timespec structure for nanosleep
#[repr(C)]
pub struct TimeSpec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// Issues a raw `syscall` with no arguments.
///
/// # Safety
///
/// `n` must be a valid syscall number for the running kernel. An invalid or
/// misused syscall can corrupt memory or terminate the process.
#[inline(always)]
pub unsafe fn syscall0(n: usize) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n as isize => ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

/// Issues a raw `syscall` with one argument.
///
/// # Safety
///
/// `n` must be a valid syscall number and `a1` must satisfy that syscall's
/// contract (including any pointer-validity requirements).
#[inline(always)]
pub unsafe fn syscall1(n: usize, a1: usize) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n as isize => ret,
        in("rdi") a1,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

/// Issues a raw `syscall` with two arguments.
///
/// # Safety
///
/// `n` must be a valid syscall number and `a1`/`a2` must satisfy that
/// syscall's contract (including any pointer-validity requirements).
#[inline(always)]
pub unsafe fn syscall2(n: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n as isize => ret,
        in("rdi") a1,
        in("rsi") a2,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

/// Issues a raw `syscall` with three arguments.
///
/// # Safety
///
/// `n` must be a valid syscall number and `a1`–`a3` must satisfy that
/// syscall's contract (including any pointer-validity requirements).
#[inline(always)]
pub unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n as isize => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

/// Issues a raw `syscall` with four arguments.
///
/// # Safety
///
/// `n` must be a valid syscall number and `a1`–`a4` must satisfy that
/// syscall's contract (including any pointer-validity requirements).
#[inline(always)]
pub unsafe fn syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n as isize => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        in("r10") a4,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

/// Issues a raw `syscall` with five arguments.
///
/// # Safety
///
/// `n` must be a valid syscall number and `a1`–`a5` must satisfy that
/// syscall's contract (including any pointer-validity requirements).
#[inline(always)]
pub unsafe fn syscall5(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n as isize => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        in("r10") a4,
        in("r8") a5,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

/// Issues a raw `syscall` with six arguments.
///
/// # Safety
///
/// `n` must be a valid syscall number and `a1`–`a6` must satisfy that
/// syscall's contract (including any pointer-validity requirements).
#[inline(always)]
pub unsafe fn syscall6(
    n: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n as isize => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        in("r10") a4,
        in("r8") a5,
        in("r9") a6,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

// Higher-level direct wrappers

/// Direct `sys_write`
///
/// # Safety
///
/// `buf` must point to at least `count` readable bytes for the duration of
/// the call. `fd` must be valid or intentionally invalid.
#[inline(always)]
pub unsafe fn sys_write(fd: i32, buf: *const u8, count: usize) -> isize {
    syscall3(SYS_WRITE, fd as usize, buf as usize, count)
}

/// Direct `sys_read`
///
/// # Safety
///
/// `buf` must point to at least `count` writable bytes that are not aliased
/// for the duration of the call. `fd` must be valid or intentionally invalid.
#[inline(always)]
pub unsafe fn sys_read(fd: i32, buf: *mut u8, count: usize) -> isize {
    syscall3(SYS_READ, fd as usize, buf as usize, count)
}

/// Direct `sys_close`
///
/// # Safety
///
/// The caller must own `fd`; closing a descriptor still in use elsewhere in
/// the process can cause subsequent operations to fail or target a reused fd.
#[inline(always)]
pub unsafe fn sys_close(fd: i32) -> isize {
    syscall1(SYS_CLOSE, fd as usize)
}

/// Direct `sys_mprotect`
///
/// # Safety
///
/// `[addr, addr + len)` must cover pages the caller is allowed to change, and
/// `prot` must be compatible with any later access the program makes. Removing
/// permissions from live memory causes faults on the next access.
#[inline(always)]
pub unsafe fn sys_mprotect(addr: *mut u8, len: usize, prot: i32) -> isize {
    syscall3(SYS_MPROTECT, addr as usize, len, prot as usize)
}

/// Direct `sys_mmap` (anonymous private mapping when flags = MAP_PRIVATE | MAP_ANONYMOUS)
///
/// # Safety
///
/// All arguments must satisfy `mmap(2)`. When `fd` is used, it must be a valid
/// descriptor of a suitable file. On success the caller owns the returned
/// mapping and must not access it outside the requested protections.
#[inline(always)]
pub unsafe fn sys_mmap(
    addr: *mut u8,
    len: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: usize,
) -> isize {
    syscall6(
        SYS_MMAP,
        addr as usize,
        len,
        prot as usize,
        flags as usize,
        fd as usize,
        offset,
    )
}

/// Direct `sys_munmap`
///
/// # Safety
///
/// `[addr, addr + len)` must be a page-aligned mapping owned by the caller.
/// Any pointer into that range is dangling after a successful call.
#[inline(always)]
pub unsafe fn sys_munmap(addr: *mut u8, len: usize) -> isize {
    syscall2(SYS_MUNMAP, addr as usize, len)
}

/// Direct `sys_open`
///
/// # Safety
///
/// `path` must be a valid NUL-terminated C string. `flags`/`mode` must be
/// valid for `open(2)`; on success the returned descriptor is owned by the
/// caller and must be closed.
#[inline(always)]
pub unsafe fn sys_open(path: *const u8, flags: i32, mode: u32) -> i32 {
    syscall3(SYS_OPEN, path as usize, flags as usize, mode as usize) as i32
}

/// Direct `sys_openat`
///
/// # Safety
///
/// `path` must be a valid NUL-terminated C string and `dirfd` must be a valid
/// descriptor (or `AT_FDCWD`). On success the returned descriptor is owned by
/// the caller and must be closed.
#[inline(always)]
pub unsafe fn sys_openat(dirfd: i32, path: *const u8, flags: i32, mode: u32) -> i32 {
    syscall4(
        SYS_OPENAT,
        dirfd as usize,
        path as usize,
        flags as usize,
        mode as usize,
    ) as i32
}

/// Direct `sys_fcntl`
///
/// # Safety
///
/// `fd` must be a valid descriptor and `arg` must be valid for `cmd`. Commands
/// that take a pointer require it to reference memory of the expected type.
#[inline(always)]
pub unsafe fn sys_fcntl(fd: i32, cmd: i32, arg: usize) -> isize {
    syscall3(SYS_FCNTL, fd as usize, cmd as usize, arg)
}

/// Direct `sys_execveat`
///
/// # Safety
///
/// `pathname`, `argv`, and `envp` must be valid NUL-terminated strings/pointer
/// arrays. On success the current process image is replaced and this function
/// does not return; the caller must also ensure the target is safe to execute.
#[inline(always)]
pub unsafe fn sys_execveat(
    dirfd: i32,
    pathname: *const u8,
    argv: *const *const u8,
    envp: *const *const u8,
    flags: i32,
) -> isize {
    syscall5(
        SYS_EXECVEAT,
        dirfd as usize,
        pathname as usize,
        argv as usize,
        envp as usize,
        flags as usize,
    )
}

/// Direct `sys_socket`
///
/// # Safety
///
/// The domain/type/protocol combination must be valid. On success the returned
/// descriptor is owned by the caller and must be closed.
#[inline(always)]
pub unsafe fn sys_socket(domain: i32, sock_type: i32, protocol: i32) -> i32 {
    syscall3(
        SYS_SOCKET,
        domain as usize,
        sock_type as usize,
        protocol as usize,
    ) as i32
}

/// Direct `sys_connect`
///
/// # Safety
///
/// `addr` must point to a valid `sockaddr` of at least `addrlen` bytes that is
/// appropriate for `fd`'s address family.
#[inline(always)]
pub unsafe fn sys_connect(fd: i32, addr: *const u8, addrlen: u32) -> isize {
    syscall3(SYS_CONNECT, fd as usize, addr as usize, addrlen as usize)
}

/// Direct `sys_pipe`
///
/// # Safety
///
/// `fds` must point to a writable `[i32; 2]`. On success both descriptors are
/// owned by the caller and must be closed.
#[inline(always)]
pub unsafe fn sys_pipe(fds: *mut i32) -> isize {
    syscall2(SYS_PIPE, fds as usize, 0)
}

/// Direct `sys_fork`
///
/// # Safety
///
/// Forks a process with the usual caveats: only the calling thread survives in
/// the child, and only async-signal-safe operations are permitted there before
/// `execve`. The caller must reap the child to avoid zombies.
#[inline(always)]
pub unsafe fn sys_fork() -> i32 {
    syscall0(SYS_FORK) as i32
}

/// Direct `sys_wait4`
///
/// # Safety
///
/// `status` may be null or must point to a writable `i32`; `rusage` may be null
/// or must point to a writable `struct rusage`. `pid`/`options` must be valid
/// for `wait4(2)`.
#[inline(always)]
pub unsafe fn sys_wait4(pid: i32, status: *mut i32, options: i32, rusage: *mut u8) -> i32 {
    syscall4(
        SYS_WAIT4,
        pid as usize,
        status as usize,
        options as usize,
        rusage as usize,
    ) as i32
}

/// Direct `sys_nanosleep`
///
/// # Safety
///
/// `req` must point to a valid `TimeSpec` with in-range fields; `rem` may be
/// null or must point to writable `TimeSpec` storage.
#[inline(always)]
pub unsafe fn sys_nanosleep(req: *const TimeSpec, rem: *mut TimeSpec) -> isize {
    syscall2(SYS_NANOSLEEP, req as usize, rem as usize)
}

/// Direct `sys_getpid`
///
/// # Safety
///
/// No pointer preconditions; the function is `unsafe` only because it is a raw
/// syscall with no libc wrapper.
#[inline(always)]
pub unsafe fn sys_getpid() -> i32 {
    syscall0(SYS_GETPID) as i32
}

/// Direct `sys_getppid`
///
/// # Safety
///
/// No pointer preconditions; the function is `unsafe` only because it is a raw
/// syscall with no libc wrapper.
#[inline(always)]
pub unsafe fn sys_getppid() -> i32 {
    syscall0(SYS_GETPPID) as i32
}

/// Direct `sys_ptrace`
///
/// # Safety
///
/// `request`/`pid`/`addr`/`data` must satisfy `ptrace(2)`. The call can stop,
/// modify, or inspect another process; the caller must own the target or
/// already be its tracer.
#[inline(always)]
pub unsafe fn sys_ptrace(request: usize, pid: i32, addr: usize, data: usize) -> isize {
    syscall4(SYS_PTRACE, request, pid as usize, addr, data)
}

/// Direct `sys_prctl`
///
/// # Safety
///
/// `option` and the argument interpretation must be valid for `prctl(2)`.
/// Options that consume pointers require valid memory of the expected type,
/// and options that alter process state affect the whole process.
#[inline(always)]
pub unsafe fn sys_prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> isize {
    syscall5(SYS_PRCTL, option as usize, arg2, arg3, arg4, arg5)
}

/// Direct `sys_getrandom`
///
/// # Safety
///
/// `buf` must point to at least `buflen` writable bytes that are not aliased
/// for the duration of the call; `flags` must be valid for `getrandom(2)`.
#[inline(always)]
pub unsafe fn sys_getrandom(buf: *mut u8, buflen: usize, flags: u32) -> isize {
    syscall3(SYS_GETRANDOM, buf as usize, buflen, flags as usize)
}

/// Direct `sys_memfd_create`
///
/// # Safety
///
/// `name` must be a valid NUL-terminated C string of at most 249 bytes and
/// `flags` must be valid for `memfd_create(2)`. On success the returned
/// descriptor is owned by the caller and must be closed.
#[inline(always)]
pub unsafe fn sys_memfd_create(name: *const u8, flags: u32) -> i32 {
    syscall2(SYS_MEMFD_CREATE, name as usize, flags as usize) as i32
}

/// Direct `sys_exit`
///
/// # Safety
///
/// Terminates the calling thread immediately without running destructors,
/// flushing buffers, or unwinding the stack.
#[inline(always)]
pub unsafe fn sys_exit(status: i32) -> ! {
    syscall1(SYS_EXIT, status as usize);
    loop {
        asm!("pause", options(nomem, nostack));
    }
}
