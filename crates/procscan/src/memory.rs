//! Read mapped memory through `/proc/<pid>/mem`.
//!
//! Reads can fail for reasons that are themselves informative, so failures are
//! classified rather than flattened into a single error.
//!
//! # `FOLL_FORCE` and parked regions
//!
//! A region demoted to `PROT_NONE` is **not** hidden from the process that
//! owns it. The kernel's `FOLL_FORCE` behaviour lets `/proc/self/mem` return
//! the real contents of a parked page instead of faulting. Cross-process
//! reads depend on ptrace permission and may fail with [`Unreadable::Inaccessible`].
//!
//! The practical consequence for callers: do not treat "the read failed" as
//! evidence of concealment, and do not treat "the read succeeded" as evidence
//! of innocence. Page protection narrows the search; the contents decide it.
//! This is verified in `tests/memory_access.rs`.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use crate::maps::MemoryRegion;

/// Why a region could not be read.
#[derive(Debug)]
pub enum Unreadable {
    /// The kernel refused the read because the region is not accessible.
    ///
    /// A mapping marked `PROT_NONE` produces `EIO` when read, even by the
    /// owning user.
    Inaccessible,
    /// The caller lacks the privilege to read another process's memory.
    PermissionDenied,
    /// The process no longer exists.
    ProcessGone,
    /// Any other I/O failure.
    Io(io::Error),
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unreadable::Inaccessible => write!(f, "region not accessible"),
            Unreadable::PermissionDenied => write!(f, "permission denied"),
            Unreadable::ProcessGone => write!(f, "process is gone"),
            Unreadable::Io(err) => write!(f, "io error: {err}"),
        }
    }
}

impl std::error::Error for Unreadable {}

/// Result of reading a region.
pub type RegionRead = Result<Vec<u8>, Unreadable>;

/// Reads up to `limit` bytes from `region` in `pid`'s address space.
///
/// The region is truncated to `limit` bytes, so a caller scanning many
/// regions does not have to reason about unmapped address space beyond the
/// region bounds.
pub fn read_region(pid: i32, region: &MemoryRegion, limit: usize) -> RegionRead {
    let len = region.len().min(limit);
    if len == 0 {
        return Ok(Vec::new());
    }

    let mut mem = File::open(format!("/proc/{pid}/mem")).map_err(classify)?;
    mem.seek(SeekFrom::Start(region.start as u64))
        .map_err(classify)?;

    let mut buf = vec![0u8; len];
    match mem.read_exact(&mut buf) {
        Ok(()) => Ok(buf),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
            // The mapping shrank between the maps read and this read; keep
            // whatever was available rather than discarding it.
            let available = read_available(&mut mem, region, len);
            match available {
                Some(bytes) => Ok(bytes),
                None => Err(Unreadable::ProcessGone),
            }
        }
        Err(err) => Err(classify(err)),
    }
}

/// Best-effort re-read after a short read, returning what is actually there.
fn read_available(mem: &mut File, region: &MemoryRegion, len: usize) -> Option<Vec<u8>> {
    if mem.seek(SeekFrom::Start(region.start as u64)).is_err() {
        return None;
    }
    let mut buf = vec![0u8; len];
    match mem.read(&mut buf) {
        Ok(read) if read > 0 => {
            buf.truncate(read);
            Some(buf)
        }
        _ => None,
    }
}

/// Maps an I/O error onto the reason the kernel gave.
fn classify(err: io::Error) -> Unreadable {
    match err.raw_os_error() {
        // EIO: the kernel refuses to satisfy a read from a non-accessible
        // mapping.
        Some(5) => Unreadable::Inaccessible,
        // EPERM, EACCES: missing CAP_SYS_PTRACE or ptrace scope disallows it.
        Some(1) | Some(13) => Unreadable::PermissionDenied,
        // ESRCH, ENOENT: the task is gone.
        Some(3) | Some(2) => Unreadable::ProcessGone,
        _ => Unreadable::Io(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::parse_line;

    #[test]
    fn reads_a_readable_region_of_this_process() {
        // A boxed slice on the heap is mapped and readable, so it can be
        // located through maps and read back through /proc/self/mem.
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let addr = data.as_ptr() as usize;

        let pid = std::process::id() as i32;
        let regions = crate::proc::read_maps(pid).expect("read maps");
        let region = regions
            .iter()
            .find(|region| addr >= region.start && addr < region.end)
            .expect("heap region containing the buffer");

        let bytes = read_region(pid, region, region.len()).expect("read region");
        assert_eq!(bytes.len(), region.len());

        // The buffer is somewhere inside the region; find it and check the
        // bytes survived the round trip.
        let offset = addr - region.start;
        assert_eq!(&bytes[offset..offset + data.len()], &data[..]);
    }

    #[test]
    fn truncates_a_read_to_the_limit() {
        let data = vec![0xABu8; 8192];
        let addr = data.as_ptr() as usize;
        let pid = std::process::id() as i32;
        let regions = crate::proc::read_maps(pid).expect("read maps");
        let region = regions
            .iter()
            .find(|region| addr >= region.start && addr < region.end)
            .expect("region containing the buffer");

        let bytes = read_region(pid, region, 64).expect("read region");
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn a_zero_length_read_returns_nothing() {
        let region = parse_line("7f00-7f00 rw-p 00000000 00:00 0").unwrap();
        let bytes = read_region(std::process::id() as i32, &region, 4096).expect("empty read");
        assert!(bytes.is_empty());
    }

    #[test]
    fn a_missing_process_is_reported_as_gone() {
        // Pid 0 is never a valid target for /proc/<pid>/mem.
        let region = parse_line("7f00-7f10 rw-p 00000000 00:00 0").unwrap();
        let result = read_region(0, &region, 16);
        assert!(
            matches!(result, Err(Unreadable::ProcessGone | Unreadable::Io(_))),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn classifies_common_errno_values() {
        use std::io::Error;
        assert!(matches!(
            classify(Error::from_raw_os_error(5)),
            Unreadable::Inaccessible
        ));
        assert!(matches!(
            classify(Error::from_raw_os_error(1)),
            Unreadable::PermissionDenied
        ));
        assert!(matches!(
            classify(Error::from_raw_os_error(13)),
            Unreadable::PermissionDenied
        ));
        assert!(matches!(
            classify(Error::from_raw_os_error(3)),
            Unreadable::ProcessGone
        ));
    }
}
