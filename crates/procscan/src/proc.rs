//! Read process metadata from `/proc`.
//!
//! Everything here is read-only. The parsers are separated from the readers so
//! they can be tested against fixed inputs without a live process.

use std::io;
use std::path::PathBuf;

use crate::maps::{parse_maps, MemoryRegion};

/// Selected fields from `/proc/<pid>/stat`.
///
/// Only the fields the detector needs are retained; the file has 52 fields and
/// most are irrelevant here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    /// Process id.
    pub pid: i32,
    /// Executable name, in parentheses in the raw file.
    pub comm: String,
    /// One-character scheduling state (`R`, `S`, `D`, `Z`, ...).
    pub state: char,
    /// Parent process id.
    pub ppid: i32,
}

/// Selected fields from `/proc/<pid>/status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// Thread name, which is what `prctl(PR_SET_NAME)` writes.
    pub name: String,
    /// Process id of the tracing process, or `0` when untraced.
    pub tracer_pid: i32,
    /// Real user id that owns the process.
    pub uid: u32,
}

/// Everything this crate reads about one process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Fields from `stat`.
    pub stat: Stat,
    /// Fields from `status`.
    pub status: Status,
    /// Argument vector from `cmdline`, empty when the process has none.
    pub argv: Vec<String>,
    /// Resolved `/proc/<pid>/exe` path, absent for kernel threads.
    pub exe: Option<PathBuf>,
    /// Memory mappings from `maps`.
    pub regions: Vec<MemoryRegion>,
}

impl ProcessInfo {
    /// Whether the process has any userspace memory mappings.
    ///
    /// Kernel threads run entirely in kernel space and have an empty `maps`
    /// file. A process that presents a kernel-thread name but *does* have
    /// mappings is not a kernel thread.
    pub fn has_userspace_mappings(&self) -> bool {
        !self.regions.is_empty()
    }

    /// Whether this process is consistent with being a kernel thread.
    ///
    /// A genuine kernel thread has no userspace mappings and no resolvable
    /// executable. Both conditions are required, because either alone can be
    /// produced independently by a userspace process.
    pub fn is_kernel_thread(&self) -> bool {
        !self.has_userspace_mappings() && self.exe.is_none()
    }

    /// Whether `status.Name` and `stat.comm` disagree.
    ///
    /// The two files are written from the same task name, so a mismatch means
    /// the name changed between the two reads, which is worth reporting.
    pub fn name_mismatch(&self) -> bool {
        self.status.name != self.stat.comm
    }

    /// Whether the process has no command line despite having a userspace image.
    ///
    /// `cmdline` is empty for kernel threads, so this only means something for
    /// a process that otherwise looks like userspace.
    pub fn has_empty_argv(&self) -> bool {
        self.argv.is_empty()
    }
}

/// Parses `/proc/<pid>/stat`.
///
/// The `comm` field is wrapped in parentheses and may itself contain spaces
/// and parentheses, so the field cannot be located by splitting on
/// whitespace. The parse therefore anchors on the last `)` in the line, which
/// is the closing parenthesis of `comm`; everything after it is positional.
pub fn parse_stat(input: &str) -> Option<Stat> {
    let open = input.find('(')?;
    let close = input.rfind(')')?;
    if close <= open {
        return None;
    }

    let pid = input[..open].trim().parse().ok()?;
    let comm = input[open + 1..close].to_string();

    let mut fields = input[close + 1..].split_whitespace();
    let state = fields.next()?.chars().next()?;
    let ppid = fields.next()?.parse().ok()?;

    Some(Stat {
        pid,
        comm,
        state,
        ppid,
    })
}

/// Parses `/proc/<pid>/status`.
pub fn parse_status(input: &str) -> Option<Status> {
    let mut name = None;
    let mut tracer_pid = None;
    let mut uid = None;

    for line in input.lines() {
        if let Some(value) = line.strip_prefix("Name:") {
            name = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("TracerPid:") {
            tracer_pid = value.trim().parse().ok();
        } else if let Some(value) = line.strip_prefix("Uid:") {
            // The line is "Uid: real effective saved fs", and the real uid is
            // the one that owns the process.
            uid = value.split_whitespace().next().and_then(|v| v.parse().ok());
        }
    }

    Some(Status {
        name: name?,
        tracer_pid: tracer_pid?,
        uid: uid?,
    })
}

/// Parses a NUL-separated `/proc/<pid>/cmdline` or `environ` buffer.
///
/// Entries are NUL-terminated, so the final element produces an empty trailing
/// field that is not a real argument.
pub fn parse_nul_list(input: &[u8]) -> Vec<String> {
    input
        .split(|&byte| byte == 0)
        .filter(|field| !field.is_empty())
        .map(|field| String::from_utf8_lossy(field).into_owned())
        .collect()
}

/// Reads `/proc/<pid>/stat`.
pub fn read_stat(pid: i32) -> io::Result<Stat> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_stat(&raw).ok_or_else(|| io::Error::other("malformed stat"))
}

/// Reads `/proc/<pid>/status`.
pub fn read_status(pid: i32) -> io::Result<Status> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    parse_status(&raw).ok_or_else(|| io::Error::other("malformed status"))
}

/// Reads `/proc/<pid>/cmdline`.
pub fn read_cmdline(pid: i32) -> io::Result<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline"))?;
    Ok(parse_nul_list(&raw))
}

/// Resolves `/proc/<pid>/exe`.
///
/// Returns `Ok(None)` for a kernel thread, which has no userspace executable.
pub fn read_exe(pid: i32) -> io::Result<Option<PathBuf>> {
    match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(path) => Ok(Some(path)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Reads and parses `/proc/<pid>/maps`.
pub fn read_maps(pid: i32) -> io::Result<Vec<MemoryRegion>> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    Ok(parse_maps(&raw))
}

/// Reads everything [`ProcessInfo`] holds for one process.
///
/// A process can exit partway through, in which case the first failing read is
/// returned and no partial result is produced.
pub fn read_process(pid: i32) -> io::Result<ProcessInfo> {
    Ok(ProcessInfo {
        stat: read_stat(pid)?,
        status: read_status(pid)?,
        argv: read_cmdline(pid)?,
        exe: read_exe(pid)?,
        regions: read_maps(pid)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_stat_line() {
        let line = "1234 (bash) S 1 1234 1234 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0";
        let stat = parse_stat(line).unwrap();
        assert_eq!(stat.pid, 1234);
        assert_eq!(stat.comm, "bash");
        assert_eq!(stat.state, 'S');
        assert_eq!(stat.ppid, 1);
    }

    #[test]
    fn parses_a_comm_containing_spaces() {
        let line = "42 (kworker/u16:1) S 2 0 0";
        let stat = parse_stat(line).unwrap();
        assert_eq!(stat.comm, "kworker/u16:1");
        assert_eq!(stat.state, 'S');
        assert_eq!(stat.ppid, 2);
    }

    #[test]
    fn parses_a_comm_containing_parentheses() {
        // A process may rename itself to something containing parentheses,
        // which is why the parse anchors on the last ')' rather than the first.
        let line = "7 (weird (name) here) R 1 7 7";
        let stat = parse_stat(line).unwrap();
        assert_eq!(stat.comm, "weird (name) here");
        assert_eq!(stat.state, 'R');
        assert_eq!(stat.ppid, 1);
    }

    #[test]
    fn rejects_a_stat_line_without_parentheses() {
        assert!(parse_stat("1234 bash S 1 1234").is_none());
    }

    #[test]
    fn rejects_a_stat_line_with_no_fields_after_comm() {
        assert!(parse_stat("1234 (bash)").is_none());
    }

    #[test]
    fn parses_a_status_block() {
        let input = "\
Name:\tbash
State:\tS (sleeping)
Tgid:\t1234
Pid:\t1234
PPid:\t1
TracerPid:\t0
Uid:\t1000\t1000\t1000\t1000
";
        let status = parse_status(input).unwrap();
        assert_eq!(status.name, "bash");
        assert_eq!(status.tracer_pid, 0);
        assert_eq!(status.uid, 1000);
    }

    #[test]
    fn parses_a_status_block_under_a_tracer() {
        let input = "Name:\tbash\nTracerPid:\t4242\nUid:\t0\t0\t0\t0\n";
        let status = parse_status(input).unwrap();
        assert_eq!(status.tracer_pid, 4242);
        assert_eq!(status.uid, 0);
    }

    #[test]
    fn rejects_a_status_block_missing_a_required_field() {
        assert!(parse_status("Name:\tbash\nTracerPid:\t0\n").is_none());
    }

    #[test]
    fn parses_a_nul_separated_cmdline() {
        let raw = b"/usr/bin/example\0--flag\0value\0";
        let argv = parse_nul_list(raw);
        assert_eq!(argv, vec!["/usr/bin/example", "--flag", "value"]);
    }

    #[test]
    fn parses_an_empty_cmdline() {
        assert!(parse_nul_list(b"").is_empty());
        assert!(parse_nul_list(b"\0").is_empty());
    }

    #[test]
    fn reads_the_current_process() {
        let info = read_process(std::process::id() as i32).expect("read self");
        assert_eq!(info.stat.pid, std::process::id() as i32);
        assert!(info.has_userspace_mappings());
        assert!(!info.is_kernel_thread());
        assert!(
            !info.has_empty_argv() || cfg!(test),
            "test harness sets argv"
        );
    }

    #[test]
    fn the_current_process_is_not_masquerading() {
        let info = read_process(std::process::id() as i32).expect("read self");
        assert!(!info.name_mismatch(), "comm and Name should agree");
    }
}
