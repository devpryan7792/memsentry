//! Parse `/proc/<pid>/maps` into structured memory regions.
//!
//! The `maps` file is the primary record of what a process has mapped. Each
//! line describes one virtual-memory area:
//!
//! ```text
//! 7f8e4c000000-7f8e4c021000 rw-p 00000000 00:00 0
//! 7f8e4c021000-7f8e4c200000 ---p 00000000 00:00 0
//! 563f2a1b4000-563f2a1b5000 r--p 00000000 08:01 1048594  /usr/bin/example
//! ```
//!
//! Fields are `address  perms  offset  dev  inode  pathname`, and the
//! pathname is absent for anonymous mappings.

use std::fmt;

/// One virtual-memory region from `/proc/<pid>/maps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    /// First address in the region.
    pub start: usize,
    /// One past the last address in the region.
    pub end: usize,
    /// Whether the region is readable.
    pub read: bool,
    /// Whether the region is writable.
    pub write: bool,
    /// Whether the region is executable.
    pub exec: bool,
    /// Whether the mapping is shared rather than private.
    pub shared: bool,
    /// File offset the mapping starts at, for file-backed regions.
    pub offset: u64,
    /// Device number as printed by the kernel, e.g. `08:01`.
    pub dev: String,
    /// Inode of the backing file, or `0` for anonymous mappings.
    pub inode: u64,
    /// Path of the backing file, absent for anonymous mappings.
    pub pathname: Option<String>,
}

impl MemoryRegion {
    /// Size of the region in bytes.
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether the region is empty.
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    /// Permission string as the kernel prints it, e.g. `rw-p` or `---p`.
    pub fn perms(&self) -> String {
        let mut out = String::with_capacity(4);
        out.push(if self.read { 'r' } else { '-' });
        out.push(if self.write { 'w' } else { '-' });
        out.push(if self.exec { 'x' } else { '-' });
        out.push(if self.shared { 's' } else { 'p' });
        out
    }

    /// Whether the region has no access at all (`---p`).
    ///
    /// This is the state a region is parked in when its contents are meant to
    /// fault on any access, which is why it is worth reporting separately.
    pub fn is_inaccessible(&self) -> bool {
        !self.read && !self.write && !self.exec
    }

    /// Whether the region is writable and executable at the same time.
    pub fn is_writable_and_executable(&self) -> bool {
        self.write && self.exec
    }

    /// Whether the region has no backing file.
    ///
    /// Anonymous mappings are reported with no pathname, or with a bracketed
    /// pseudo-path such as `[heap]`, `[stack]`, or `[vdso]`.
    pub fn is_anonymous(&self) -> bool {
        match self.pathname.as_deref() {
            None => true,
            Some(path) => path.is_empty() || path.starts_with('['),
        }
    }

    /// Whether the backing path was reported as unlinked.
    ///
    /// The kernel appends ` (deleted)` to the path of a file that was removed
    /// after being mapped.
    pub fn is_deleted(&self) -> bool {
        self.pathname
            .as_deref()
            .is_some_and(|path| path.ends_with("(deleted)"))
    }

    /// Whether the mapping is backed by an anonymous memory file descriptor.
    ///
    /// A `memfd` mapping has no filesystem path; the kernel prints it as
    /// `/memfd:<name>` when it has a name, or `/memfd: (deleted)` otherwise.
    pub fn is_memfd(&self) -> bool {
        self.pathname
            .as_deref()
            .is_some_and(|path| path.starts_with("/memfd:") || path.contains("memfd:"))
    }
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:x}-{:x} {} {}",
            self.start,
            self.end,
            self.perms(),
            self.pathname.as_deref().unwrap_or("")
        )
    }
}

/// Parses the full contents of a `maps` file.
///
/// Unparseable lines are skipped rather than treated as errors: the kernel
/// does not guarantee the file is unchanged between the read and the parse,
/// and a single malformed line should not lose the rest of the mapping.
pub fn parse_maps(input: &str) -> Vec<MemoryRegion> {
    input.lines().filter_map(parse_line).collect()
}

/// Parses one line of a `maps` file.
pub fn parse_line(line: &str) -> Option<MemoryRegion> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let (range, rest) = line.split_once(char::is_whitespace)?;
    let (start, end) = range.split_once('-')?;
    let start = usize::from_str_radix(start, 16).ok()?;
    let end = usize::from_str_radix(end, 16).ok()?;

    let rest = rest.trim_start();
    let (perms, rest) = split_field(rest)?;
    let perms: Vec<char> = perms.chars().collect();
    if perms.len() != 4 {
        return None;
    }
    let read = perms[0] == 'r';
    let write = perms[1] == 'w';
    let exec = perms[2] == 'x';
    let shared = perms[3] == 's';

    let (offset, rest) = split_field(rest)?;
    let offset = u64::from_str_radix(offset, 16).ok()?;

    let (dev, rest) = split_field(rest)?;
    let dev = dev.to_string();

    // The pathname is the remainder and may itself contain spaces, so it is
    // split off last. Anonymous mappings have no pathname at all, in which
    // case the inode is the final field.
    let (inode, pathname) = match rest.trim_start().split_once(char::is_whitespace) {
        Some((inode, pathname)) => (inode, pathname.trim()),
        None => (rest.trim_start(), ""),
    };
    let inode = inode.parse().ok()?;

    Some(MemoryRegion {
        start,
        end,
        read,
        write,
        exec,
        shared,
        offset,
        dev,
        inode,
        pathname: if pathname.is_empty() {
            None
        } else {
            Some(pathname.to_string())
        },
    })
}

/// Splits off the first whitespace-delimited field, returning it and the rest.
fn split_field(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start();
    match input.split_once(char::is_whitespace) {
        Some((field, rest)) => Some((field, rest)),
        None if input.is_empty() => None,
        None => Some((input, "")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_anonymous_region() {
        let region = parse_line("7f8e4c021000-7f8e4c200000 ---p 00000000 00:00 0").unwrap();
        assert_eq!(region.start, 0x7f8e4c021000);
        assert_eq!(region.end, 0x7f8e4c200000);
        assert_eq!(region.perms(), "---p");
        assert!(region.is_inaccessible());
        assert!(!region.is_writable_and_executable());
        assert!(region.is_anonymous());
        assert_eq!(region.pathname, None);
        assert_eq!(region.inode, 0);
    }

    #[test]
    fn parses_a_file_backed_region() {
        let line = "563f2a1b4000-563f2a1b5000 r--p 00000000 08:01 1048594    /usr/bin/example";
        let region = parse_line(line).unwrap();
        assert_eq!(region.perms(), "r--p");
        assert!(!region.is_anonymous());
        assert_eq!(region.pathname.as_deref(), Some("/usr/bin/example"));
        assert_eq!(region.inode, 1048594);
        assert_eq!(region.dev, "08:01");
        assert_eq!(region.offset, 0);
    }

    #[test]
    fn preserves_spaces_in_a_pathname() {
        let line = "7f00-7f01 rw-p 00000000 00:00 0    /tmp/a file with spaces";
        let region = parse_line(line).unwrap();
        assert_eq!(region.pathname.as_deref(), Some("/tmp/a file with spaces"));
    }

    #[test]
    fn parses_a_bracketed_pseudo_path_as_anonymous() {
        let region = parse_line("55d0-55d1 rw-p 00000000 00:00 0    [heap]").unwrap();
        assert!(region.is_anonymous());
        assert_eq!(region.pathname.as_deref(), Some("[heap]"));
    }

    #[test]
    fn detects_writable_and_executable() {
        let region = parse_line("7f00-7f01 rwxp 00000000 00:00 0").unwrap();
        assert!(region.is_writable_and_executable());
        assert_eq!(region.perms(), "rwxp");
    }

    #[test]
    fn detects_a_deleted_backing_file() {
        let line = "7f00-7f01 r-xp 00000000 00:00 5    /tmp/payload (deleted)";
        let region = parse_line(line).unwrap();
        assert!(region.is_deleted());
        assert!(!region.is_memfd());
    }

    #[test]
    fn detects_a_memfd_mapping() {
        let region =
            parse_line("7f00-7f01 r-xp 00000000 00:00 42    /memfd:worker (deleted)").unwrap();
        assert!(region.is_memfd());
        assert!(region.is_deleted());
    }

    #[test]
    fn rejects_a_line_with_a_short_permission_field() {
        assert!(parse_line("7f00-7f01 rw 00000000 00:00 0").is_none());
    }

    #[test]
    fn rejects_an_empty_line() {
        assert!(parse_line("").is_none());
        assert!(parse_line("   ").is_none());
    }

    #[test]
    fn skips_malformed_lines_without_losing_the_rest() {
        let input = "\
7f00-7f01 rw-p 00000000 00:00 0
this line is not a mapping
7f02-7f03 ---p 00000000 00:00 0
";
        let regions = parse_maps(input);
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].start, 0x7f00);
        assert_eq!(regions[1].start, 0x7f02);
    }

    #[test]
    fn computes_length_and_emptiness() {
        let region = parse_line("7f00-7f10 rw-p 00000000 00:00 0").unwrap();
        assert_eq!(region.len(), 0x10);
        assert!(!region.is_empty());

        let empty = parse_line("7f00-7f00 rw-p 00000000 00:00 0").unwrap();
        assert!(empty.is_empty());
    }
}
