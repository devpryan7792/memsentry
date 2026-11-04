//! # procscan
//!
//! Read-only parsing and analysis of Linux `/proc`.
//!
//! This crate turns the kernel's process bookkeeping into structured data:
//! memory mappings, process identity, and byte-level statistics over mapped
//! memory. It makes no judgements — deciding what a mapping *means* is the
//! caller's job.
//!
//! ## What it reads
//!
//! | Source | Module | Contents |
//! | :--- | :--- | :--- |
//! | `/proc/<pid>/maps` | [`maps`] | Virtual-memory regions and permissions |
//! | `/proc/<pid>/stat` | [`proc`] | Process id, name, state, parent |
//! | `/proc/<pid>/status` | [`proc`] | Thread name, tracer, owner |
//! | `/proc/<pid>/cmdline` | [`proc`] | Argument vector |
//! | `/proc/<pid>/exe` | [`proc`] | Resolved executable path |
//! | mapped memory | [`memory`] | Region contents for analysis |
//! | byte buffers | [`entropy`] | Shannon entropy |
//!
//! ## Design
//!
//! Parsing is separated from reading throughout. Every parser takes a `&str`
//! or `&[u8]` and is unit-tested against fixed input, so the parsing logic can
//! be verified without a live process and without depending on the running
//! kernel's exact output.
//!
//! ## Limits
//!
//! `/proc` is a snapshot, not a transaction. A process can change between two
//! reads that together form one finding. Readers return raw values so callers
//! can surface what was actually observed.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod entropy;
pub mod maps;
pub mod memory;
pub mod proc;

pub use entropy::shannon_entropy;
pub use maps::{parse_maps, MemoryRegion};
pub use memory::{read_region, RegionRead};
pub use proc::{read_process, ProcessInfo, Stat, Status};
