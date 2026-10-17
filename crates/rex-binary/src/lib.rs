//! # rex-binary
//!
//! Static analysis of native executables and firmware images.
//!
//! | Module | What it answers |
//! |---|---|
//! | [`model`] | What is this file? (format, CPU, sections, imports, exports, symbols) |
//! | [`checksec`](model::Mitigation) | How hard is it to exploit? (NX, PIE, RELRO, canaries, CFG, CET …) |
//! | [`strings`] | What text does it carry? (URLs, IPs, paths, registry keys, secrets) |
//! | [`capabilities`] | What can it *do*? (injection, persistence, keylogging … → ATT&CK) |
//! | [`packer`] | Is the real code hidden? |
//! | [`disasm`], [`functions`] | Where is the code, how does it flow, who calls whom? |
//! | [`fingerprint`] | How do I find its relatives? (imphash, TLSH) |
//! | [`carve`] | What's embedded inside? (filesystems, archives, keys) |
//! | [`diff`] | What changed between two versions? |
//!
//! Nothing here executes the input. All analysis is static.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod analyzers;
pub mod arm;
pub mod capabilities;
pub mod carve;
mod checksec;
pub mod diff;
pub mod disasm;
pub mod dotnet;
pub mod fingerprint;
pub mod functions;
pub mod go;
pub mod model;
pub mod packer;
pub mod strings;
pub mod wasm;
pub mod wasm_ops;
#[cfg(feature = "yara")]
pub mod yara;

pub use analyzers::register;
pub use model::Binary;
