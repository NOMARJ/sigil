//! Corpus module: declarative signature pack schema and loader.
//!
//! Packs are JSON documents containing regex rules and declarative suppression
//! predicates.  No executable code lives in packs — only data that the engine
//! evaluates.
//!
//! # Module structure
//!
//! - [`schema`] — `SignaturePack`, `PackRule`, `FileFilter`, `SuppressionPredicates`
//! - [`loader`] — discovers and parses packs from embedded data and `~/.sigil/packs/`
//! - [`engine`] — runs pack rules against file content, returning `Finding`s
//! - [`compiled`] — the same rules compiled once into a cached, per-phase form
//! - [`custom`] — custom packs named for one run (`--rules`, policy `rule_packs`)
//! - [`yara`] — YARA rule files (`.yar`, `.yara`) loaded as custom packs

pub mod compiled;
pub mod custom;
pub mod engine;
pub mod loader;
pub mod schema;
pub mod signing;
pub mod yara;

#[cfg(test)]
mod agent_supply_chain_tests;
#[cfg(test)]
mod guardrail_tests;
#[cfg(test)]
mod insecure_transport_tests;
#[cfg(test)]
mod mcp_fp_tests;
#[cfg(test)]
mod multilingual_tests;
