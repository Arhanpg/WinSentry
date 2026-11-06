//! WinSentry Core Engine
//!
//! High-performance Windows storage reclamation and security auditing engine.
//! Interfaces directly with Win32 NT kernel APIs, Win32 security subsystem,
//! cryptographic hashers, and modern endpoint security pipelines.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const APP_NAME: &str = "WinSentry";

pub mod cache;
pub mod classifier;
pub mod dedup;
pub mod models;
pub mod remediation;
pub mod security;
pub mod win32;


