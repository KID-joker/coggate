//! Build-time locations of the native workers.
//!
//! `WORKER_PATH` always names the fail-closed, Linux-only execution worker.
//! `ENGINE_TEST_PATH` is a distinct, **unsandboxed** local development binary.
//! It must never be used to validate untrusted submissions.

/// The strict worker. Unsupported operating systems return an error.
pub const WORKER_PATH: &str = env!("COGGATE_WORKER_PATH");

/// UNSANDBOXED development binary for engine compatibility tests only.
#[cfg(feature = "engine-tests")]
pub const ENGINE_TEST_PATH: &str = env!("COGGATE_ENGINE_TEST_PATH");
