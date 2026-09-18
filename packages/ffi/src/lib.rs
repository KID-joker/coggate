#![deny(unsafe_op_in_unsafe_fn)]

mod adapters;
mod callbacks;
mod json;
mod memory;
mod service;
mod status;

pub use callbacks::{
    AgActiveKeyCallback, AgAttemptOutcome, AgBeginAttemptCallback, AgBeginStatus, AgCallbackHeader,
    AgFinishAttemptCallback, AgKeyByIdCallback, AgKeyCallbacks, AgKeyStatus, AgLifecycleCallbacks,
    AgLifecycleStatus, AgObserveCallback, AgObserverCallbacks, AgStoreIssuedCallback,
};
pub use memory::{AgByteSlice, AgHostBuffer, AgHostRelease, AgOwnedBuffer, ag_buffer_free};
pub use service::{
    AgAttemptLimit, AgService, ag_service_create, ag_service_destroy, ag_service_issue,
    ag_service_verify,
};
pub use status::AgStatus;

use std::panic::{AssertUnwindSafe, catch_unwind};

pub const AG_ABI_VERSION_1: u32 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn ag_abi_version() -> u32 {
    AG_ABI_VERSION_1
}

/// Returns the CogGate core package version as borrowed UTF-8 bytes.
///
/// The returned slice references immutable static storage while the CogGate
/// library remains loaded (normally the process lifetime). It is not
/// NUL-terminated and must not be freed.
#[unsafe(no_mangle)]
pub extern "C" fn ag_core_version() -> AgByteSlice {
    let version = env!("CARGO_PKG_VERSION").as_bytes();
    AgByteSlice {
        data: version.as_ptr(),
        len: version.len(),
    }
}

pub(crate) fn catch_status(operation: impl FnOnce() -> AgStatus) -> AgStatus {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(AgStatus::PanicCaught)
}

#[cfg(test)]
mod tests {
    use super::{AgStatus, catch_status};

    #[test]
    fn catch_status_converts_panics_to_status() {
        assert_eq!(
            catch_status(|| panic!("panic must not cross the ABI")),
            AgStatus::PanicCaught
        );
    }
}
