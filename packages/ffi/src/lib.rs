#![deny(unsafe_op_in_unsafe_fn)]

mod memory;
mod status;

pub use memory::{AgByteSlice, AgHostBuffer, AgHostRelease, AgOwnedBuffer, ag_buffer_free};
pub use status::AgStatus;

use std::panic::{AssertUnwindSafe, catch_unwind};

pub const AG_ABI_VERSION_1: u32 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn ag_abi_version() -> u32 {
    AG_ABI_VERSION_1
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
