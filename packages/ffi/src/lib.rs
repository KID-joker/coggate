#![deny(unsafe_op_in_unsafe_fn)]

mod status;

pub use status::AgStatus;

pub const AG_ABI_VERSION_1: u32 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn ag_abi_version() -> u32 {
    AG_ABI_VERSION_1
}
