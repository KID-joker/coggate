use std::ffi::c_void;
use std::ptr;
use std::slice;

use crate::{AgStatus, catch_status};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AgByteSlice {
    pub data: *const u8,
    pub len: usize,
}

impl AgByteSlice {
    /// Copies the bytes referenced by this ABI slice.
    ///
    /// # Safety
    ///
    /// When `data` is non-null, it must be valid to read `len` bytes.
    pub unsafe fn copy_bytes(self) -> Result<Vec<u8>, AgStatus> {
        if self.data.is_null() {
            return if self.len == 0 {
                Ok(Vec::new())
            } else {
                Err(AgStatus::InvalidArgument)
            };
        }

        Ok(unsafe { slice::from_raw_parts(self.data, self.len) }.to_vec())
    }
}

#[repr(C)]
pub struct AgOwnedBuffer {
    pub data: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

impl AgOwnedBuffer {
    pub fn empty() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    }

    pub fn from_vec(mut bytes: Vec<u8>) -> Self {
        let buffer = Self {
            data: bytes.as_mut_ptr(),
            len: bytes.len(),
            capacity: bytes.capacity(),
        };
        std::mem::forget(bytes);
        buffer
    }
}

pub type AgHostRelease = unsafe extern "C" fn(*mut c_void, *mut u8, usize);

#[repr(C)]
pub struct AgHostBuffer {
    pub data: *mut u8,
    pub len: usize,
    pub release_data: *mut c_void,
    pub release: Option<AgHostRelease>,
}

impl AgHostBuffer {
    pub fn empty() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
            release_data: ptr::null_mut(),
            release: None,
        }
    }
}

/// Releases a buffer returned by Agentgate and resets it to the empty state.
///
/// # Safety
///
/// `buffer` must either be null or point to a writable `AgOwnedBuffer`. A
/// non-empty buffer must have been created by [`AgOwnedBuffer::from_vec`] and
/// must not have been freed previously.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ag_buffer_free(buffer: *mut AgOwnedBuffer) -> AgStatus {
    catch_status(|| unsafe { free_buffer(buffer) })
}

unsafe fn free_buffer(buffer: *mut AgOwnedBuffer) -> AgStatus {
    let Some(buffer) = (unsafe { buffer.as_mut() }) else {
        return AgStatus::InvalidArgument;
    };

    if buffer.data.is_null() {
        return if buffer.len == 0 && buffer.capacity == 0 {
            AgStatus::Ok
        } else {
            AgStatus::InvalidArgument
        };
    }

    if buffer.len > buffer.capacity {
        return AgStatus::InvalidArgument;
    }

    let bytes = unsafe { Vec::from_raw_parts(buffer.data, buffer.len, buffer.capacity) };
    *buffer = AgOwnedBuffer::empty();
    drop(bytes);
    AgStatus::Ok
}
