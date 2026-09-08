#[cfg(test)]
use std::cell::Cell;
use std::ffi::c_void;
use std::ptr;
use std::slice;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::{AgStatus, catch_status};

#[cfg(test)]
thread_local! {
    static REQUIRED_HOST_BUFFER_COPY_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_required_host_buffer_copy_count() {
    REQUIRED_HOST_BUFFER_COPY_COUNT.set(0);
}

#[cfg(test)]
pub(crate) fn required_host_buffer_copy_count() -> usize {
    REQUIRED_HOST_BUFFER_COPY_COUNT.get()
}

/// A borrowed byte slice passed across the C ABI.
///
/// A null `data` pointer is valid only when `len == 0`. A non-null pointer must
/// be readable for `len` bytes. When Rust passes this structure to a host
/// callback, the bytes are borrowed only for that synchronous callback
/// invocation and the host must not retain the pointer.
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
    /// When `data` is non-null, it must be valid to read `len` bytes and must
    /// not be concurrently mutated for the duration of this call.
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

/// A Rust-owned byte buffer returned through the ABI.
///
/// Values produced by [`AgOwnedBuffer::from_vec`] transfer ownership to the
/// caller until passed exactly once to [`ag_buffer_free`].
#[repr(C)]
pub struct AgOwnedBuffer {
    pub data: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

impl AgOwnedBuffer {
    pub const fn empty() -> Self {
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

/// Releases a host-owned callback output.
///
/// Rust invokes this function exactly once only for an output transferred by a
/// callback that returned its `Ok` status. It receives the exact `release_data`,
/// `data`, and `len` tuple supplied by the host. The function must accept
/// `len == 0`, must not unwind, throw, or longjmp across the ABI boundary, and
/// must not reenter the same service handle.
pub type AgHostRelease = unsafe extern "C" fn(*mut c_void, *mut u8, usize);

/// A host-owned callback output buffer.
///
/// Ownership transfers to Rust only when the producing callback returns its
/// `Ok` status. On every other status the buffer remains host-owned and Rust
/// neither reads nor releases it. After transfer, a null pointer is permitted
/// only with `len == 0` for an output documented as optional. Every non-null
/// `data` pointer must be readable for `len` bytes and must have a non-null
/// [`AgHostRelease`], including when `len == 0`. Rust releases a transferred
/// non-null buffer exactly once with the unchanged tuple after its last read.
#[repr(C)]
pub struct AgHostBuffer {
    pub data: *mut u8,
    pub len: usize,
    pub release_data: *mut c_void,
    pub release: Option<AgHostRelease>,
}

impl AgHostBuffer {
    pub const fn empty() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
            release_data: ptr::null_mut(),
            release: None,
        }
    }
}

pub(crate) struct HostBufferGuard {
    buffer: AgHostBuffer,
    protocol_violation: Arc<AtomicBool>,
}

impl HostBufferGuard {
    pub(crate) fn take(buffer: AgHostBuffer, protocol_violation: Arc<AtomicBool>) -> Self {
        Self {
            buffer,
            protocol_violation,
        }
    }

    pub(crate) fn copy_required(&self) -> Result<Vec<u8>, ()> {
        #[cfg(test)]
        REQUIRED_HOST_BUFFER_COPY_COUNT.with(|count| count.set(count.get() + 1));

        let bytes = self.copy_bytes()?;
        if bytes.is_empty() {
            self.mark_violation();
            return Err(());
        }
        Ok(bytes)
    }

    pub(crate) fn copy_optional(&self) -> Result<Vec<u8>, ()> {
        self.copy_bytes()
    }

    fn copy_bytes(&self) -> Result<Vec<u8>, ()> {
        if self.buffer.data.is_null() {
            if self.buffer.len == 0 {
                return Ok(Vec::new());
            }
            self.mark_violation();
            return Err(());
        }
        if self.buffer.release.is_none() {
            self.mark_violation();
            return Err(());
        }
        Ok(unsafe { slice::from_raw_parts(self.buffer.data, self.buffer.len) }.to_vec())
    }

    pub(crate) fn mark_violation(&self) {
        self.protocol_violation.store(true, Ordering::SeqCst);
    }
}

impl Drop for HostBufferGuard {
    fn drop(&mut self) {
        if (self.buffer.data.is_null() && self.buffer.len == 0) || self.buffer.release.is_none() {
            return;
        }
        if let Some(release) = self.buffer.release.take() {
            unsafe { release(self.buffer.release_data, self.buffer.data, self.buffer.len) };
        }
    }
}

/// Releases a buffer returned by Agentgate and resets it to the empty state.
///
/// # Safety
///
/// `buffer` must either be null or point to a valid, writable
/// [`AgOwnedBuffer`], and the structure may not be concurrently accessed for
/// the duration of this call.
///
/// When `data` is non-null and `len <= capacity`, including when `len == 0` and
/// `capacity > 0`, the complete `(data, len, capacity)` triple must be exact and
/// unchanged from [`AgOwnedBuffer::from_vec`]. The allocation must remain
/// uniquely owned by that buffer, must not have been previously freed or
/// transferred, and may not be concurrently accessed during the call.
///
/// A null `data` pointer with nonzero metadata is accepted as a malformed input
/// and rejected without inspecting an allocation. When `len > capacity`,
/// `data` may contain any pointer value; that combination is rejected before
/// `data` is dereferenced or passed to [`Vec::from_raw_parts`]. The provenance
/// and ownership requirements above therefore do not apply to either malformed
/// case.
///
/// Runtime validation can reject null pointers and `len > capacity`, but it
/// cannot establish allocation provenance, unique ownership, unchanged
/// metadata, or the absence of concurrent access for a reconstructable buffer.
/// Violating those requirements results in undefined behavior.
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
