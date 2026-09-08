use std::ptr;
use std::slice;

use agentgate_ffi::{AgByteSlice, AgOwnedBuffer, AgStatus, ag_buffer_free};

#[test]
fn null_nonzero_slice_is_rejected() {
    let malformed = AgByteSlice {
        data: ptr::null(),
        len: 1,
    };
    let empty = AgByteSlice {
        data: ptr::null(),
        len: 0,
    };

    assert_eq!(
        unsafe { malformed.copy_bytes() },
        Err(AgStatus::InvalidArgument)
    );
    assert_eq!(unsafe { empty.copy_bytes() }, Ok(Vec::new()));
}

#[test]
fn rust_owned_buffer_is_reset_by_free() {
    let mut buffer = AgOwnedBuffer::from_vec(b"abc".to_vec());

    assert!(!buffer.data.is_null());
    assert_eq!(buffer.len, 3);
    assert_eq!(
        unsafe { slice::from_raw_parts(buffer.data, buffer.len) },
        b"abc"
    );

    assert_eq!(unsafe { ag_buffer_free(&mut buffer) }, AgStatus::Ok);
    assert!(buffer.data.is_null());
    assert_eq!(buffer.len, 0);
    assert_eq!(buffer.capacity, 0);
}

#[test]
fn freeing_an_empty_buffer_is_idempotent() {
    let mut buffer = AgOwnedBuffer::empty();

    assert_eq!(unsafe { ag_buffer_free(&mut buffer) }, AgStatus::Ok);
    assert_eq!(unsafe { ag_buffer_free(&mut buffer) }, AgStatus::Ok);
    assert!(buffer.data.is_null());
    assert_eq!(buffer.len, 0);
    assert_eq!(buffer.capacity, 0);
}

#[test]
fn null_buffer_pointer_is_rejected() {
    assert_eq!(
        unsafe { ag_buffer_free(ptr::null_mut()) },
        AgStatus::InvalidArgument
    );
}

#[test]
fn malformed_empty_buffer_is_rejected() {
    let mut buffer = AgOwnedBuffer {
        data: ptr::null_mut(),
        len: 1,
        capacity: 1,
    };

    assert_eq!(
        unsafe { ag_buffer_free(&mut buffer) },
        AgStatus::InvalidArgument
    );
}
