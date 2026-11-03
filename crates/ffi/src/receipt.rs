//! The content digests that a receipt commits to, for the gateway that signs them and the
//! clients that check them. Status: 0 success, 1 not one JSON object or event that a receipt
//! can commit to, 3 an integer that a double cannot hold exactly, 255 panic (discard the owner).

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    slice,
};
use stogas_core::receipt::{
    self, CanonicalError, ContentDigest, StreamContent, canonical::DIGEST_BYTES,
};

/// The largest request body that the gateway admits.
const MAX_REQUEST_BYTES: usize = 128 * 1024 * 1024;

/// A stream's events, read into the response that its receipt signs.
pub struct StogasStreamContent(Option<StreamContent>);

fn status(operation: impl FnOnce() -> Result<(), u32>) -> u32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => 0,
        Ok(Err(code)) => code,
        Err(_) => 255,
    }
}

const fn code(error: &receipt::Error) -> u32 {
    match error {
        receipt::Error::Canonical(CanonicalError::Integer) => 3,
        _ => 1,
    }
}

/// # Safety
/// Non-null pointers address `len` readable bytes for the call.
const unsafe fn input<'a>(data: *const u8, len: usize, maximum: usize) -> Result<&'a [u8], u32> {
    if len > maximum || (data.is_null() && len > 0) {
        return Err(1);
    }
    if len == 0 {
        return Ok(&[]);
    }
    // SAFETY: the caller supplies a readable allocation of this length.
    Ok(unsafe { slice::from_raw_parts(data, len) })
}

/// # Safety
/// The output is null or addresses 64 writable bytes.
unsafe fn write(output: *mut u8, digest: &ContentDigest) -> Result<(), u32> {
    // SAFETY: the caller supplies 64 writable bytes.
    let output = unsafe { output.cast::<[u8; DIGEST_BYTES]>().as_mut() }.ok_or(1_u32)?;
    *output = *digest;
    Ok(())
}

/// Write the 64-byte digest of a request body as its receipt commits it: the RFC 8785 form of
/// the body without its top-level `encryption_keys`.
///
/// # Safety
/// The body addresses its readable length; the digest addresses 64 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_receipt_request_digest(
    body: *const u8,
    body_len: usize,
    digest: *mut u8,
) -> u32 {
    status(|| {
        // SAFETY: the caller supplies a readable body and a writable digest.
        unsafe {
            let body = input(body, body_len, MAX_REQUEST_BYTES)?;
            let value = receipt::request_digest(body)
                .map_err(|error| code(&receipt::Error::Canonical(error)))?;
            write(digest, &value)
        }
    })
}

/// Write the 64-byte digest of a buffered response body as its receipt commits it: the RFC 8785
/// form of the body without its top-level `stogas` bag.
///
/// # Safety
/// The body addresses its readable length; the digest addresses 64 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_receipt_response_digest(
    body: *const u8,
    body_len: usize,
    digest: *mut u8,
) -> u32 {
    status(|| {
        // SAFETY: the caller supplies a readable body and a writable digest.
        unsafe {
            let body = input(body, body_len, receipt::MAX_BUFFERED_BYTES)?;
            let value = receipt::response_digest(body)
                .map_err(|error| code(&receipt::Error::Canonical(error)))?;
            write(digest, &value)
        }
    })
}

/// Start reading a stream's events. Free the reader with `stogas_stream_content_free`.
#[unsafe(no_mangle)]
pub extern "C" fn stogas_stream_content_new() -> *mut StogasStreamContent {
    Box::into_raw(Box::new(StogasStreamContent(
        Some(StreamContent::default()),
    )))
}

/// Read one complete event as it was sent, with or without its closing blank line.
///
/// A block of comments, such as a keepalive or the receipt, changes nothing. After a failure the
/// reader rejects every later call.
///
/// # Safety
/// The reader is live and used by one thread at a time; the event addresses its readable
/// length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_stream_content_push(
    content: *mut StogasStreamContent,
    event: *const u8,
    event_len: usize,
) -> u32 {
    status(|| {
        // SAFETY: the caller supplies a live reader and a readable event.
        let (content, event) = unsafe {
            (
                content.as_mut().ok_or(1_u32)?,
                input(event, event_len, receipt::MAX_BUFFERED_BYTES)?,
            )
        };
        let reader = content.0.as_mut().ok_or(1_u32)?;
        reader.push(event).map_err(|error| {
            content.0 = None;
            code(&error)
        })
    })
}

/// Write the 64-byte digest of the response that the complete stream carries. The reader then
/// rejects every later call.
///
/// # Safety
/// The reader is live and used by one thread at a time; the digest addresses 64 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_stream_content_digest(
    content: *mut StogasStreamContent,
    digest: *mut u8,
) -> u32 {
    status(|| {
        // SAFETY: the caller supplies a live reader and a writable digest.
        let content = unsafe { content.as_mut() }.ok_or(1_u32)?;
        let value = content
            .0
            .take()
            .ok_or(1_u32)?
            .digest()
            .map_err(|error| code(&error))?;
        // SAFETY: the caller supplies 64 writable bytes.
        unsafe { write(digest, &value) }
    })
}

/// # Safety
/// The reader is null or live, and is released exactly once after its last use.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_stream_content_free(content: *mut StogasStreamContent) {
    if !content.is_null() {
        // SAFETY: the pointer came from `stogas_stream_content_new` and is released once.
        drop(unsafe { Box::from_raw(content) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    fn request(body: &[u8]) -> (u32, [u8; DIGEST_BYTES]) {
        let mut digest = [0; DIGEST_BYTES];
        // SAFETY: both buffers are live for the call.
        let status = unsafe {
            stogas_receipt_request_digest(body.as_ptr(), body.len(), digest.as_mut_ptr())
        };
        (status, digest)
    }

    #[test]
    fn digests_report_why_content_cannot_be_committed() {
        let (status, digest) = request(br#"{"b":1,"encryption_keys":{"k":"v"},"a":"x"}"#);
        assert_eq!(status, 0);
        assert_eq!(
            digest,
            receipt::request_digest(br#"{"a":"x","b":1}"#).unwrap()
        );
        assert_eq!(request(br#"{"seed":9007199254740993}"#).0, 3);
        assert_eq!(request(b"[]").0, 1);
        assert_eq!(request(br#"{"a":1,"a":2}"#).0, 1);
        // SAFETY: a null body with a length and a null output are rejected before any access.
        unsafe {
            assert_eq!(
                stogas_receipt_request_digest(ptr::null(), 1, [0; 64].as_mut_ptr()),
                1
            );
            assert_eq!(
                stogas_receipt_request_digest(b"{}".as_ptr(), 2, ptr::null_mut()),
                1
            );
        }
        let mut digest = [0; DIGEST_BYTES];
        let body = br#"{"id":"r","stogas":{"receipt":{}}}"#;
        // SAFETY: both buffers are live for the call.
        let status = unsafe {
            stogas_receipt_response_digest(body.as_ptr(), body.len(), digest.as_mut_ptr())
        };
        assert_eq!(status, 0);
        assert_eq!(digest, receipt::response_digest(br#"{"id":"r"}"#).unwrap());
    }

    #[test]
    fn a_stream_reader_digests_its_response_once_and_stops_at_its_first_error() {
        let events: [&[u8]; 2] = [
            b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[]}\n\n",
            b"data: [DONE]\n\n",
        ];
        let expected = receipt::canonical::digest(
            &serde_json::json!({"object": "chat.completion", "choices": []}),
        )
        .unwrap();
        let content = stogas_stream_content_new();
        let mut digest = [0; DIGEST_BYTES];
        // SAFETY: the reader is live until it is freed, and each buffer for its call.
        unsafe {
            for event in events {
                assert_eq!(
                    stogas_stream_content_push(content, event.as_ptr(), event.len()),
                    0
                );
            }
            assert_eq!(
                stogas_stream_content_digest(content, digest.as_mut_ptr()),
                0
            );
            assert_eq!(digest, expected);
            assert_eq!(
                stogas_stream_content_digest(content, digest.as_mut_ptr()),
                1
            );
            assert_eq!(
                stogas_stream_content_push(content, events[1].as_ptr(), events[1].len()),
                1
            );
            stogas_stream_content_free(content);
        }
        let content = stogas_stream_content_new();
        let integer =
            b"data: {\"object\":\"chat.completion.chunk\",\"created\":9007199254740993}\n\n";
        // SAFETY: the reader is live until it is freed, and each buffer for its call.
        unsafe {
            assert_eq!(
                stogas_stream_content_push(content, integer.as_ptr(), integer.len()),
                3
            );
            assert_eq!(
                stogas_stream_content_push(content, events[0].as_ptr(), events[0].len()),
                1
            );
            assert_eq!(
                stogas_stream_content_digest(content, digest.as_mut_ptr()),
                1
            );
            stogas_stream_content_free(content);
            stogas_stream_content_free(ptr::null_mut());
        }
    }
}
