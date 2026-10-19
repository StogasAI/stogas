//! Binary server embedding. This boundary owns no clock, socket or runtime.

use super::StogasBuffer;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};
use stogas_core::channel::{
    Error, Kind, MAX_RECORD_BYTES, MAX_RECORD_PLAINTEXT, ServerReader, ServerSession, ServerWriter,
    setup::{CLIENT_SETUP_BYTES, prepare_server_setup},
};

pub struct StogasChannelSession(ServerSession);
pub struct StogasChannelReader(ServerReader);
pub struct StogasChannelWriter(ServerWriter);

fn status(operation: impl FnOnce() -> Result<(), Error>) -> u32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => match error {
            Error::Record => 1,
            Error::Authentication => 2,
            Error::Limit => 3,
            Error::Closed => 4,
            Error::Truncated => 5,
            Error::Pending => 6,
            Error::Crypto => 7,
        },
        Err(_) => 255,
    }
}

const unsafe fn record<'a>(data: *mut u8, len: usize) -> Result<&'a mut [u8], Error> {
    if data.is_null() || len > MAX_RECORD_BYTES {
        return Err(Error::Record);
    }
    // SAFETY: this API requires exclusive access to the caller's live buffer.
    Ok(unsafe { slice::from_raw_parts_mut(data, len) })
}

/// # Safety
/// Hello contains `hello_len` readable bytes; boot hash contains 32. All outputs
/// are writable and disjoint, with 32 bytes each for ID and transcript. Environment
/// is 1 (production) or 2 (staging). Quote the returned transcript with that
/// environment and boot hash before publishing the response/session. Free both
/// successful outputs if quoting or publication fails. No input is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_channel_setup(
    environment: u8,
    idle_seconds: u32,
    hello: *const u8,
    hello_len: usize,
    boot_hash: *const u8,
    session: *mut *mut StogasChannelSession,
    id: *mut u8,
    transcript: *mut u8,
    response: *mut StogasBuffer,
) -> u32 {
    status(|| {
        if session.is_null() || id.is_null() || transcript.is_null() || response.is_null() {
            return Err(Error::Record);
        }
        // SAFETY: the caller provides writable, disjoint outputs.
        unsafe {
            session.write(ptr::null_mut());
            id.write_bytes(0, 32);
            transcript.write_bytes(0, 32);
            response.write(StogasBuffer::EMPTY);
        }
        if hello.is_null() || hello_len != CLIENT_SETUP_BYTES || boot_hash.is_null() {
            return Err(Error::Record);
        }
        let environment = match environment {
            1 => stogas_core::approvals::Environment::Production,
            #[cfg(feature = "staging")]
            2 => stogas_core::approvals::Environment::Staging,
            _ => return Err(Error::Record),
        };
        // SAFETY: non-null inputs have the readable sizes specified by the ABI.
        let hello = unsafe { slice::from_raw_parts(hello, hello_len) };
        let boot_hash = unsafe { &*boot_hash.cast::<[u8; 32]>() };
        let prepared = prepare_server_setup(environment, hello, idle_seconds, boot_hash)?;
        let owner = Box::new(StogasChannelSession(prepared.session));
        let prefix = StogasBuffer::owned(prepared.response_prefix);
        // SAFETY: all allocations are complete, outputs are disjoint and writable.
        // Only public bytes and an opaque secret owner cross this boundary.
        unsafe {
            id.copy_from_nonoverlapping(prepared.session_id.as_ptr(), 32);
            transcript.copy_from_nonoverlapping(prepared.transcript.as_ptr(), 32);
            response.write(prefix);
            session.write(Box::into_raw(owner));
        }
        Ok(())
    })
}

/// # Safety
/// Session is live and exclusively borrowed. Record storage is exclusive and
/// writable; every output is writable and disjoint from the record and inputs.
/// The plaintext offset borrows the input buffer. No pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_channel_accept(
    session: *mut StogasChannelSession,
    number: u64,
    data: *mut u8,
    len: usize,
    now_ms: u64,
    reader: *mut *mut StogasChannelReader,
    writer: *mut *mut StogasChannelWriter,
    offset: *mut usize,
    plaintext_len: *mut usize,
) -> u32 {
    status(|| {
        if reader.is_null() || writer.is_null() || offset.is_null() || plaintext_len.is_null() {
            return Err(Error::Record);
        }
        // SAFETY: all output pointers were checked and must be writable and disjoint.
        unsafe {
            reader.write(ptr::null_mut());
            writer.write(ptr::null_mut());
            offset.write(0);
            plaintext_len.write(0);
        }
        // SAFETY: caller supplies a live exclusive session and bounded record allocation.
        let session = unsafe { session.as_mut() }.ok_or(Error::Closed)?;
        let encoded = unsafe { record(data, len)? };
        let (incoming, outgoing, metadata) = session.0.accept_start(number, encoded, now_ms)?;
        // SAFETY: metadata is a subslice of this exact record allocation.
        let start = usize::try_from(unsafe { metadata.as_ptr().offset_from(data) })
            .map_err(|_| Error::Record)?;
        // SAFETY: checked writable outputs; newly allocated handles transfer ownership.
        unsafe {
            offset.write(start);
            plaintext_len.write(metadata.len());
            reader.write(Box::into_raw(Box::new(StogasChannelReader(incoming))));
            writer.write(Box::into_raw(Box::new(StogasChannelWriter(outgoing))));
        }
        Ok(())
    })
}

/// # Safety
/// Handle is live and exclusively borrowed for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_channel_session_expire(
    session: *mut StogasChannelSession,
    now_ms: u64,
) -> u32 {
    status(|| {
        // SAFETY: caller provides a live exclusively borrowed session.
        unsafe { session.as_mut() }
            .ok_or(Error::Closed)?
            .0
            .expire(now_ms);
        Ok(())
    })
}

/// # Safety
/// Reader and record are live and exclusively borrowed; scalar outputs are
/// writable and disjoint. Returned plaintext borrows the record buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_channel_open(
    reader: *mut StogasChannelReader,
    data: *mut u8,
    len: usize,
    kind: *mut u8,
    offset: *mut usize,
    plaintext_len: *mut usize,
) -> u32 {
    status(|| {
        if kind.is_null() || offset.is_null() || plaintext_len.is_null() {
            return Err(Error::Record);
        }
        // SAFETY: checked scalar outputs supplied by caller.
        unsafe {
            kind.write(0);
            offset.write(0);
            plaintext_len.write(0);
        }
        // SAFETY: caller supplies live, exclusively borrowed reader and record.
        let reader = unsafe { reader.as_mut() }.ok_or(Error::Closed)?;
        let encoded = match unsafe { record(data, len) } {
            Ok(encoded) => encoded,
            Err(error) => {
                reader.0.close();
                return Err(error);
            }
        };
        let (actual, plaintext) = reader.0.open(encoded)?;
        // SAFETY: plaintext is a subslice of this exact allocation.
        let start = usize::try_from(unsafe { plaintext.as_ptr().offset_from(data) })
            .map_err(|_| Error::Record)?;
        // SAFETY: checked scalar outputs supplied by caller.
        unsafe {
            kind.write(actual as u8);
            offset.write(start);
            plaintext_len.write(plaintext.len());
        }
        Ok(())
    })
}

/// # Safety
/// Reader is live and exclusively borrowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_channel_complete(reader: *mut StogasChannelReader) -> u32 {
    status(|| {
        // SAFETY: caller supplies an exclusive live reader.
        unsafe { reader.as_mut() }
            .ok_or(Error::Closed)?
            .0
            .complete()
    })
}

/// # Safety
/// Writer is live and exclusive. Input has `len` readable bytes and may be null
/// only when empty. Output is writable and disjoint. Release its owned buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_channel_seal(
    writer: *mut StogasChannelWriter,
    kind: u8,
    data: *const u8,
    len: usize,
    output: *mut StogasBuffer,
) -> u32 {
    status(|| {
        if output.is_null() {
            return Err(Error::Record);
        }
        // SAFETY: caller supplies writable output storage.
        unsafe {
            output.write(StogasBuffer::EMPTY);
        };
        // SAFETY: caller supplies a live exclusive writer.
        let writer = unsafe { writer.as_mut() }.ok_or(Error::Closed)?;
        if len > MAX_RECORD_PLAINTEXT || (data.is_null() && len != 0) {
            writer.0.close();
            return Err(Error::Limit);
        }
        let kind = match Kind::try_from(kind) {
            Ok(kind) => kind,
            Err(error) => {
                writer.0.close();
                return Err(error);
            }
        };
        let plaintext = if len == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(data, len) }
        };
        let bytes = StogasBuffer::owned(writer.0.seal(kind, plaintext)?);
        // SAFETY: checked output storage; ciphertext allocation transfers to caller.
        unsafe { output.write(bytes) };
        Ok(())
    })
}

/// # Safety
/// Handle is null or a live session, freed once after concurrent calls finish.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_channel_session_free(handle: *mut StogasChannelSession) {
    if !handle.is_null() {
        // SAFETY: exclusive ownership is returned exactly once.
        drop(unsafe { Box::from_raw(handle) });
    }
}

/// # Safety
/// Handle is null or a live reader, freed once after concurrent calls finish.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_channel_reader_free(handle: *mut StogasChannelReader) {
    if !handle.is_null() {
        // SAFETY: exclusive ownership is returned exactly once.
        drop(unsafe { Box::from_raw(handle) });
    }
}

/// # Safety
/// Handle is null or a live writer, freed once after concurrent calls finish.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_channel_writer_free(handle: *mut StogasChannelWriter) {
    if !handle.is_null() {
        // SAFETY: exclusive ownership is returned exactly once.
        drop(unsafe { Box::from_raw(handle) });
    }
}

#[cfg(test)]
mod tests;
