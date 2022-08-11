use std::ffi::c_void;

/// An error that occurred while attempting to read from a stream.
///
/// # Safety
///
/// Foreign code is not allowed to make any assumptions about the interior
/// layout of this type.
pub struct StreamReadError {
    pub(crate) _inner: (),
}

/// Status code returned by a stream handler.
///
/// Note that if ContinueOrdered is returned after a previous call returned
/// ContinueUnordered, it will be ignored, and data will remain unordered.
#[repr(u16)]
pub enum HandleChunkResult {
    CleanupNow = 0,
    ContinueOrdered = 1,
    ContinueUnordered = 2,
}

impl HandleChunkResult {
    pub(crate) fn from_u16(value: u16) -> Option<HandleChunkResult> {
        match value {
            0 => Some(HandleChunkResult::CleanupNow),
            1 => Some(HandleChunkResult::ContinueOrdered),
            2 => Some(HandleChunkResult::ContinueUnordered),
            _ => None,
        }
    }
}

/// This v-table provides the interface for a FFI client to define how
/// it handles messages.
#[repr(C)]
pub struct StreamHandlerVTable {
    /// User-specified object pointer.
    ///
    /// # Safety
    ///
    /// This function pointer must be safe to send to arbitrary threads.
    pub obj: *mut c_void,

    /// Maximum size of the memory buffer passed to [`handle_chunk`].
    pub max_chunk_size: usize,

    /// If this value is non-zero, the stream will always operate in unordered
    /// mode, including the first chunk.  If the handler returns
    /// ContinueOrdered, it will be ignored.
    pub always_unordered: usize,

    /// This function is called when there is no more data available in
    /// the stream.  If the stream finished naturally, the error will be null.
    ///
    /// This function is responsible for cleaning up any resources associated
    /// with the StreamHandler, it will not be used again.
    ///
    /// # Safety
    ///
    /// This function pointer must not be null.
    ///
    /// This function must tolerate being called from an arbitrary thread.
    ///
    /// The `error` pointer is valid only for the duration of this function call.
    pub finish: extern "C" fn(
        obj: *mut StreamHandlerVTable,
        error: *const StreamReadError,
    ),

    /// This function is called by the library when fresh data is available
    /// to be processed by the stream handler.
    ///
    /// The return value should be a member of the [`HandleChunkResult`] enum.
    ///
    /// Offset is the offset of the chunk of data within the stream.  As long
    /// as the stream handler returns `ContinueOrdered`, these offsets will
    /// indicate data immediately following the previous chunk.
    ///
    /// # Safety
    ///
    /// This function pointer must not be null.
    ///
    /// This function must tolerate being called from an arbitrary thread.
    ///
    /// The `msg` pointer is valid only for the duration of this function call.
    /// Implementations should make a copy of the pointed-to data if they need
    /// access after the function has returned.
    pub handle_chunk: extern "C" fn(
        obj: *mut c_void,
        offset: u64,
        data: *const u8,
        data_len: usize,
    ) -> u16,
}

unsafe impl Send for StreamHandlerVTable {}
unsafe impl Sync for StreamHandlerVTable {}

pub struct StreamHandler {
    vtable: *mut StreamHandlerVTable,
}

unsafe impl Send for StreamHandler {}
unsafe impl Sync for StreamHandler {}

impl StreamHandler {
    pub fn new(vtable: *mut StreamHandlerVTable) -> Self {
        assert!(!vtable.is_null());
        Self { vtable }
    }

    pub fn max_chunk_size(&self) -> usize {
        unsafe { (*self.vtable).max_chunk_size }
    }

    pub fn ordered_initial(&self) -> bool {
        unsafe { (*self.vtable).always_unordered == 0 }
    }

    pub fn handle_chunk(&self, offset: u64, data: &[u8]) -> HandleChunkResult {
        let result = unsafe {
            ((*self.vtable).handle_chunk)(
                (*self.vtable).obj,
                offset,
                data.as_ptr(),
                data.len(),
            )
        };
        HandleChunkResult::from_u16(result)
            .unwrap_or(HandleChunkResult::CleanupNow)
    }

    fn private_finish(&self, error: Option<&StreamReadError>) {
        unsafe {
            let finish = (*self.vtable).finish;
            let err_ptr =
                error.map(|r| r as *const _).unwrap_or(std::ptr::null());
            finish(self.vtable, err_ptr);
        }
    }

    pub fn finish(self, error: Option<&StreamReadError>) {
        self.private_finish(error);
        std::mem::forget(self);
    }
}

impl Drop for StreamHandler {
    fn drop(&mut self) {
        self.private_finish(None);
    }
}

/// This v-table provides the interface for a FFI client to define how
/// it sends messages.
#[repr(C)]
pub struct StreamWriterVTable {
    /// User-specified object pointer.
    pub obj: *mut c_void,

    /// This size of the buffer passed to [`write_chunk`].
    pub chunk_size: usize,

    /// This function is called after write_data returns 0, or an error occurs
    /// while writing to the stream.  To avoid a memory leak, `cleanup` should
    /// de-allocated all the resources associated with this v-table.
    ///
    /// # Safety
    ///
    /// This function pointer must not be null.
    ///
    /// This function must tolerate being called from an arbitrary thread.
    pub cleanup: extern "C" fn(obj: *mut StreamWriterVTable),

    /// This function is called to populate a buffer with data to be written to
    /// the stream.  The return value should be the number of bytes written to
    /// the buffer. If the return value is 0, cleanup will be called.
    ///
    /// # Safety
    ///
    /// This function pointer must not be null.
    ///
    /// The `data` pointer points to a buffer of size `chunk_size`, this
    /// function must not write more than `chunk_size` bytes to the buffer.
    ///
    /// The `data` pointer is valid only for the duration of this function
    /// call.  Implementors should make a copy of the pointed-to data if they
    /// need access after the function has returned.
    ///
    /// This function must tolerate being called from an arbitrary thread.
    pub write_data: extern "C" fn(obj: *mut c_void, data: *mut u8) -> usize,
}

unsafe impl Send for StreamWriterVTable {}
unsafe impl Sync for StreamWriterVTable {}

pub struct StreamWriter {
    vtable: *mut StreamWriterVTable,
}

unsafe impl Send for StreamWriter {}
unsafe impl Sync for StreamWriter {}

impl StreamWriter {
    pub fn new(vtable: *mut StreamWriterVTable) -> Self {
        assert!(!vtable.is_null());
        Self { vtable }
    }

    pub fn chunk_size(&self) -> usize {
        unsafe { (*self.vtable).chunk_size }
    }

    pub fn get_data_to_write(&mut self, buf: &mut [u8]) -> usize {
        let written = unsafe {
            assert!(buf.len() >= (*self.vtable).chunk_size);
            ((*self.vtable).write_data)((*self.vtable).obj, buf.as_mut_ptr())
        };
        assert!(written <= buf.len());
        written
    }
}

impl Drop for StreamWriter {
    fn drop(&mut self) {
        unsafe {
            let cleanup = (*self.vtable).cleanup;
            cleanup(self.vtable);
        }
    }
}
