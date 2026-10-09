//! Per-thread allocation accounting, so concurrently running tests cannot
//! contaminate each other's retained and temporary totals. Test builds only.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

std::thread_local! {
    static USED: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

/// Install as a test binary's `#[global_allocator]`.
pub struct Counting;

// SAFETY: every call forwards the unchanged layout and pointer to the system
// allocator; the constant-initialized thread-local counters never allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwards the caller's layout unchanged.
        let value = unsafe { System.alloc(layout) };
        if !value.is_null() {
            let _ = USED.try_with(|used| {
                used.set(used.get() + layout.size());
                let _ = PEAK.try_with(|peak| peak.set(peak.get().max(used.get())));
            });
        }
        value
    }

    unsafe fn dealloc(&self, value: *mut u8, layout: Layout) {
        let _ = USED.try_with(|used| used.set(used.get().saturating_sub(layout.size())));
        // SAFETY: returns the original allocation with its original layout.
        unsafe { System.dealloc(value, layout) };
    }
}

/// Bytes currently allocated by this thread.
#[must_use]
pub fn used() -> usize {
    USED.with(Cell::get)
}

/// The highest usage since this thread last called `reset_peak`.
#[must_use]
pub fn peak() -> usize {
    PEAK.with(Cell::get)
}

/// Restart this thread's peak at its current usage.
pub fn reset_peak() {
    PEAK.with(|peak| peak.set(used()));
}
