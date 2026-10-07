//! Allocation accounting belongs in a separate test process so concurrent unit
//! tests cannot contaminate the session's retained and temporary memory totals.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use stogas_verifier::channel::ratchet::{InitialKey, MAX_SKIPPED_KEYS, Peer};

struct Counting;
static USED: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
#[global_allocator]
static ALLOCATOR: Counting = Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwards the unchanged layout to the system allocator.
        let value = unsafe { System.alloc(layout) };
        if !value.is_null() {
            PEAK.fetch_max(
                USED.fetch_add(layout.size(), Relaxed) + layout.size(),
                Relaxed,
            );
        }
        value
    }
    unsafe fn dealloc(&self, value: *mut u8, layout: Layout) {
        USED.fetch_sub(layout.size(), Relaxed);
        // SAFETY: returns the original allocation with its original layout.
        unsafe { System.dealloc(value, layout) };
    }
}

#[test]
fn full_skipped_window_and_authenticated_replacement_fit_the_embedding_reservation() {
    for separate_turns in [false, true] {
        let initial = InitialKey::generate().unwrap();
        let mut sender = Peer::initiator(&[1; 32], initial.public_key()).unwrap();
        let baseline = USED.load(Relaxed);
        let mut receiver = Peer::responder(&[1; 32], initial);
        let mut largest_peak = 0;
        let mut largest_retained = 0;
        let rounds = if separate_turns {
            MAX_SKIPPED_KEYS + 2
        } else {
            4
        };
        for round in 0..rounds {
            let gap = if separate_turns { 1 } else { MAX_SKIPPED_KEYS };
            for _ in 0..gap {
                drop(sender.send().unwrap());
            }
            let packet = sender.send().unwrap();
            let before = USED.load(Relaxed);
            PEAK.store(before, Relaxed);
            receiver
                .receive(&packet.header, round as u64, |secret| {
                    assert_eq!(*secret, *packet.secret);
                    Ok(())
                })
                .unwrap();
            if separate_turns {
                let reply = receiver.send().unwrap();
                sender
                    .receive(&reply.header, round as u64, |secret| {
                        assert_eq!(*secret, *reply.secret);
                        Ok(())
                    })
                    .unwrap();
            }
            let retained = USED.load(Relaxed).saturating_sub(baseline);
            let peak = retained + PEAK.load(Relaxed).saturating_sub(USED.load(Relaxed));
            largest_peak = largest_peak.max(peak);
            largest_retained = largest_retained.max(retained);
        }
        // Includes fixed header ciphers from up to 256 separate retained turns,
        // as well as a staged replacement before old keys are evicted.
        assert!(largest_peak < 512 * 1024, "{largest_peak}");
        println!("separate_turns={separate_turns} retained={largest_retained} peak={largest_peak}");
    }
}
