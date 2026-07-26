// Cooperative pause/cancel signaling for long-running vault operations.
//
// Rust has no built-in way to interrupt a thread mid-flight, so pause/cancel
// here is cooperative: the operation's own loop calls `checkpoint()` at each
// natural boundary (once per chunk / once per fragment) and `checkpoint()`
// blocks (if paused) or bails out (if cancelled). There is no true mid-call
// interruption for the small-file path's single in-memory encrypt/decrypt —
// pause/cancel there only takes effect between fragment writes/reads in the
// calling command, not inside fragmenter.rs itself.

use crate::core::error::{CoreError, CoreResult};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

const RUNNING: u8 = 0;
const PAUSED: u8 = 1;
const CANCELLED: u8 = 2;

const POLL_INTERVAL: Duration = Duration::from_millis(100);

pub struct OpControl {
    state: AtomicU8,
}

impl OpControl {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { state: AtomicU8::new(RUNNING) })
    }

    pub fn pause(&self) {
        // Don't clobber a cancellation with a late pause request.
        let _ = self.state.compare_exchange(
            RUNNING, PAUSED, Ordering::SeqCst, Ordering::SeqCst,
        );
    }

    pub fn resume(&self) {
        let _ = self.state.compare_exchange(
            PAUSED, RUNNING, Ordering::SeqCst, Ordering::SeqCst,
        );
    }

    pub fn cancel(&self) {
        self.state.store(CANCELLED, Ordering::SeqCst);
    }

    /// Call once per loop iteration (per chunk / per fragment). Blocks while
    /// paused; returns `Err(CoreError::Cancelled)` once cancelled, including
    /// while blocked in a pause (so Cancel always wins and unblocks a paused op).
    pub fn checkpoint(&self) -> CoreResult<()> {
        loop {
            match self.state.load(Ordering::SeqCst) {
                CANCELLED => return Err(CoreError::Cancelled),
                PAUSED => std::thread::sleep(POLL_INTERVAL),
                _ => return Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_checkpoint_ok_when_running() {
        let ctl = OpControl::new();
        assert!(ctl.checkpoint().is_ok());
    }

    #[test]
    fn test_checkpoint_err_when_cancelled() {
        let ctl = OpControl::new();
        ctl.cancel();
        assert!(matches!(ctl.checkpoint(), Err(CoreError::Cancelled)));
    }

    #[test]
    fn test_pause_blocks_until_resumed() {
        let ctl = OpControl::new();
        ctl.pause();
        let ctl2 = ctl.clone();
        let handle = std::thread::spawn(move || ctl2.checkpoint());
        std::thread::sleep(Duration::from_millis(250));
        assert!(!handle.is_finished());
        ctl.resume();
        assert!(handle.join().unwrap().is_ok());
    }

    #[test]
    fn test_cancel_unblocks_a_paused_checkpoint() {
        let ctl = OpControl::new();
        ctl.pause();
        let ctl2 = ctl.clone();
        let handle = std::thread::spawn(move || ctl2.checkpoint());
        std::thread::sleep(Duration::from_millis(150));
        ctl.cancel();
        assert!(matches!(handle.join().unwrap(), Err(CoreError::Cancelled)));
    }

    #[test]
    fn test_resume_without_pause_is_noop() {
        let ctl = OpControl::new();
        ctl.resume();
        assert!(ctl.checkpoint().is_ok());
    }

    #[test]
    fn test_pause_after_cancel_does_not_resurrect() {
        let ctl = OpControl::new();
        ctl.cancel();
        ctl.pause();
        assert!(matches!(ctl.checkpoint(), Err(CoreError::Cancelled)));
    }
}
