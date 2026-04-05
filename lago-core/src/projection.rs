use crate::error::LagoResult;
use crate::event::EventEnvelope;

/// A projection consumes events and builds derived state.
pub trait Projection: Send + Sync {
    /// Process a single event.
    fn on_event(&mut self, event: &EventEnvelope) -> LagoResult<()>;

    /// Called after replaying all existing events, before live tailing begins.
    fn on_replay_complete(&mut self) -> LagoResult<()> {
        Ok(())
    }

    /// Name of this projection (for logging/debugging).
    fn name(&self) -> &str;
}
