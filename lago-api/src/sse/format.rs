use lago_core::EventEnvelope;

/// A single frame to be sent over the SSE connection.
pub struct SseFrame {
    /// Optional event type (the `event:` field in SSE).
    pub event: Option<String>,
    /// The `data:` field in SSE (JSON-encoded string, typically).
    pub data: String,
    /// Optional event ID (the `id:` field in SSE). Used for reconnection.
    pub id: Option<String>,
}

/// Trait for formatting `EventEnvelope`s into SSE frames for a given wire
/// protocol (OpenAI, Anthropic, Vercel AI SDK, or native Lago format).
pub trait SseFormat: Send + Sync {
    /// Convert an event envelope into zero or more SSE frames.
    ///
    /// Returning an empty vec means the event is filtered out (not relevant
    /// to this format).
    fn format(&self, event: &EventEnvelope) -> Vec<SseFrame>;

    /// An optional "done" frame to send when the stream terminates.
    fn done_frame(&self) -> Option<SseFrame>;

    /// Extra HTTP headers to include in the SSE response (e.g. Vercel's
    /// `x-vercel-ai-data-stream` header).
    fn extra_headers(&self) -> Vec<(String, String)>;

    /// Human-readable name of this format (for logging).
    fn name(&self) -> &str;
}
