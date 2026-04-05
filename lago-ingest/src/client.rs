use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tracing::error;

use lago_core::EventEnvelope;

use crate::codec;
use crate::proto::{self, ingest_service_client::IngestServiceClient};

/// Client SDK for streaming events into Lago.
pub struct IngestClient {
    client: IngestServiceClient<Channel>,
}

impl IngestClient {
    /// Connect to a Lago ingest server.
    pub async fn connect(addr: impl Into<String>) -> Result<Self, tonic::transport::Error> {
        let client = IngestServiceClient::connect(addr.into()).await?;
        Ok(Self { client })
    }

    /// Create a new session.
    pub async fn create_session(
        &mut self,
        session_id: &str,
        name: &str,
    ) -> Result<proto::CreateSessionResponse, tonic::Status> {
        let req = proto::CreateSessionRequest {
            session_id: session_id.to_string(),
            config: Some(proto::SessionConfig {
                name: name.to_string(),
                model: String::new(),
                params: Default::default(),
            }),
        };
        let resp = self.client.create_session(req).await?;
        Ok(resp.into_inner())
    }

    /// Open a bidirectional ingest stream.
    /// Returns a sender for events and a receiver for acks.
    pub async fn open_stream(&mut self) -> Result<(IngestSender, IngestReceiver), tonic::Status> {
        let (tx, rx) = mpsc::channel::<proto::IngestRequest>(256);
        let stream = ReceiverStream::new(rx);
        let response = self.client.ingest(stream).await?;
        let mut in_stream = response.into_inner();

        let (ack_tx, ack_rx) = mpsc::channel::<proto::IngestResponse>(256);

        tokio::spawn(async move {
            while let Some(result) = in_stream.next().await {
                match result {
                    Ok(resp) => {
                        if ack_tx.send(resp).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("ingest stream error: {e}");
                        break;
                    }
                }
            }
        });

        Ok((IngestSender { tx }, IngestReceiver { rx: ack_rx }))
    }
}

/// Sender half of an ingest stream.
pub struct IngestSender {
    tx: mpsc::Sender<proto::IngestRequest>,
}

impl IngestSender {
    /// Send an event to the ingest stream.
    pub async fn send_event(
        &self,
        event: &EventEnvelope,
    ) -> Result<(), mpsc::error::SendError<proto::IngestRequest>> {
        let proto_event = codec::event_to_proto(event);
        let req = proto::IngestRequest {
            message: Some(proto::ingest_request::Message::Event(proto_event)),
        };
        self.tx.send(req).await
    }

    /// Send a heartbeat.
    pub async fn send_heartbeat(&self) -> Result<(), mpsc::error::SendError<proto::IngestRequest>> {
        let hb = codec::make_heartbeat();
        let req = proto::IngestRequest {
            message: Some(proto::ingest_request::Message::Heartbeat(hb)),
        };
        self.tx.send(req).await
    }
}

/// Receiver half of an ingest stream.
pub struct IngestReceiver {
    rx: mpsc::Receiver<proto::IngestResponse>,
}

impl IngestReceiver {
    /// Receive the next response (ack or heartbeat).
    pub async fn recv(&mut self) -> Option<proto::IngestResponse> {
        self.rx.recv().await
    }
}
