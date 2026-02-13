use std::sync::Arc;

use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{error, info, warn};

use lago_core::{Journal, Session, SessionConfig, SessionId, event::EventEnvelope as CoreEvent};

use crate::codec;
use crate::proto::{self, ingest_service_server::IngestService};

/// Maximum number of pending WAL entries before backpressure.
const _MAX_PENDING: u64 = 10_000;

pub struct IngestServer<J: Journal> {
    journal: Arc<J>,
}

impl<J: Journal> IngestServer<J> {
    pub fn new(journal: Arc<J>) -> Self {
        Self { journal }
    }
}

#[tonic::async_trait]
impl<J: Journal + 'static> IngestService for IngestServer<J> {
    type IngestStream = ReceiverStream<Result<proto::IngestResponse, Status>>;

    async fn ingest(
        &self,
        request: Request<Streaming<proto::IngestRequest>>,
    ) -> Result<Response<Self::IngestStream>, Status> {
        let journal = Arc::clone(&self.journal);
        let mut in_stream = request.into_inner();
        let (tx, rx) = mpsc::channel(256);

        tokio::spawn(async move {
            while let Some(result) = in_stream.next().await {
                match result {
                    Ok(req) => {
                        let Some(message) = req.message else {
                            continue;
                        };

                        match message {
                            proto::ingest_request::Message::Event(proto_event) => {
                                let event_id = proto_event.event_id.clone();
                                match codec::event_from_proto(proto_event) {
                                    Ok(event) => match journal.append(event).await {
                                        Ok(seq) => {
                                            let ack = codec::make_ack(&event_id, seq, true, None);
                                            let resp = proto::IngestResponse {
                                                message: Some(
                                                    proto::ingest_response::Message::Ack(ack),
                                                ),
                                            };
                                            if tx.send(Ok(resp)).await.is_err() {
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            error!("journal append error: {e}");
                                            let ack = codec::make_ack(
                                                &event_id,
                                                0,
                                                false,
                                                Some(e.to_string()),
                                            );
                                            let resp = proto::IngestResponse {
                                                message: Some(
                                                    proto::ingest_response::Message::Ack(ack),
                                                ),
                                            };
                                            let _ = tx.send(Ok(resp)).await;
                                        }
                                    },
                                    Err(e) => {
                                        warn!("proto decode error: {e}");
                                        let ack = codec::make_ack(
                                            &event_id,
                                            0,
                                            false,
                                            Some(format!("decode error: {e}")),
                                        );
                                        let resp = proto::IngestResponse {
                                            message: Some(proto::ingest_response::Message::Ack(
                                                ack,
                                            )),
                                        };
                                        let _ = tx.send(Ok(resp)).await;
                                    }
                                }
                            }
                            proto::ingest_request::Message::Heartbeat(_) => {
                                let hb = codec::make_heartbeat();
                                let resp = proto::IngestResponse {
                                    message: Some(proto::ingest_response::Message::Heartbeat(hb)),
                                };
                                let _ = tx.send(Ok(resp)).await;
                            }
                        }
                    }
                    Err(e) => {
                        error!("stream error: {e}");
                        break;
                    }
                }
            }
            info!("ingest stream closed");
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn create_session(
        &self,
        request: Request<proto::CreateSessionRequest>,
    ) -> Result<Response<proto::CreateSessionResponse>, Status> {
        let req = request.into_inner();
        let session_id = SessionId::from_string(&req.session_id);
        let config = req.config.unwrap_or_default();

        let session = Session {
            session_id: session_id.clone(),
            config: SessionConfig {
                name: config.name.clone(),
                model: config.model.clone(),
                params: config.params,
            },
            created_at: CoreEvent::now_micros(),
            branches: vec![],
        };

        self.journal
            .put_session(session)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::CreateSessionResponse {
            session_id: req.session_id,
            created: true,
        }))
    }

    async fn get_session(
        &self,
        request: Request<proto::GetSessionRequest>,
    ) -> Result<Response<proto::GetSessionResponse>, Status> {
        let req = request.into_inner();
        let session_id = SessionId::from_string(&req.session_id);

        let session = self
            .journal
            .get_session(&session_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("session not found"))?;

        Ok(Response::new(proto::GetSessionResponse {
            session_id: req.session_id,
            config: Some(proto::SessionConfig {
                name: session.config.name,
                model: session.config.model,
                params: session.config.params,
            }),
            event_count: 0,
        }))
    }
}
