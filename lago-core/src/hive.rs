//! Hive task aggregate — reconstructs hive state from events.

use crate::event::EventEnvelope;
use crate::id::SessionId;
use aios_protocol::HiveTaskId;

/// Aggregate view of a hive collaborative task, built from events.
#[derive(Debug, Clone)]
pub struct HiveTask {
    pub hive_task_id: HiveTaskId,
    pub objective: String,
    pub agent_sessions: Vec<SessionId>,
    pub current_generation: u32,
    pub best_score: Option<f32>,
    pub best_session_id: Option<SessionId>,
    pub completed: bool,
}

impl HiveTask {
    /// Reconstruct a HiveTask aggregate from a sequence of events.
    ///
    /// Scans for hive-related `EventKind` variants and builds the aggregate.
    /// Returns `None` if no `HiveTaskCreated` event is found.
    pub fn from_events(events: &[EventEnvelope]) -> Option<Self> {
        let mut task: Option<Self> = None;

        for envelope in events {
            match &envelope.payload {
                aios_protocol::EventKind::HiveTaskCreated {
                    hive_task_id,
                    objective,
                    ..
                } => {
                    task = Some(Self {
                        hive_task_id: hive_task_id.clone(),
                        objective: objective.clone(),
                        agent_sessions: Vec::new(),
                        current_generation: 0,
                        best_score: None,
                        best_session_id: None,
                        completed: false,
                    });
                }
                aios_protocol::EventKind::HiveArtifactShared {
                    source_session_id,
                    score,
                    ..
                } => {
                    if let Some(ref mut t) = task {
                        let sid = SessionId::from_string(source_session_id.as_str());
                        if !t.agent_sessions.iter().any(|s| s.as_str() == sid.as_str()) {
                            t.agent_sessions.push(sid);
                        }
                        if t.best_score.is_none_or(|best| *score > best) {
                            t.best_score = Some(*score);
                            t.best_session_id =
                                Some(SessionId::from_string(source_session_id.as_str()));
                        }
                    }
                }
                aios_protocol::EventKind::HiveSelectionMade {
                    winning_session_id,
                    winning_score,
                    generation,
                    ..
                } => {
                    if let Some(ref mut t) = task {
                        t.current_generation = *generation;
                        t.best_score = Some(*winning_score);
                        t.best_session_id =
                            Some(SessionId::from_string(winning_session_id.as_str()));
                    }
                }
                aios_protocol::EventKind::HiveGenerationCompleted { generation, .. } => {
                    if let Some(ref mut t) = task {
                        t.current_generation = *generation;
                    }
                }
                aios_protocol::EventKind::HiveTaskCompleted { .. } => {
                    if let Some(ref mut t) = task {
                        t.completed = true;
                    }
                }
                _ => {}
            }
        }

        task
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventEnvelope, EventPayload};
    use crate::id::{BranchId, EventId};
    use std::collections::HashMap;

    fn make_envelope(payload: EventPayload) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_string("E1"),
            session_id: SessionId::from_string("S1"),
            branch_id: BranchId::from_string("main"),
            run_id: None,
            seq: 1,
            timestamp: 100,
            parent_id: None,
            payload,
            metadata: HashMap::new(),
            schema_version: 1,
        }
    }

    #[test]
    fn from_events_empty() {
        assert!(HiveTask::from_events(&[]).is_none());
    }

    #[test]
    fn from_events_full_lifecycle() {
        let events = vec![
            make_envelope(EventPayload::HiveTaskCreated {
                hive_task_id: HiveTaskId::from_string("H1"),
                objective: "optimize".into(),
                agent_count: 3,
            }),
            make_envelope(EventPayload::HiveArtifactShared {
                hive_task_id: HiveTaskId::from_string("H1"),
                source_session_id: aios_protocol::SessionId::from_string("SA"),
                score: 0.8,
                mutation_summary: "first try".into(),
            }),
            make_envelope(EventPayload::HiveArtifactShared {
                hive_task_id: HiveTaskId::from_string("H1"),
                source_session_id: aios_protocol::SessionId::from_string("SB"),
                score: 0.9,
                mutation_summary: "better".into(),
            }),
            make_envelope(EventPayload::HiveSelectionMade {
                hive_task_id: HiveTaskId::from_string("H1"),
                winning_session_id: aios_protocol::SessionId::from_string("SB"),
                winning_score: 0.9,
                generation: 1,
            }),
            make_envelope(EventPayload::HiveTaskCompleted {
                hive_task_id: HiveTaskId::from_string("H1"),
                total_generations: 1,
                total_trials: 6,
                final_score: 0.95,
            }),
        ];

        let task = HiveTask::from_events(&events).unwrap();
        assert_eq!(task.hive_task_id.as_str(), "H1");
        assert_eq!(task.objective, "optimize");
        assert_eq!(task.agent_sessions.len(), 2);
        assert_eq!(task.current_generation, 1);
        assert_eq!(task.best_score, Some(0.9));
        assert_eq!(task.best_session_id.as_ref().unwrap().as_str(), "SB");
        assert!(task.completed);
    }

    #[test]
    fn from_events_no_task_created() {
        let events = vec![make_envelope(EventPayload::HiveArtifactShared {
            hive_task_id: HiveTaskId::from_string("H1"),
            source_session_id: aios_protocol::SessionId::from_string("SA"),
            score: 0.8,
            mutation_summary: "orphan".into(),
        })];
        assert!(HiveTask::from_events(&events).is_none());
    }
}
