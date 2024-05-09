// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use parking_lot::RwLock;
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    block::{BlockAPI, VerifiedBlock},
    commit::{load_committed_subdag_from_store, CommitAPI, CommitIndex, CommittedSubDag},
    context::Context,
    dag_state::DagState,
    error::{ConsensusError, ConsensusResult},
    leader_schedule::LeaderSchedule,
    linearizer::Linearizer,
    storage::Store,
    CommitConsumer, ConsensusOutput,
};

/// Role of CommitObserver
/// - Called by core when try_commit() returns newly committed leaders.
/// - The newly committed leaders are sent to commit observer and then commit observer
/// gets subdags for each leader via the commit interpreter (linearizer)
/// - The committed subdags are sent as consensus output via an unbounded tokio channel.
/// No back pressure mechanism is needed as backpressure is handled as input into
/// consenus.
/// - Commit metadata including index is persisted in store, before the CommittedSubDag
/// is sent to the consumer.
/// - When CommitObserver is initialized a last processed commit index can be used
/// to ensure any missing commits are re-sent.
pub(crate) struct CommitObserver {
    context: Arc<Context>,
    /// Component to deterministically collect subdags for committed leaders.
    commit_interpreter: Linearizer,
    /// An unbounded channel to send committed sub-dags to the consumer of consensus output.
    sender: UnboundedSender<ConsensusOutput>,
    /// Persistent storage for blocks, commits and other consensus data.
    store: Arc<dyn Store>,
    leader_schedule: Arc<LeaderSchedule>,
}

impl CommitObserver {
    pub(crate) fn new(
        context: Arc<Context>,
        commit_consumer: CommitConsumer,
        // sender: UnboundedSender<ConsensusOutput>,
        // last_processed_commit_round: Round,
        // last_processed_commit_index: CommitIndex,
        dag_state: Arc<RwLock<DagState>>,
        store: Arc<dyn Store>,
        leader_schedule: Arc<LeaderSchedule>,
    ) -> Self {
        let mut observer = Self {
            context,
            commit_interpreter: Linearizer::new(dag_state.clone()),
            sender: commit_consumer.sender,
            store,
            leader_schedule,
        };

        observer.recover_and_send_commits(commit_consumer.last_processed_commit_index);
        observer
    }

    pub(crate) fn handle_commit(
        &mut self,
        committed_leaders: Vec<VerifiedBlock>,
    ) -> ConsensusResult<Vec<CommittedSubDag>> {
        let _s = self
            .context
            .metrics
            .node_metrics
            .scope_processing_time
            .with_label_values(&["CommitObserver::handle_commit"])
            .start_timer();

        let committed_sub_dags = self.commit_interpreter.handle_commit(committed_leaders);
        let mut sent_sub_dags = vec![];

        for committed_sub_dag in committed_sub_dags.into_iter() {
            // Failures in sender.send() are assumed to be permanent
            if let Err(err) = self.sender.send(ConsensusOutput {
                commit: committed_sub_dag.clone(),
                reputation_scores: self
                    .leader_schedule
                    .leader_swap_table
                    .read()
                    .reputation_scores
                    .authorities_by_score_desc(self.context.clone()),
            }) {
                tracing::error!(
                    "Failed to send committed sub-dag, probably due to shutdown: {err:?}"
                );
                return Err(ConsensusError::Shutdown);
            }
            tracing::debug!(
                "Sending to execution commit {} leader {}",
                committed_sub_dag.commit_index,
                committed_sub_dag.leader
            );
            sent_sub_dags.push(committed_sub_dag);
        }

        self.report_metrics(&sent_sub_dags);
        tracing::trace!("Committed & sent {sent_sub_dags:#?}");
        Ok(sent_sub_dags)
    }

    fn recover_and_send_commits(&mut self, last_processed_commit_index: CommitIndex) {
        // TODO: remove this check, to allow consensus to regenerate commits?
        let last_commit = self
            .store
            .read_last_commit()
            .expect("Reading the last commit should not fail");

        if let Some(last_commit) = last_commit {
            let last_commit_index = last_commit.index();

            assert!(last_commit_index >= last_processed_commit_index);
            if last_commit_index == last_processed_commit_index {
                return;
            }
        };

        // We should not send the last processed commit again, so last_processed_commit_index+1
        let unsent_commits = self
            .store
            .scan_commits(((last_processed_commit_index + 1)..CommitIndex::MAX).into())
            .expect("Scanning commits should not fail");

        // Resend all the committed subdags to the consensus output channel
        // for all the commits above the last processed index.
        let mut last_sent_commit_index = last_processed_commit_index;
        for commit in unsent_commits {
            // Commit index must be continuous.
            assert_eq!(commit.index(), last_sent_commit_index + 1);
            let committed_sub_dag = load_committed_subdag_from_store(self.store.as_ref(), commit);

            self.sender
                .send(ConsensusOutput {
                    commit: committed_sub_dag,
                    reputation_scores: self
                        .leader_schedule
                        .leader_swap_table
                        .read()
                        .reputation_scores
                        .authorities_by_score_desc(self.context.clone()),
                })
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to send commit during recovery, probably due to shutdown: {:?}",
                        e
                    )
                });

            last_sent_commit_index += 1;
        }
    }

    fn report_metrics(&self, committed: &[CommittedSubDag]) {
        let utc_now = self.context.clock.timestamp_utc_ms();
        let mut total = 0;
        for block in committed.iter().flat_map(|dag| &dag.blocks) {
            let latency_ms = utc_now
                .checked_sub(block.timestamp_ms())
                .unwrap_or_default();

            total += 1;

            self.context
                .metrics
                .node_metrics
                .block_commit_latency
                .observe(Duration::from_millis(latency_ms).as_secs_f64());
            self.context
                .metrics
                .node_metrics
                .last_committed_leader_round
                .set(block.round() as i64);
        }

        self.context
            .metrics
            .node_metrics
            .blocks_per_commit_count
            .observe(total as f64);
        self.context
            .metrics
            .node_metrics
            .sub_dags_per_commit_count
            .observe(committed.len() as f64);
    }
}

#[cfg(test)]
mod tests {
    use parking_lot::RwLock;
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

    use super::*;
    use crate::{
        block::{BlockRef, Round},
        commit::DEFAULT_WAVE_LENGTH,
        context::Context,
        dag_state::DagState,
        storage::mem_store::MemStore,
        test_dag_builder::DagBuilder,
    };

    #[test]
    fn test_handle_commit() {
        telemetry_subscribers::init_for_testing();
        let num_authorities = 4;
        let context = Arc::new(Context::new_for_test(num_authorities).0);
        let mem_store = Arc::new(MemStore::new());
        let dag_state = Arc::new(RwLock::new(DagState::new(
            context.clone(),
            mem_store.clone(),
        )));
        let last_processed_commit_round = 0;
        let last_processed_commit_index = 0;
        let (sender, mut receiver) = unbounded_channel();

        let leader_schedule = Arc::new(LeaderSchedule::from_store(
            context.clone(),
            dag_state.clone(),
        ));

        let mut observer = CommitObserver::new(
            context.clone(),
            CommitConsumer::new(
                sender,
                last_processed_commit_round,
                last_processed_commit_index,
            ),
            dag_state.clone(),
            mem_store.clone(),
            leader_schedule,
        );

        // Populate fully connected test blocks for round 0 ~ 10, authorities 0 ~ 3.
        let num_rounds = 10;
        let mut builder = DagBuilder::new(context.clone());
        builder
            .layers(1..=num_rounds)
            .build()
            .persist_layers(dag_state.clone());

        let leaders = builder
            .leader_blocks(1..=num_rounds)
            .into_iter()
            .map(Option::unwrap)
            .collect::<Vec<_>>();

        let commits = observer.handle_commit(leaders.clone()).unwrap();

        // Check commits are returned by CommitObserver::handle_commit is accurate
        let mut expected_stored_refs: Vec<BlockRef> = vec![];
        for (idx, subdag) in commits.iter().enumerate() {
            tracing::info!("{subdag:?}");
            assert_eq!(subdag.leader, leaders[idx].reference());
            let expected_ts = if idx == 0 {
                leaders[idx].timestamp_ms()
            } else {
                leaders[idx]
                    .timestamp_ms()
                    .max(commits[idx - 1].timestamp_ms)
            };
            assert_eq!(expected_ts, subdag.timestamp_ms);
            if idx == 0 {
                // First subdag includes the leader block plus all ancestor blocks
                // of the leader minus the genesis round blocks
                assert_eq!(subdag.blocks.len(), 1);
            } else {
                // Every subdag after will be missing the leader block from the previous
                // committed subdag
                assert_eq!(subdag.blocks.len(), num_authorities);
            }
            for block in subdag.blocks.iter() {
                expected_stored_refs.push(block.reference());
                assert!(block.round() <= leaders[idx].round());
            }
            assert_eq!(subdag.commit_index, idx as CommitIndex + 1);
        }

        // Check commits sent over consensus output channel is accurate
        let mut processed_subdag_index = 0;
        while let Ok(output) = receiver.try_recv() {
            assert_eq!(output.commit, commits[processed_subdag_index]);
            assert_eq!(output.reputation_scores, vec![]);
            processed_subdag_index = output.commit.commit_index as usize;
            if processed_subdag_index == leaders.len() {
                break;
            }
        }
        assert_eq!(processed_subdag_index, leaders.len());

        verify_channel_empty(&mut receiver);

        // Check commits have been persisted to storage
        let last_commit = mem_store.read_last_commit().unwrap().unwrap();
        assert_eq!(last_commit.index(), commits.last().unwrap().commit_index);
        let all_stored_commits = mem_store
            .scan_commits((0..CommitIndex::MAX).into())
            .unwrap();
        assert_eq!(all_stored_commits.len(), leaders.len());
        let blocks_existence = mem_store.contains_blocks(&expected_stored_refs).unwrap();
        assert!(blocks_existence.iter().all(|exists| *exists));
    }

    #[test]
    fn test_recover_and_send_commits() {
        telemetry_subscribers::init_for_testing();
        let num_authorities = 4;
        let context = Arc::new(Context::new_for_test(num_authorities).0);
        let mem_store = Arc::new(MemStore::new());
        let dag_state = Arc::new(RwLock::new(DagState::new(
            context.clone(),
            mem_store.clone(),
        )));
        let last_processed_commit_round = 0;
        let last_processed_commit_index = 0;
        let (sender, mut receiver) = unbounded_channel();

        let leader_schedule = Arc::new(LeaderSchedule::from_store(
            context.clone(),
            dag_state.clone(),
        ));

        let mut observer = CommitObserver::new(
            context.clone(),
            CommitConsumer::new(
                sender.clone(),
                last_processed_commit_round,
                last_processed_commit_index,
            ),
            dag_state.clone(),
            mem_store.clone(),
            leader_schedule.clone(),
        );

        // Populate fully connected test blocks for round 0 ~ 10, authorities 0 ~ 3.
        let num_rounds = 10;
        let mut builder = DagBuilder::new(context.clone());
        builder
            .layers(1..=num_rounds)
            .build()
            .persist_layers(dag_state.clone());

        let leaders = builder
            .leader_blocks(1..=num_rounds)
            .into_iter()
            .map(Option::unwrap)
            .collect::<Vec<_>>();

        // Commit first batch of leaders (2) and "receive" the subdags as the
        // consumer of the consensus output channel.
        let expected_last_processed_index: usize = 2;
        let expected_last_processed_round =
            expected_last_processed_index as u32 * DEFAULT_WAVE_LENGTH;
        let mut commits = observer
            .handle_commit(
                leaders
                    .clone()
                    .into_iter()
                    .take(expected_last_processed_index)
                    .collect::<Vec<_>>(),
            )
            .unwrap();

        // Check commits sent over consensus output channel is accurate
        let mut processed_subdag_index = 0;
        while let Ok(output) = receiver.try_recv() {
            tracing::info!("Processed {output}");
            assert_eq!(output.commit, commits[processed_subdag_index]);
            assert_eq!(output.reputation_scores, vec![]);
            processed_subdag_index = output.commit.commit_index as usize;
            if processed_subdag_index == expected_last_processed_index {
                break;
            }
        }
        assert_eq!(processed_subdag_index, expected_last_processed_index);

        verify_channel_empty(&mut receiver);

        // Check last stored commit is correct
        let last_commit = mem_store.read_last_commit().unwrap().unwrap();
        assert_eq!(
            last_commit.index(),
            expected_last_processed_index as CommitIndex
        );

        // Handle next batch of leaders (1), these will be sent by consensus but not
        // "processed" by consensus output channel. Simulating something happened on
        // the consumer side where the commits were not persisted.
        commits.append(
            &mut observer
                .handle_commit(
                    leaders
                        .clone()
                        .into_iter()
                        .skip(expected_last_processed_index)
                        .collect::<Vec<_>>(),
                )
                .unwrap(),
        );

        let expected_last_sent_index = num_rounds as usize;
        while let Ok(output) = receiver.try_recv() {
            tracing::info!("{output} was sent but not processed by consumer");
            assert_eq!(output.commit, commits[processed_subdag_index]);
            assert_eq!(output.reputation_scores, vec![]);
            processed_subdag_index = output.commit.commit_index as usize;
            if processed_subdag_index == expected_last_sent_index {
                break;
            }
        }
        assert_eq!(processed_subdag_index, expected_last_sent_index);

        verify_channel_empty(&mut receiver);

        // Check last stored commit is correct. We should persist the last commit
        // that was sent over the channel regardless of how the consumer handled
        // the commit on their end.
        let last_commit = mem_store.read_last_commit().unwrap().unwrap();
        assert_eq!(last_commit.index(), expected_last_sent_index as CommitIndex);

        // Re-create commit observer starting from index 2 which represents the
        // last processed index from the consumer over consensus output channel
        let _observer = CommitObserver::new(
            context.clone(),
            CommitConsumer::new(
                sender,
                expected_last_processed_round as Round,
                expected_last_processed_index as CommitIndex,
            ),
            dag_state.clone(),
            mem_store.clone(),
            leader_schedule,
        );

        // Check commits sent over consensus output channel is accurate starting
        // from last processed index of 2 and finishing at last sent index of 3.
        processed_subdag_index = expected_last_processed_index;
        while let Ok(output) = receiver.try_recv() {
            tracing::info!("Processed {output} on resubmission");
            assert_eq!(output.commit, commits[processed_subdag_index]);
            assert_eq!(output.reputation_scores, vec![]);
            processed_subdag_index = output.commit.commit_index as usize;
            if processed_subdag_index == expected_last_sent_index {
                break;
            }
        }
        assert_eq!(processed_subdag_index, expected_last_sent_index);

        verify_channel_empty(&mut receiver);
    }

    #[test]
    fn test_send_no_missing_commits() {
        telemetry_subscribers::init_for_testing();
        let num_authorities = 4;
        let context = Arc::new(Context::new_for_test(num_authorities).0);
        let mem_store = Arc::new(MemStore::new());
        let dag_state = Arc::new(RwLock::new(DagState::new(
            context.clone(),
            mem_store.clone(),
        )));
        let last_processed_commit_round = 0;
        let last_processed_commit_index = 0;
        let (sender, mut receiver) = unbounded_channel();

        let leader_schedule = Arc::new(LeaderSchedule::from_store(
            context.clone(),
            dag_state.clone(),
        ));

        let mut observer = CommitObserver::new(
            context.clone(),
            CommitConsumer::new(
                sender.clone(),
                last_processed_commit_round,
                last_processed_commit_index,
            ),
            dag_state.clone(),
            mem_store.clone(),
            leader_schedule.clone(),
        );

        // Populate fully connected test blocks for round 0 ~ 10, authorities 0 ~ 3.
        let num_rounds = 10;
        let mut builder = DagBuilder::new(context.clone());
        builder
            .layers(1..=num_rounds)
            .build()
            .persist_layers(dag_state.clone());

        let leaders = builder
            .leader_blocks(1..=num_rounds)
            .into_iter()
            .map(Option::unwrap)
            .collect::<Vec<_>>();

        // Commit all of the leaders and "receive" the subdags as the consumer of
        // the consensus output channel.
        let expected_last_processed_index: usize = 10;
        let expected_last_processed_round =
            expected_last_processed_index as u32 * DEFAULT_WAVE_LENGTH;
        let commits = observer.handle_commit(leaders.clone()).unwrap();

        // Check commits sent over consensus output channel is accurate
        let mut processed_subdag_index = 0;
        while let Ok(output) = receiver.try_recv() {
            tracing::info!("Processed {output}");
            assert_eq!(output.commit, commits[processed_subdag_index]);
            assert_eq!(output.reputation_scores, vec![]);
            processed_subdag_index = output.commit.commit_index as usize;
            if processed_subdag_index == expected_last_processed_index {
                break;
            }
        }
        assert_eq!(processed_subdag_index, expected_last_processed_index);

        verify_channel_empty(&mut receiver);

        // Check last stored commit is correct
        let last_commit = mem_store.read_last_commit().unwrap().unwrap();
        assert_eq!(
            last_commit.index(),
            expected_last_processed_index as CommitIndex
        );

        // Re-create commit observer starting from index 3 which represents the
        // last processed index from the consumer over consensus output channel
        let _observer = CommitObserver::new(
            context.clone(),
            CommitConsumer::new(
                sender,
                expected_last_processed_round as Round,
                expected_last_processed_index as CommitIndex,
            ),
            dag_state.clone(),
            mem_store.clone(),
            leader_schedule,
        );

        // No commits should be resubmitted as consensus store's last commit index
        // is equal to last processed index by consumer
        verify_channel_empty(&mut receiver);
    }

    /// After receiving all expected subdags, ensure channel is empty
    fn verify_channel_empty(receiver: &mut UnboundedReceiver<ConsensusOutput>) {
        match receiver.try_recv() {
            Ok(_) => {
                panic!("Expected the consensus output channel to be empty, but found more subdags.")
            }
            Err(e) => match e {
                tokio::sync::mpsc::error::TryRecvError::Empty => {}
                tokio::sync::mpsc::error::TryRecvError::Disconnected => {
                    panic!("The consensus output channel was unexpectedly closed.")
                }
            },
        }
    }
}
