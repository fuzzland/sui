// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use consensus_config::AuthorityIndex;
use futures::StreamExt;
use mysten_metrics::spawn_monitored_task;
use parking_lot::{Mutex, RwLock};
use tokio::{task::JoinHandle, time::sleep};
use tracing::{debug, error, info};

use crate::{
    block::BlockAPI as _,
    context::Context,
    dag_state::DagState,
    network::{NetworkClient, NetworkService},
    Round,
};

/// Subscriber manages the block stream subscriptions to other peers, taking care of retrying
/// when subscription streams break. Blocks returned from the peer are sent to the authority
/// service for processing.
/// Currently subscription management for individual peer is not exposed, but it could become
/// useful in future.
pub(crate) struct Subscriber<C: NetworkClient, S: NetworkService> {
    context: Arc<Context>,
    network_client: Arc<C>,
    authority_service: Arc<S>,
    dag_state: Arc<RwLock<DagState>>,
    subscriptions: Arc<Mutex<Box<[Option<JoinHandle<()>>]>>>,
}

impl<C: NetworkClient, S: NetworkService> Subscriber<C, S> {
    pub(crate) fn new(
        context: Arc<Context>,
        network_client: Arc<C>,
        authority_service: Arc<S>,
        dag_state: Arc<RwLock<DagState>>,
    ) -> Self {
        let subscriptions = (0..context.committee.size())
            .map(|_| None)
            .collect::<Vec<_>>();
        Self {
            context,
            network_client,
            authority_service,
            dag_state,
            subscriptions: Arc::new(Mutex::new(subscriptions.into_boxed_slice())),
        }
    }

    pub(crate) fn subscribe(&self, peer: AuthorityIndex) {
        if peer == self.context.own_index {
            error!("Attempt to subscribe to own validator {peer} is ignored!");
            return;
        }
        let context = self.context.clone();
        let network_client = self.network_client.clone();
        let authority_service = self.authority_service.clone();
        let last_received = self
            .dag_state
            .read()
            .get_last_block_for_authority(peer)
            .round();

        let mut subscriptions = self.subscriptions.lock();
        self.unsubscribe_locked(peer, &mut subscriptions[peer.value()]);
        subscriptions[peer.value()] = Some(spawn_monitored_task!(Self::subscription_loop(
            context,
            network_client,
            authority_service,
            peer,
            last_received,
        )));
        let peer_hostname = self.context.committee.authority(peer).hostname.clone();
        self.context
            .metrics
            .node_metrics
            .subscriber_connections
            .with_label_values(&[&peer_hostname])
            .inc();
    }

    pub(crate) fn stop(&self) {
        let mut subscriptions = self.subscriptions.lock();
        for (peer, _) in self.context.committee.authorities() {
            self.unsubscribe_locked(peer, &mut subscriptions[peer.value()]);
        }
    }

    fn unsubscribe_locked(&self, peer: AuthorityIndex, subscription: &mut Option<JoinHandle<()>>) {
        let peer_hostname = self.context.committee.authority(peer).hostname.clone();
        self.context
            .metrics
            .node_metrics
            .subscriber_connections
            .with_label_values(&[&peer_hostname])
            .dec();
        if let Some(subscription) = subscription.take() {
            subscription.abort();
        }
    }

    async fn subscription_loop(
        context: Arc<Context>,
        network_client: Arc<C>,
        authority_service: Arc<S>,
        peer: AuthorityIndex,
        last_received: Round,
    ) {
        const IMMEDIATE_RETRIES: i64 = 3;
        const MAX_RETRY_INTERNAL: Duration = Duration::from_secs(10);
        let peer_hostname = context.committee.authority(peer).hostname.clone();
        let mut retries: i64 = 0;
        'subscription: loop {
            if retries > IMMEDIATE_RETRIES {
                // When not immediately retrying, add a delay starting from 100ms and increases until 10s.
                let delay = Duration::from_secs_f64(
                    0.1 * 1.2f64.powf((retries - IMMEDIATE_RETRIES - 1) as f64),
                )
                .min(MAX_RETRY_INTERNAL);
                debug!(
                    "Delaying retry {} to subscribe to blocks from peer {} in {} seconds",
                    retries,
                    peer,
                    delay.as_secs_f64(),
                );
                sleep(delay).await;
            } else {
                // Retry immediately, but still yield to avoid monopolizing the thread.
                tokio::task::yield_now().await;
            }
            let mut blocks = match network_client
                .subscribe_blocks(peer, last_received, MAX_RETRY_INTERNAL)
                .await
            {
                Ok(blocks) => {
                    retries = 0;
                    context
                        .metrics
                        .node_metrics
                        .subscriber_connection_attempts
                        .with_label_values(&[&peer_hostname, "success"])
                        .inc();
                    blocks
                }
                Err(e) => {
                    retries += 1;
                    context
                        .metrics
                        .node_metrics
                        .subscriber_connection_attempts
                        .with_label_values(&[&peer_hostname, "failure"])
                        .inc();
                    debug!("Failed to subscribe to blocks from peer {}: {}", peer, e);
                    continue 'subscription;
                }
            };
            'stream: loop {
                match blocks.next().await {
                    Some(block) => {
                        let result = authority_service
                            .handle_send_block(peer, block.clone())
                            .await;
                        if let Err(e) = result {
                            info!(
                                "Failed to process block from peer {}: {}. Block: {:?}",
                                peer, e, block,
                            );
                        }
                    }
                    None => {
                        retries += 1;
                        debug!("Subscription to blocks from peer {} ended", peer);
                        break 'stream;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use anemo::async_trait;
    use bytes::Bytes;
    use futures::stream;

    use super::*;
    use crate::{
        block::{BlockRef, VerifiedBlock},
        error::ConsensusResult,
        network::{test_network::TestService, BlockStream},
        storage::mem_store::MemStore,
    };

    struct SubscriberTestClient {}

    impl SubscriberTestClient {
        fn new() -> Self {
            Self {}
        }
    }

    #[async_trait]
    impl NetworkClient for SubscriberTestClient {
        const SUPPORT_STREAMING: bool = true;

        async fn send_block(
            &self,
            _peer: AuthorityIndex,
            _block: &VerifiedBlock,
            _timeout: Duration,
        ) -> ConsensusResult<()> {
            unimplemented!("Unimplemented")
        }

        async fn subscribe_blocks(
            &self,
            _peer: AuthorityIndex,
            _last_received: Round,
            _timeout: Duration,
        ) -> ConsensusResult<BlockStream> {
            let block_stream = stream::unfold((), |_| async {
                sleep(Duration::from_millis(1)).await;
                Some((Bytes::from(vec![1u8; 8]), ()))
            })
            .take(10);
            Ok(Box::pin(block_stream))
        }

        async fn fetch_blocks(
            &self,
            _peer: AuthorityIndex,
            _block_refs: Vec<BlockRef>,
            _timeout: Duration,
        ) -> ConsensusResult<Vec<Bytes>> {
            unimplemented!("Unimplemented")
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn subscriber_retries() {
        let (context, _keys) = Context::new_for_test(4);
        let context = Arc::new(context);
        let authority_service = Arc::new(Mutex::new(TestService::new()));
        let network_client = Arc::new(SubscriberTestClient::new());
        let store = Arc::new(MemStore::new());
        let dag_state = Arc::new(RwLock::new(DagState::new(context.clone(), store)));
        let subscriber = Subscriber::new(
            context.clone(),
            network_client,
            authority_service.clone(),
            dag_state,
        );

        let peer = context.committee.to_authority_index(2).unwrap();
        subscriber.subscribe(peer);

        // Wait for enough blocks received.
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let service = authority_service.lock();
            if service.handle_send_block.len() >= 100 {
                break;
            }
        }

        // Even if the stream ends after 10 blocks, the subscriber should retry and get enough
        // blocks eventually.
        let service = authority_service.lock();
        assert!(service.handle_send_block.len() >= 100);
        for (p, block) in service.handle_send_block.iter() {
            assert_eq!(*p, peer);
            assert_eq!(*block, Bytes::from(vec![1u8; 8]));
        }
    }
}
