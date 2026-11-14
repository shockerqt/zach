//! Durable orchestration owner. Workers execute one bounded side effect and return
//! typed events; only this thread owns the daemon's SQLite connection.
use crate::v2::delivery::{self, DeliveryStore, SystemDeliveryDriver};
use crate::v2::intake::{self, WsTaskClient};
use crate::v2::isolation::{self, PreparedResources};
use crate::v2::merge_queue::{self, MergePhaseResult, SystemMergeDriver};
use crate::v2::pipeline::{self, PipelineStepResult};
use crate::v2::router::infer_model_family;
use crate::v2::runner::{
    self, AttemptManifest, PreparedLaunch, StageExecutionResult, SystemUnitController,
    UnitController, UnitObservation, UnitState,
};
use crate::v2::scheduler::{self, HeavyCheckSemaphore};
use crate::v2::socket::{ClientCommand, ServerMessage};
use crate::v2::store::{
    DecisionResolution, LifecycleOperation, MergeCheckpoint, PipelineCheckpoint,
    StageAttemptRecord, TaskRecord, V2Store, V2StoreError,
};
use crate::v2::{default_ws_task_bin, now_epoch};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// Acquire before socket unlink/bind; CLOEXEC prevents subprocesses retaining it.
pub struct DaemonLock {
    _file: File,
}
impl DaemonLock {
    pub fn acquire(state_dir: &Path) -> Result<Self, String> {
        isolation::secure_parents(state_dir)?;
        runner::ensure_secure_dir(state_dir)?;
        let path = state_dir.join("zachd.lock");
        isolation::reject_symlink_components(&path)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| e.to_string())?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("another zachd owns the state directory".into());
        }
        Ok(Self { _file: file })
    }
}

type Job = Box<dyn FnOnce() -> Result<WorkerResult, String> + Send>;
struct WorkerJob {
    key: String,
    task_id: Option<String>,
    work: Job,
}
struct WorkerPool {
    tx: mpsc::SyncSender<WorkerJob>,
}
impl WorkerPool {
    fn new(count: usize, events: mpsc::SyncSender<CoordinatorEvent>) -> Self {
        let (tx, rx) = mpsc::sync_channel::<WorkerJob>(count);
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..count {
            let rx = rx.clone();
            let events = events.clone();
            std::thread::spawn(move || {
                loop {
                    let job = {
                        let Ok(rx) = rx.lock() else { return };
                        match rx.recv() {
                            Ok(job) => job,
                            Err(_) => return,
                        }
                    };
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job.work))
                        .unwrap_or_else(|_| Err("worker job panicked".into()));
                    if events
                        .send(CoordinatorEvent::Completed {
                            key: job.key,
                            task_id: job.task_id,
                            result: Box::new(result),
                        })
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
        Self { tx }
    }
    fn submit(&self, key: String, task_id: Option<String>, work: Job) -> bool {
        self.tx.try_send(WorkerJob { key, task_id, work }).is_ok()
    }
}

#[allow(clippy::large_enum_variant)]
pub enum WorkerResult {
    Preflight,
    Export(Vec<TaskRecord>),
    Prepared(PreparedLaunch),
    Launched(String),
    Observed {
        attempt_id: String,
        observation: UnitObservation,
        recovered: Option<PreparedResources>,
        manifest: Result<AttemptManifest, String>,
        recovery_error: Option<String>,
    },
    Harvested {
        attempt_id: String,
        result: Result<StageExecutionResult, String>,
    },
    UnitIdentity {
        attempt_id: String,
        manifest: AttemptManifest,
    },
    UnitStopped {
        attempt_id: String,
        observation: UnitObservation,
    },
    Stopped(String),
    Pipeline {
        attempt_id: String,
        step: PipelineStepResult,
    },
    Lifecycle {
        operation_id: String,
        output: String,
    },
    Merge {
        task_id: String,
        result: MergePhaseResult,
    },
    StartupReconciled {
        adopted: Vec<StageAttemptRecord>,
        retired: Vec<StageAttemptRecord>,
    },
    Reconciled,
    DeliveryPolled,
}

type DeliveryStoreOperation = Box<dyn FnOnce(&mut V2Store) + Send>;

/// A worker waits only for short store operations; the coordinator never waits
/// for delivery network I/O. Intent checkpoints commit before remote dispatch.
struct CoordinatorDeliveryStore {
    commands: mpsc::SyncSender<CoordinatorEvent>,
}
impl DeliveryStore for CoordinatorDeliveryStore {
    fn access<T: Send + 'static>(
        &mut self,
        operation: impl FnOnce(&mut V2Store) -> Result<T, V2StoreError> + Send + 'static,
    ) -> Result<T, V2StoreError> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.commands
            .send(CoordinatorEvent::DeliveryStore(Box::new(move |store| {
                let _ = tx.send(operation(store));
            })))
            .map_err(|_| V2StoreError("delivery coordinator stopped".into()))?;
        rx.recv()
            .map_err(|_| V2StoreError("delivery coordinator stopped".into()))?
    }
}

pub enum CoordinatorEvent {
    DeliveryStore(DeliveryStoreOperation),
    Socket {
        client_id: usize,
        command: ClientCommand,
    },
    Completed {
        key: String,
        task_id: Option<String>,
        result: Box<Result<WorkerResult, String>>,
    },
    Replay {
        client_id: usize,
        group: Option<String>,
        since_seq: i64,
    },
    Shutdown,
}

pub enum SocketDelivery {
    Reply {
        client_id: usize,
        messages: Vec<ServerMessage>,
    },
    Events(Vec<crate::v2::store::TaskEventRecord>),
    ReplayPage {
        client_id: usize,
        events: Vec<crate::v2::store::TaskEventRecord>,
        as_of_seq: i64,
    },
    Fatal(String),
    Ready,
    Stopped,
}

pub struct CoordinatorHandle {
    pub commands: mpsc::SyncSender<CoordinatorEvent>,
    pub deliveries: mpsc::Receiver<SocketDelivery>,
}

pub struct Coordinator {
    store: V2Store,
    state_dir: PathBuf,
    instance: String,
    rx: mpsc::Receiver<CoordinatorEvent>,
    commands: mpsc::SyncSender<CoordinatorEvent>,
    socket_tx: mpsc::SyncSender<SocketDelivery>,
    pending_deliveries: VecDeque<SocketDelivery>,
    workers: WorkerPool,
    monitors: WorkerPool,
    governance: WorkerPool,
    controller: Arc<dyn UnitController>,
    ws: Arc<dyn WsTaskClient>,
    semaphore: HeavyCheckSemaphore,
    jobs: BTreeSet<String>,
    manifests: BTreeMap<String, AttemptManifest>,
    resources: BTreeMap<String, PreparedResources>,
    attached: BTreeSet<String>,
    last_poll: BTreeMap<String, Instant>,
    observation_faults: BTreeMap<String, u32>,
    merge_poll: BTreeMap<String, Instant>,
    ready: bool,
    preflight: bool,
    reconciled: bool,
    synced: bool,
    last_export: Instant,
    last_delivery_poll: Instant,
    last_heartbeat: Instant,
    last_seq: i64,
    scope: Option<(Option<String>, Option<String>)>,
    #[cfg(test)]
    submission_probe: Option<BTreeMap<&'static str, usize>>,
    #[cfg(test)]
    rehearsal_delivery: Option<Arc<Mutex<tests::RehearsalDelivery>>>,
    #[cfg(test)]
    rehearsal_poll_progress: Option<Arc<[std::sync::atomic::AtomicUsize; 2]>>,
}

impl Coordinator {
    pub fn spawn(store: V2Store, state_dir: PathBuf) -> CoordinatorHandle {
        let (mut coordinator, handle) = Self::create(store, state_dir);
        std::thread::spawn(move || {
            if let Err(error) = coordinator.run() {
                let _delivery = coordinator.socket_tx.try_send(SocketDelivery::Fatal(error));
            }
        });
        handle
    }

    fn create(store: V2Store, state_dir: PathBuf) -> (Self, CoordinatorHandle) {
        let (tx, rx) = mpsc::sync_channel(256);
        let (socket_tx, deliveries) = mpsc::sync_channel(128);
        let workers = WorkerPool::new(4, tx.clone());
        // Unit inspections and Governance each have reserved capacity.
        let monitors = WorkerPool::new(2, tx.clone());
        let governance = WorkerPool::new(1, tx.clone());
        let commands = tx.clone();
        let coordinator = Self {
            store,
            state_dir,
            instance: format!("{}-{}", std::process::id(), now_epoch()),
            rx,
            commands: tx,
            socket_tx,
            pending_deliveries: VecDeque::new(),
            workers,
            monitors,
            governance,
            controller: Arc::new(SystemUnitController),
            ws: Arc::new(intake::SystemWsTaskClient {
                bin: default_ws_task_bin(),
            }),
            semaphore: HeavyCheckSemaphore::new(),
            jobs: BTreeSet::new(),
            manifests: BTreeMap::new(),
            resources: BTreeMap::new(),
            attached: BTreeSet::new(),
            last_poll: BTreeMap::new(),
            observation_faults: BTreeMap::new(),
            merge_poll: BTreeMap::new(),
            ready: false,
            preflight: false,
            reconciled: false,
            synced: false,
            last_export: Instant::now() - Duration::from_secs(3600),
            last_delivery_poll: Instant::now() - Duration::from_secs(10),
            last_heartbeat: Instant::now() - Duration::from_secs(10),
            last_seq: 0,
            scope: None,
            #[cfg(test)]
            submission_probe: None,
            #[cfg(test)]
            rehearsal_delivery: None,
            #[cfg(test)]
            rehearsal_poll_progress: None,
        };
        (
            coordinator,
            CoordinatorHandle {
                commands,
                deliveries,
            },
        )
    }

    fn submit(&mut self, key: String, task_id: Option<String>, pool: u8, job: Job) -> bool {
        #[cfg(test)]
        if let Some(probe) = self.submission_probe.as_mut() {
            // Drop the closure BEFORE it can reach any WorkerPool thread. Never
            // retain keys/task IDs/payloads in private-rehearsal diagnostics.
            let class = match key.split(':').next().unwrap_or("") {
                "prepare" => "preparation",
                "launch" => "worker",
                "pipeline" => "pipeline",
                "lifecycle" | "ws" => "publication",
                "merge" => "merge",
                "deploy" => "deploy",
                "delivery-close" => "delivery",
                "post-merge-deliveries" => "delivery-poll",
                "identity" | "observe" => "inspection",
                "stop" | "cleanup" => "unit-mutation",
                "reconcile" | "preflight" | "export" => "control",
                _ => "other",
            };
            *probe.entry(class).or_default() += 1;
            if key != "post-merge-deliveries" || self.rehearsal_delivery.is_none() {
                drop(job);
                return false;
            }
            // Only the fake-bound read/settled poll can reach a WorkerPool.
        }
        if self.jobs.contains(&key) {
            return false;
        }
        let accepted = match pool {
            1 => self.monitors.submit(key.clone(), task_id, job),
            2 => self.governance.submit(key.clone(), task_id, job),
            _ => self.workers.submit(key.clone(), task_id, job),
        };
        if accepted {
            self.jobs.insert(key);
        }
        accepted
    }

    fn run(&mut self) -> Result<(), String> {
        self.store
            .set_meta("daemon_instance_id", &self.instance)
            .map_err(|e| e.to_string())?;
        for op in self.store.lifecycle_ops().map_err(|e| e.to_string())? {
            if op.kind == "start" && op.state == "ACKNOWLEDGED" {
                let mut task = self.task(&op.task_id)?;
                if !task.memory.governance_started {
                    task.memory.governance_started = true;
                    self.save(&task)?;
                }
            }
            if op.state == "FAILED" {
                let task = self.task(&op.task_id)?;
                if task.autonomous_consent
                    && !task.memory.halt_requested
                    && !matches!(task.status.as_str(), "Done" | "Cancelled")
                {
                    self.lifecycle_failed(
                        &op.operation_id,
                        op.last_error
                            .as_deref()
                            .unwrap_or("interrupted publication failure"),
                    )?;
                }
            }
            if op.state == "IN_FLIGHT" {
                self.store
                    .update_lifecycle(&op.operation_id, "PENDING", None, 0)
                    .map_err(|e| e.to_string())?;
            }
        }
        loop {
            self.flush_deliveries()?;
            for _ in 0..64 {
                if self.pending_deliveries.len() >= 128 {
                    break;
                }
                match self.rx.try_recv() {
                    Ok(CoordinatorEvent::Shutdown) => {
                        self.ready = false;
                        self.store
                            .set_meta("daemon_lease_expires_epoch", "0")
                            .map_err(|e| e.to_string())?;
                        let _stopped = self.socket_tx.try_send(SocketDelivery::Stopped);
                        return Ok(());
                    }
                    Ok(event) => self.handle_event(event)?,
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
                }
            }
            self.tick()?;
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn send_delivery(&mut self, delivery: SocketDelivery) -> Result<(), String> {
        if !self.pending_deliveries.is_empty() {
            self.pending_deliveries.push_back(delivery);
            return Ok(());
        }
        match self.socket_tx.try_send(delivery) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(delivery)) => {
                self.pending_deliveries.push_back(delivery);
                Ok(())
            }
            Err(mpsc::TrySendError::Disconnected(_)) => Err("socket consumer disconnected".into()),
        }
    }
    fn flush_deliveries(&mut self) -> Result<(), String> {
        for _ in 0..128 {
            let Some(delivery) = self.pending_deliveries.pop_front() else {
                break;
            };
            match self.socket_tx.try_send(delivery) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(delivery)) => {
                    self.pending_deliveries.push_front(delivery);
                    break;
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    return Err("socket consumer disconnected".into());
                }
            }
        }
        Ok(())
    }

    fn error_event(&mut self, task_id: Option<&str>, message: &str) -> Result<(), String> {
        let task = task_id
            .map(|id| self.store.get_task(id))
            .transpose()
            .map_err(|e| e.to_string())?
            .flatten();
        self.store
            .append_event(
                task_id.unwrap_or("daemon"),
                task.as_ref()
                    .map(|t| t.task_group.as_str())
                    .unwrap_or("daemon"),
                "SUPERVISOR_ERROR",
                &serde_json::json!({"error":runner::truncate_utf8_bytes(message,1024)}),
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn handle_event(&mut self, event: CoordinatorEvent) -> Result<(), String> {
        match event {
            CoordinatorEvent::Replay {
                client_id,
                group,
                since_seq,
            } => {
                let as_of_seq = self.store.max_seq_id().map_err(|e| e.to_string())?;
                let events = self
                    .store
                    .list_events_since(group.as_deref(), since_seq, 128)
                    .map_err(|e| e.to_string())?;
                self.send_delivery(SocketDelivery::ReplayPage {
                    client_id,
                    events,
                    as_of_seq,
                })?;
            }
            CoordinatorEvent::Socket { client_id, command } => {
                let result = self.socket_command(command);
                let messages = match result {
                    Ok(messages) => messages,
                    Err(error) => vec![ServerMessage::Error { error }],
                };
                self.send_delivery(SocketDelivery::Reply {
                    client_id,
                    messages,
                })?;
            }
            CoordinatorEvent::Completed {
                key,
                task_id,
                result,
            } => {
                self.jobs.remove(&key);
                let handled = (*result).and_then(|result| self.worker_result(result));
                match handled {
                    Ok(()) => {}
                    Err(error) => {
                        self.error_event(task_id.as_deref(), &error)?;
                        if key == "preflight" {
                            return Err(error);
                        }
                        if key.starts_with("observe:") {
                            let id = key.trim_start_matches("observe:").to_owned();
                            let faults = self.observation_faults.entry(id.clone()).or_default();
                            *faults += 1;
                            if *faults >= 10
                                && let Some(mut attempt) = self
                                    .store
                                    .get_stage_attempt(&id)
                                    .map_err(|e| e.to_string())?
                            {
                                attempt.phase = "HARVESTED".into();
                                attempt.status = "FAILED".into();
                                attempt.failure_class = Some("infra".into());
                                attempt.summary = Some(
                                    "persistent unit observation fault; stop required before retry"
                                        .into(),
                                );
                                attempt.ended_epoch = Some(now_epoch());
                                self.store
                                    .record_stage_attempt(&attempt)
                                    .map_err(|e| e.to_string())?;
                            }
                            let count = self
                                .store
                                .meta("reconciliation_errors")
                                .map_err(|e| e.to_string())?
                                .and_then(|s| s.parse::<u64>().ok())
                                .unwrap_or(0)
                                + 1;
                            self.store
                                .set_meta("reconciliation_errors", &count.to_string())
                                .map_err(|e| e.to_string())?;
                        } else if key.starts_with("identity:") {
                            if let Some(id) = task_id.as_deref() {
                                self.quarantine_task(id, &error)?;
                            }
                        } else if key.starts_with("ws:") {
                            self.lifecycle_failed(key.trim_start_matches("ws:"), &error)?;
                        } else if key == "export" || key == "reconcile" {
                            self.last_export = Instant::now();
                        } else if let Some(task_id) = task_id {
                            if key.starts_with("stop:")
                                || key.starts_with("cleanup:")
                                || key.starts_with("launch:")
                            { /* uncertain launch/stop: inspect before retry or cleanup */
                            } else if key.starts_with("delivery-close:") {
                                let task = self.task(&task_id)?;
                                if self.delivery_verified(&task)?
                                    && task.autonomous_consent
                                    && !task.memory.halt_requested
                                {
                                    self.store
                                        .open_decision(
                                            &format!(
                                                "delivery-close-readback-{}-{}",
                                                task.task_id, task.memory.merge_retry_generation
                                            ),
                                            &task.task_id,
                                            &task.task_group,
                                            "governance_close_failed",
                                            "Delivery close requires merge receipt reconciliation",
                                            &["Retry close".into(), "Manual reconciliation".into()],
                                            Some(0),
                                            &error,
                                            task.memory
                                                .merge_checkpoint
                                                .as_ref()
                                                .and_then(|cp| cp.merge_sha.as_deref()),
                                        )
                                        .map_err(|e| e.to_string())?;
                                }
                            } else if key.starts_with("merge:") {
                                self.merge_failed(&task_id, &error)?;
                            } else {
                                self.fail_task(&task_id, &error, None)?;
                            }
                        }
                    }
                }
            }
            CoordinatorEvent::DeliveryStore(operation) => operation(&mut self.store),
            CoordinatorEvent::Shutdown => {}
        }
        Ok(())
    }

    fn socket_command(&mut self, command: ClientCommand) -> Result<Vec<ServerMessage>, String> {
        Ok(match command {
            ClientCommand::Status => vec![ServerMessage::Status {
                ok: true,
                status: self.store.status_summary().map_err(|e| e.to_string())?,
            }],
            ClientCommand::Subscribe { group, .. } => {
                let as_of_seq = self.store.max_seq_id().map_err(|e| e.to_string())?;
                vec![ServerMessage::Snapshot {
                    tasks: self
                        .store
                        .list_tasks(group.as_deref())
                        .map_err(|e| e.to_string())?,
                    open_decisions: self
                        .store
                        .list_decisions(true, group.as_deref())
                        .map_err(|e| e.to_string())?,
                    as_of_seq,
                }]
            }
            ClientCommand::GetDecision { decision_id } => vec![ServerMessage::Decision {
                decision: self
                    .store
                    .get_decision(&decision_id)
                    .map_err(|e| e.to_string())?,
            }],
            ClientCommand::Decide {
                decision_id,
                choice,
                by,
                note,
            } => {
                let resolution = self
                    .store
                    .resolve_decision(
                        &decision_id,
                        &choice,
                        by.as_deref().unwrap_or("operator"),
                        note.as_deref(),
                    )
                    .map_err(|e| e.to_string())?;
                match resolution {
                    DecisionResolution::Resolved(decision) => {
                        self.apply_decision(&decision)?;
                        vec![ServerMessage::DecisionResult {
                            outcome: "RESOLVED".into(),
                            decision: Some(decision),
                        }]
                    }
                    DecisionResolution::AlreadyResolved(decision) => {
                        vec![ServerMessage::DecisionResult {
                            outcome: "ALREADY_RESOLVED".into(),
                            decision: Some(decision),
                        }]
                    }
                    DecisionResolution::NotFound => vec![ServerMessage::DecisionResult {
                        outcome: "NOT_FOUND".into(),
                        decision: None,
                    }],
                }
            }
            ClientCommand::Run {
                task,
                group,
                once: _,
            } => {
                self.scope = Some((task, group));
                // `zach run` wakes delivery follow-up through the daemon owner.
                self.last_delivery_poll = Instant::now() - Duration::from_secs(10);
                vec![ServerMessage::RunAccepted { ready: self.ready }]
            }
        })
    }

    fn tick(&mut self) -> Result<(), String> {
        if self.last_heartbeat.elapsed() >= Duration::from_secs(1) {
            self.store
                .record_heartbeat(now_epoch())
                .map_err(|e| e.to_string())?;
            self.store
                .set_meta(
                    "daemon_lease_expires_epoch",
                    &(now_epoch() + 15).to_string(),
                )
                .map_err(|e| e.to_string())?;
            self.last_heartbeat = Instant::now();
        }
        if !self.preflight {
            self.submit(
                "preflight".into(),
                None,
                1,
                Box::new(|| {
                    isolation::verify_host_isolation()?;
                    Ok(WorkerResult::Preflight)
                }),
            );
            return self.deliver_events();
        }
        if !self.reconciled {
            self.reconcile_startup()?;
            return self.deliver_events();
        }
        let sync_secs = std::env::var("ZACH_SYNC_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30)
            .max(1);
        if self.last_export.elapsed() >= Duration::from_secs(sync_secs)
            && !self.jobs.contains("export")
        {
            let ws = self.ws.clone();
            if self.submit(
                "export".into(),
                None,
                2,
                Box::new(move || {
                    let output =
                        ws.execute(&["export".into(), "--sync".into(), "--json".into()])?;
                    Ok(WorkerResult::Export(
                        intake::decode_export_records(&output).map_err(|e| e.to_string())?,
                    ))
                }),
            ) {
                self.last_export = Instant::now();
            }
        }
        self.monitor_attempts()?;
        if !self.synced || self.jobs.contains("export") {
            return self.deliver_events();
        }
        self.reconcile_terminal_tasks()?;
        self.replay_lifecycle()?;
        self.resume_pipeline_steps()?;
        self.resume_decisions()?;
        self.reconcile_terminal_tasks()?;
        let mut recovery_ready = true;
        for task in self.store.list_tasks(None).map_err(|e| e.to_string())? {
            if let Some(id) = &task.active_attempt_id {
                let attempt = self
                    .store
                    .get_stage_attempt(id)
                    .map_err(|e| e.to_string())?;
                if attempt.as_ref().is_some_and(|a| {
                    matches!(a.phase.as_str(), "RUNNING" | "LAUNCH_PENDING")
                        && !self.attached.contains(id)
                }) {
                    recovery_ready = false;
                }
            }
        }
        let was_ready = self.ready;
        self.ready = self.preflight && self.reconciled && self.synced && recovery_ready;
        if self.ready && !was_ready {
            self.send_delivery(SocketDelivery::Ready)?;
        }
        if self.ready {
            self.evaluate_gates()?;
            self.dispatch()?;
            self.drive_merges()?;
            self.poll_deliveries()?;
        }
        self.deliver_events()
    }

    fn reconcile_terminal_tasks(&mut self) -> Result<(), String> {
        for mut task in self.store.list_tasks(None).map_err(|e| e.to_string())? {
            if let Some(recovered) = self
                .store
                .recover_unclosed_delivery(&task.task_id)
                .map_err(|e| e.to_string())?
            {
                task = recovered;
            }
            if !matches!(task.status.as_str(), "Done" | "Cancelled")
                && task.autonomous_consent
                && !task.memory.halt_requested
            {
                continue;
            }
            if self.jobs.iter().any(|key| {
                key.ends_with(&format!(":{}", task.task_id))
                    || task
                        .active_attempt_id
                        .as_ref()
                        .is_some_and(|id| key.ends_with(&format!(":{id}")))
            }) {
                continue;
            }
            if let Some(id) = task.active_attempt_id.clone() {
                let Some(mut attempt) = self
                    .store
                    .get_stage_attempt(&id)
                    .map_err(|e| e.to_string())?
                else {
                    continue;
                };
                if !matches!(attempt.phase.as_str(), "POSTPROCESSING" | "COMPLETE") {
                    continue;
                }
                attempt.phase = "COMPLETE".into();
                self.store
                    .record_stage_attempt(&attempt)
                    .map_err(|e| e.to_string())?;
                task.active_attempt_id = None;
                task.memory.pipeline_checkpoint = None;
                self.save(&task)?;
            }
            if task.status == "Done"
                && (self
                    .store
                    .list_deliveries(Some(&task.task_id))
                    .map_err(|e| e.to_string())?
                    .is_empty()
                    || (task.memory.governance_terminal_observed
                        && self.delivery_receipt_verified(&task)?))
                && task
                    .memory
                    .merge_checkpoint
                    .as_ref()
                    .is_some_and(|c| c.phase == "CLOSE_PENDING" && c.post_merge_verified)
                && let Some(op) = self
                    .store
                    .lifecycle_ops()
                    .map_err(|e| e.to_string())?
                    .iter()
                    .find(|o| {
                        o.task_id == task.task_id && o.kind == "close" && o.state != "ACKNOWLEDGED"
                    })
            {
                self.lifecycle_ack(&op.operation_id, "")?;
            }
            if task.status != "Done"
                && !task.memory.merge_lane_released
                && task.memory.merge_checkpoint.as_ref().is_some_and(|c| {
                    c.merge_sha.is_some()
                        || matches!(
                            c.phase.as_str(),
                            "MERGE_PENDING" | "POST_MERGE_CI" | "CLOSE_PENDING" | "LANE_BLOCKED"
                        )
                })
            {
                continue;
            }
            if task.memory.pipeline_checkpoint.take().is_some() {
                self.save(&task)?;
            }
            self.store
                .release_path_locks(&task.task_id)
                .map_err(|e| e.to_string())?;
            self.store
                .remove_merge_queue_entry(&task.repository, &task.task_id)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn deliver_events(&mut self) -> Result<(), String> {
        let events = self
            .store
            .list_events_since(None, self.last_seq, 128)
            .map_err(|e| e.to_string())?;
        if let Some(last) = events.last() {
            let seq = last.seq_id;
            if self
                .socket_tx
                .try_send(SocketDelivery::Events(events))
                .is_ok()
            {
                self.last_seq = seq;
            }
        }
        Ok(())
    }

    fn startup_ownership(&self) -> Result<BTreeSet<String>, String> {
        self.store
            .list_tasks(None)
            .map_err(|e| e.to_string())?
            .iter()
            .filter_map(|task| match self.store.native_startup_owned(task) {
                Ok(true) => Some(Ok(task.task_id.clone())),
                Ok(false) => None,
                Err(e) => Some(Err(e.to_string())),
            })
            .collect()
    }

    fn reconcile_startup(&mut self) -> Result<(), String> {
        if self.jobs.contains("reconcile") || self.last_export.elapsed() < Duration::from_secs(2) {
            return Ok(());
        }
        // Enumerate as well as inspect exact persisted identities. Dispatch stays disabled.
        self.startup_ownership()?;
        let controller = self.controller.clone();
        let snapshots = self
            .store
            .list_tasks(None)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|task| {
                let attempts = self.store.list_stage_attempts(&task.task_id)?;
                Ok((task, attempts))
            })
            .collect::<Result<Vec<_>, crate::v2::store::V2StoreError>>()
            .map_err(|e| e.to_string())?;
        let state = self.state_dir.clone();
        self.submit(
            "reconcile".into(),
            None,
            1,
            Box::new(move || reconcile_attempt_snapshots(controller.as_ref(), &state, snapshots)),
        );
        Ok(())
    }

    fn task(&self, id: &str) -> Result<TaskRecord, String> {
        self.store
            .get_task(id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("task {id} missing"))
    }
    fn save(&mut self, task: &TaskRecord) -> Result<(), String> {
        self.store.upsert_task(task).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn dispatch(&mut self) -> Result<(), String> {
        let scope = self.scope.take().unwrap_or((None, None));
        let dispatches = scheduler::schedule_scoped_dispatches(
            &mut self.store,
            scope.0.as_deref(),
            scope.1.as_deref(),
        )?;
        for dispatch in dispatches {
            let mut task = self.task(&dispatch.task_id)?;
            if !task.memory.governance_started {
                task.executor = Some("zach".into());
                task.status = "Ready".into();
                let op = LifecycleOperation {
                    attempt_id: None,
                    decision_id: None,
                    operation_id: format!("start-{}", task.task_id),
                    task_id: task.task_id.clone(),
                    kind: "start".into(),
                    args: vec![
                        "start".into(),
                        task.task_id.clone(),
                        "--executor".into(),
                        "zach".into(),
                    ],
                    body_path: None,
                    depends_on: None,
                    state: "PENDING".into(),
                    retry_epoch: 0,
                    attempts: 0,
                    last_error: None,
                };
                self.store
                    .checkpoint_with_lifecycle(&task, &op)
                    .map_err(|e| e.to_string())?;
                continue;
            }
            if dispatch.stage == "impl"
                && let Some(id) = task.memory.suspended_impl_attempt_id.take()
            {
                task.active_attempt_id = Some(id.clone());
                task.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
                    attempt_id: id,
                    operation: "VALIDATE".into(),
                });
                task.lease_owner = Some(self.instance.clone());
                task.lease_expires_epoch = Some(now_epoch() + 30);
                self.save(&task)?;
                continue;
            }
            let id = format!(
                "{}-{}-{}-{}",
                task.task_id.to_ascii_lowercase(),
                dispatch.stage,
                now_epoch(),
                task.version
            );
            task.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
                attempt_id: id,
                operation: "PREPARING".into(),
            });
            task.lease_owner = Some(self.instance.clone());
            task.lease_expires_epoch = Some(now_epoch() + 30);
            self.save(&task)?;
        }
        Ok(())
    }

    fn resume_pipeline_steps(&mut self) -> Result<(), String> {
        for task in self.store.list_tasks(None).map_err(|e| e.to_string())? {
            if !task.autonomous_consent
                || matches!(task.status.as_str(), "Done" | "Cancelled" | "Blocked")
            {
                continue;
            }
            let Some(cp) = task.memory.pipeline_checkpoint.clone() else {
                continue;
            };
            if cp.operation == "PREPARING" {
                let Some(stage) = task.current_stage.clone() else {
                    self.quarantine_task(&task.task_id, "preparation checkpoint lacks a stage")?;
                    continue;
                };
                let author_stage = match stage.as_str() {
                    "plan-review" => Some("plan"),
                    "pr-review" => Some("impl"),
                    _ => None,
                };
                let author = if let Some(stage) = author_stage {
                    self.store
                        .list_stage_attempts(&task.task_id)
                        .map_err(|e| e.to_string())?
                        .into_iter()
                        .rev()
                        .find(|a| a.stage == stage && a.status == "PASSED")
                        .map(|a| infer_model_family(&a.model))
                } else {
                    None
                };
                if author_stage.is_some() && author.is_none() {
                    self.fail_task(
                        &task.task_id,
                        "missing author model for cross-family review",
                        Some("semantic"),
                    )?;
                    continue;
                }
                let state = self.state_dir.clone();
                let task_id = task.task_id.clone();
                self.submit(
                    format!("prepare:{}", task.task_id),
                    Some(task_id),
                    0,
                    Box::new(move || {
                        Ok(WorkerResult::Prepared(pipeline::prepare_supervised_stage(
                            &state,
                            &task,
                            &stage,
                            &cp.attempt_id,
                            author,
                        )?))
                    }),
                );
            } else if cp.operation.starts_with("PUBLISH_") {
                let Some(stage) = task.current_stage.as_deref() else {
                    self.quarantine_task(&task.task_id, "publication checkpoint lacks a stage")?;
                    continue;
                };
                let path = self
                    .state_dir
                    .join("attempts")
                    .join(&cp.attempt_id)
                    .join("stage-evidence.md");
                let sha = if matches!(stage, "plan" | "plan-review") {
                    task.plan_base_sha.as_deref()
                } else {
                    task.reviewed_sha.as_deref()
                };
                let verdict = matches!(stage, "plan-review" | "pr-review")
                    .then(|| cp.operation.trim_start_matches("PUBLISH_"));
                let op = intake::stage_operation(
                    &task,
                    &format!("zach-stage-{}", cp.attempt_id),
                    stage,
                    &path,
                    verdict,
                    sha,
                    "zach",
                );
                self.store
                    .enqueue_lifecycle(&op)
                    .map_err(|e| e.to_string())?;
            } else if matches!(
                cp.operation.as_str(),
                "VALIDATE" | "CHECKS" | "COMMIT" | "PUSH"
            ) {
                let Some(attempt) = self
                    .store
                    .get_stage_attempt(&cp.attempt_id)
                    .map_err(|e| e.to_string())?
                else {
                    continue;
                };
                if attempt.phase != "POSTPROCESSING" {
                    continue;
                }
                if attempt.stage == "impl"
                    && !task
                        .required_stages
                        .iter()
                        .take_while(|s| s.as_str() != "impl")
                        .all(|s| task.stages_completed.contains(s))
                {
                    let mut task = task;
                    task.memory.suspended_impl_attempt_id = Some(attempt.attempt_id);
                    task.active_attempt_id = None;
                    task.memory.pipeline_checkpoint = None;
                    task.status = "Ready".into();
                    task.current_stage = scheduler::determine_next_stage(&task);
                    self.save(&task)?;
                    continue;
                }
                let state = self.state_dir.clone();
                let sem = self.semaphore.clone();
                let id = cp.attempt_id.clone();
                self.submit(
                    format!("pipeline:{id}"),
                    Some(task.task_id.clone()),
                    0,
                    Box::new(move || {
                        Ok(WorkerResult::Pipeline {
                            attempt_id: id,
                            step: pipeline::run_supervised_pipeline_step(
                                &state,
                                &default_ws_task_bin(),
                                task,
                                &attempt,
                                &cp.operation,
                                &sem,
                            )?,
                        })
                    }),
                );
            }
        }
        Ok(())
    }

    fn monitor_attempts(&mut self) -> Result<(), String> {
        for task in self.store.list_tasks(None).map_err(|e| e.to_string())? {
            let Some(id) = task.active_attempt_id.clone() else {
                continue;
            };
            let Some(attempt) = self
                .store
                .get_stage_attempt(&id)
                .map_err(|e| e.to_string())?
            else {
                self.quarantine_task(&task.task_id, "active attempt row is missing")?;
                continue;
            };
            if self.jobs.iter().any(|k| k.ends_with(&format!(":{id}"))) {
                continue;
            }
            if self
                .last_poll
                .get(&id)
                .is_some_and(|t| t.elapsed() < Duration::from_secs(1))
            {
                continue;
            }
            if attempt.systemd_unit.is_none() {
                let state = self.state_dir.clone();
                let job_id = id.clone();
                if self.submit(
                    format!("identity:{id}"),
                    Some(task.task_id.clone()),
                    1,
                    Box::new(move || {
                        Ok(WorkerResult::UnitIdentity {
                            attempt_id: job_id.clone(),
                            manifest: runner::read_attempt_manifest(&state, &job_id)?,
                        })
                    }),
                ) {
                    self.last_poll.insert(id, Instant::now());
                }
                continue;
            }
            if attempt.phase == "HARVESTED" {
                if task
                    .memory
                    .pipeline_checkpoint
                    .as_ref()
                    .is_some_and(|c| c.attempt_id == id && c.operation == "CLEANUP_PENDING")
                {
                    self.submit_cleanup(&attempt)?;
                } else {
                    self.submit_stop(&attempt)?;
                }
                continue;
            }
            if !matches!(
                attempt.phase.as_str(),
                "RUNNING" | "LAUNCH_PENDING" | "EXIT_OBSERVED"
            ) {
                continue;
            }
            if self
                .last_poll
                .get(&id)
                .is_some_and(|t| t.elapsed() < Duration::from_secs(1))
            {
                continue;
            }
            let unit = attempt
                .systemd_unit
                .clone()
                .ok_or("verified unit identity disappeared")?;
            let controller = self.controller.clone();
            let state = self.state_dir.clone();
            let attach = !self.attached.contains(&id);
            let task_id = task.task_id.clone();
            let job_id = id.clone();
            if self.submit(
                format!("observe:{id}"),
                Some(task_id),
                1,
                Box::new(move || {
                    let observed = controller.inspect(&unit)?;
                    let manifest = runner::read_attempt_manifest(&state, &job_id);
                    let mut recovered = None;
                    let mut recovery_error = None;
                    let observed = if let Ok(m) = &manifest {
                        if m.task_id != task.task_id
                            || m.spec.unit_name.trim_end_matches(".service")
                                != unit.trim_end_matches(".service")
                        {
                            recovery_error = Some("attempt manifest identity mismatch".into());
                        }
                        if attach
                            && observed.state()? == UnitState::Running
                            && recovery_error.is_none()
                        {
                            match PreparedResources::recover(
                                &m.attempt_dir,
                                m.route.family,
                                m.spec.network,
                            ) {
                                Ok(r) => recovered = Some(r),
                                Err(e) => recovery_error = Some(e),
                            }
                        }
                        runner::sample_attempt(m, observed)
                    } else {
                        observed
                    };
                    Ok(WorkerResult::Observed {
                        attempt_id: job_id,
                        observation: observed,
                        recovered,
                        manifest,
                        recovery_error,
                    })
                }),
            ) {
                self.last_poll.insert(id, Instant::now());
            }
        }
        Ok(())
    }

    fn submit_stop(&mut self, attempt: &StageAttemptRecord) -> Result<(), String> {
        let id = attempt.attempt_id.clone();
        let unit = attempt.systemd_unit.clone().ok_or("missing unit to stop")?;
        let controller = self.controller.clone();
        let failed = attempt.status != "PASSED" || attempt.exit_code != Some(0);
        self.submit(
            format!("stop:{id}"),
            Some(attempt.task_id.clone()),
            1,
            Box::new(move || {
                controller.stop(&unit)?;
                let observation = controller.inspect(&unit)?;
                match observation.state()? {
                    UnitState::Missing | UnitState::Dead | UnitState::Failed => {}
                    _ => return Err("stop not confirmed; retaining resources".into()),
                }
                if failed {
                    controller.reset_failed(&unit)?;
                }
                Ok(WorkerResult::UnitStopped {
                    attempt_id: id,
                    observation,
                })
            }),
        );
        Ok(())
    }

    fn submit_cleanup(&mut self, attempt: &StageAttemptRecord) -> Result<(), String> {
        let id = attempt.attempt_id.clone();
        let unit = attempt.systemd_unit.clone().ok_or("missing stop unit")?;
        let dir = self.state_dir.join("attempts").join(&id);
        let controller = self.controller.clone();
        // UnitStopped was persisted before taking the registry handle. Queue
        // saturation can now drop a listener safely because execution has ended.
        let resources = self.resources.remove(&id);
        let failed = attempt.exit_code != Some(0) || attempt.status != "PASSED";
        self.submit(
            format!("cleanup:{id}"),
            Some(attempt.task_id.clone()),
            1,
            Box::new(move || {
                runner::stop_and_cleanup(controller.as_ref(), &unit, &dir, resources, failed)?;
                Ok(WorkerResult::Stopped(id))
            }),
        );
        Ok(())
    }

    fn worker_result(&mut self, result: WorkerResult) -> Result<(), String> {
        match result {
            WorkerResult::Preflight => self.preflight = true,
            WorkerResult::StartupReconciled { adopted, retired } => {
                self.startup_ownership()?;
                for attempt in retired {
                    self.store
                        .record_stage_attempt(&attempt)
                        .map_err(|e| e.to_string())?;
                    let mut task = self.task(&attempt.task_id)?;
                    if task.active_attempt_id.as_deref() == Some(&attempt.attempt_id) {
                        if attempt.failure_class.is_some()
                            && !task.stages_completed.contains(&attempt.stage)
                        {
                            self.fail_task(
                                &task.task_id,
                                attempt
                                    .summary
                                    .as_deref()
                                    .unwrap_or("interrupted failure handling"),
                                attempt.failure_class.as_deref(),
                            )?;
                            continue;
                        }
                        task.active_attempt_id = None;
                        task.memory.pipeline_checkpoint = None;
                        if matches!(
                            task.status.as_str(),
                            "Planning" | "Plan Review" | "In Progress" | "PR Review"
                        ) && task.stages_completed.contains(&attempt.stage)
                        {
                            task.status = "Ready".into();
                        }
                        self.save(&task)?;
                    }
                }
                for attempt in adopted {
                    let mut task = self.task(&attempt.task_id)?;
                    task.active_attempt_id = Some(attempt.attempt_id.clone());
                    task.current_stage = Some(attempt.stage.clone());
                    task.lease_owner = Some(self.instance.clone());
                    task.lease_expires_epoch = Some(now_epoch() + 30);
                    let stale_postprocessing = attempt.phase == "POSTPROCESSING"
                        && task.memory.pipeline_checkpoint.as_ref().is_some_and(|c| {
                            !matches!(
                                c.operation.as_str(),
                                "VALIDATE" | "CHECKS" | "COMMIT" | "PUSH"
                            ) && !c.operation.starts_with("PUBLISH_")
                        });
                    if task.memory.pipeline_checkpoint.is_none() || stale_postprocessing {
                        task.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
                            attempt_id: attempt.attempt_id.clone(),
                            operation: if attempt.phase == "POSTPROCESSING" {
                                "VALIDATE"
                            } else {
                                "LAUNCH_PENDING"
                            }
                            .into(),
                        });
                    }
                    self.save(&task)?;
                    self.store
                        .record_stage_attempt(&attempt)
                        .map_err(|e| e.to_string())?;
                }
                self.worker_result(WorkerResult::Reconciled)?;
            }
            WorkerResult::DeliveryPolled => {}
            WorkerResult::Reconciled => {
                // Prove every exclusion before the first cleanup/lock/failure write.
                let native = self.startup_ownership()?;
                self.reconciled = true;
                for lock in self
                    .store
                    .list_path_locks(None)
                    .map_err(|e| e.to_string())?
                {
                    if let Some(task) = self
                        .store
                        .get_task(&lock.task_id)
                        .map_err(|e| e.to_string())?
                    {
                        if task.active_attempt_id.is_none()
                            && task.memory.merge_checkpoint.is_none()
                            && task.status != "Queued for Merge"
                            && !(task.status == "Blocked"
                                && task
                                    .current_stage
                                    .as_deref()
                                    .is_some_and(|s| s.starts_with("human-")))
                        {
                            self.store
                                .release_path_locks(&task.task_id)
                                .map_err(|e| e.to_string())?;
                        }
                    } else {
                        self.store
                            .release_path_locks(&lock.task_id)
                            .map_err(|e| e.to_string())?;
                    }
                }
                for task in self.store.list_tasks(None).map_err(|e| e.to_string())? {
                    let owns = native.contains(&task.task_id)
                        && (task.active_attempt_id.is_some()
                            || matches!(
                                task.status.as_str(),
                                "Planning"
                                    | "Plan Review"
                                    | "In Progress"
                                    | "PR Review"
                                    | "Queued for Merge"
                            )
                            || (task.memory.merge_checkpoint.is_some()
                                && !task.memory.merge_lane_released)
                            || (task.status == "Blocked"
                                && task
                                    .current_stage
                                    .as_deref()
                                    .is_some_and(|s| s.starts_with("human-"))));
                    if owns
                        && !self
                            .store
                            .acquire_path_locks(&task.repository, &["*".into()], &task.task_id)
                            .map_err(|e| e.to_string())?
                    {
                        self.store.open_decision(&format!("ownership-conflict-{}",task.task_id),&task.task_id,&task.task_group,"repository_ownership_conflict","Multiple active tasks own this repository",&["Abort task".into(),"Manual reconciliation".into()],Some(0),"No further dispatch is permitted until live workers and repository ownership are reconciled",task.reviewed_sha.as_deref()).map_err(|e|e.to_string())?;
                    }
                }
                for mut task in self.store.list_tasks(None).map_err(|e| e.to_string())? {
                    if !native.contains(&task.task_id) {
                        continue;
                    }
                    if matches!(
                        task.status.as_str(),
                        "Planning" | "Plan Review" | "In Progress" | "PR Review"
                    ) && task.active_attempt_id.is_none()
                        && task.memory.pipeline_checkpoint.is_none()
                    {
                        self.fail_task(
                            &task.task_id,
                            "ORPHAN_LOST: interrupted pre-attempt transition",
                            Some("infra"),
                        )?;
                    } else if task
                        .memory
                        .pipeline_checkpoint
                        .as_ref()
                        .is_some_and(|c| c.operation == "PREPARING")
                        && task.active_attempt_id.is_none()
                    {
                        // No unit can launch until prepare_launch has committed its row.
                        task.status = "Ready".into();
                        task.memory.pipeline_checkpoint = None;
                        self.save(&task)?;
                    }
                }
            }
            WorkerResult::Export(output) => {
                // External terminal changes and consent revocations are observed
                // before any dispatch. Live attempts keep ownership until stopped.
                intake::ingest_task_records(&mut self.store, output).map_err(|e| e.to_string())?;
                self.synced = true;
            }
            WorkerResult::Prepared(prepared) => {
                let PreparedLaunch {
                    manifest,
                    resources,
                } = prepared;
                let mut task = self.task(&manifest.task_id)?;
                if task
                    .memory
                    .pipeline_checkpoint
                    .as_ref()
                    .is_none_or(|c| c.attempt_id != manifest.attempt_id)
                    || !task.autonomous_consent
                    || matches!(task.status.as_str(), "Done" | "Cancelled" | "Blocked")
                {
                    resources.cleanup_after_stop()?;
                    return Ok(());
                }
                let started = now_epoch();
                let attempt = StageAttemptRecord {
                    attempt_id: manifest.attempt_id.clone(),
                    task_id: task.task_id.clone(),
                    stage: manifest.route.stage.clone(),
                    model: manifest.route.model.clone(),
                    effort: manifest.route.effort.as_str().into(),
                    systemd_unit: Some(manifest.spec.unit_name.clone()),
                    invocation_id: None,
                    started_epoch: started,
                    ended_epoch: None,
                    status: "RUNNING".into(),
                    failure_class: None,
                    summary: None,
                    input_tokens: None,
                    output_tokens: None,
                    total_tokens: None,
                    sha_before: Some(manifest.sha_before.clone()),
                    sha_after: None,
                    phase: "LAUNCH_PENDING".into(),
                    last_liveness_epoch: started,
                    last_output_bytes: 0,
                    last_cpu_usage_usec: None,
                    control_group: None,
                    exit_code: None,
                    exit_code_kind: None,
                    retry_generation: task.memory.retry_generation,
                };
                task.active_attempt_id = Some(manifest.attempt_id.clone());
                if task.plan_base_sha.is_none() {
                    task.plan_base_sha = Some(manifest.sha_before.clone());
                    task.context_pack.base_sha = task.plan_base_sha.clone();
                }
                task.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
                    attempt_id: manifest.attempt_id.clone(),
                    operation: "LAUNCH_PENDING".into(),
                });
                self.store
                    .prepare_launch(&task, &attempt)
                    .map_err(|e| e.to_string())?;
                let id = manifest.attempt_id.clone();
                self.resources.insert(id.clone(), resources);
                self.attached.insert(id.clone());
                self.manifests.insert(id.clone(), manifest.clone());
                let controller = self.controller.clone();
                // This follows the durable launch intent. A missed queue submission
                // becomes a bounded missing-unit observation, never a duplicate start.
                self.submit(
                    format!("launch:{id}"),
                    Some(task.task_id),
                    0,
                    Box::new(move || {
                        controller.launch(&manifest)?;
                        Ok(WorkerResult::Launched(id))
                    }),
                );
            }
            WorkerResult::Launched(id) => {
                // --no-block acknowledges only the manager job. Keep the durable
                // startup phase until inspection proves running or exited.
                self.last_poll.remove(&id);
            }
            WorkerResult::Observed {
                attempt_id,
                observation,
                recovered,
                manifest,
                recovery_error,
            } => self.observed(
                &attempt_id,
                observation,
                recovered,
                manifest,
                recovery_error,
            )?,
            WorkerResult::Harvested { attempt_id, result } => {
                let Some(mut attempt) = self
                    .store
                    .get_stage_attempt(&attempt_id)
                    .map_err(|e| e.to_string())?
                else {
                    return Ok(());
                };
                let mut task = self.task(&attempt.task_id)?;
                match result {
                    Ok(result) => {
                        attempt.status = result.status.clone();
                        attempt.summary = Some(result.summary.clone());
                        attempt.input_tokens = result.input_tokens;
                        attempt.output_tokens = result.output_tokens;
                        attempt.total_tokens = result.total_tokens;
                        attempt.sha_after = result.sha_after;
                        if let Some(tokens) = result.total_tokens {
                            let previous = self
                                .store
                                .list_stage_attempts(&task.task_id)
                                .map_err(|e| e.to_string())?
                                .iter()
                                .filter(|a| {
                                    a.stage == attempt.stage && a.attempt_id != attempt.attempt_id
                                })
                                .filter_map(|a| a.total_tokens)
                                .sum::<u64>();
                            task.memory
                                .token_usage_by_stage
                                .insert(attempt.stage.clone(), previous.saturating_add(tokens));
                        }
                        self.save(&task)?;
                    }
                    Err(error) => {
                        attempt.status = "FAILED".into();
                        if attempt.failure_class.is_none() {
                            attempt.failure_class = Some(
                                pipeline::classify_failure_class(&attempt.stage, "FAILED", &error)
                                    .into(),
                            );
                        }
                        attempt.summary = Some(error);
                    }
                }
                attempt.phase = "HARVESTED".into();
                attempt.ended_epoch = Some(now_epoch());
                self.store
                    .record_stage_attempt(&attempt)
                    .map_err(|e| e.to_string())?;
            }
            WorkerResult::UnitIdentity {
                attempt_id,
                manifest,
            } => {
                let Some(mut attempt) = self
                    .store
                    .get_stage_attempt(&attempt_id)
                    .map_err(|e| e.to_string())?
                else {
                    return Ok(());
                };
                if manifest.task_id != attempt.task_id || manifest.route.stage != attempt.stage {
                    return self
                        .quarantine_task(&attempt.task_id, "manifest does not match attempt");
                }
                attempt.systemd_unit = Some(manifest.spec.unit_name);
                attempt.sha_before = attempt.sha_before.or(Some(manifest.sha_before));
                self.store
                    .record_stage_attempt(&attempt)
                    .map_err(|e| e.to_string())?;
            }
            WorkerResult::UnitStopped {
                attempt_id: id,
                observation,
            } => {
                if let Some(mut attempt) = self
                    .store
                    .get_stage_attempt(&id)
                    .map_err(|e| e.to_string())?
                {
                    let mut task = self.task(&attempt.task_id)?;
                    if !observation.exit_code_kind.is_empty() && observation.exit_code_kind != "0" {
                        attempt.exit_code_kind = Some(observation.exit_code_kind);
                        attempt.exit_code = observation.exit_code;
                    }
                    task.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
                        attempt_id: id,
                        operation: "CLEANUP_PENDING".into(),
                    });
                    self.store
                        .transition_attempt(&task, &attempt, false, None)
                        .map_err(|e| e.to_string())?;
                }
            }
            WorkerResult::Stopped(id) => {
                let Some(mut attempt) = self
                    .store
                    .get_stage_attempt(&id)
                    .map_err(|e| e.to_string())?
                else {
                    return Ok(());
                };
                self.attached.remove(&id);
                self.manifests.remove(&id);
                let mut task = self.task(&attempt.task_id)?;
                if !task.autonomous_consent
                    || task.memory.halt_requested
                    || matches!(task.status.as_str(), "Done" | "Cancelled")
                {
                    attempt.phase = "COMPLETE".into();
                    task.active_attempt_id = None;
                    task.memory.pipeline_checkpoint = None;
                    if !matches!(task.status.as_str(), "Done" | "Cancelled") {
                        task.status = "Blocked".into();
                    }
                    self.store
                        .transition_attempt(&task, &attempt, true, None)
                        .map_err(|e| e.to_string())?;
                } else if attempt.status != "PASSED" {
                    self.fail_task(
                        &attempt.task_id,
                        attempt.summary.as_deref().unwrap_or("worker failed"),
                        attempt.failure_class.as_deref(),
                    )?;
                } else {
                    attempt.phase = "POSTPROCESSING".into();
                    task.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
                        attempt_id: id,
                        operation: "VALIDATE".into(),
                    });
                    self.store
                        .transition_attempt(&task, &attempt, false, None)
                        .map_err(|e| e.to_string())?;
                }
            }
            WorkerResult::Pipeline { attempt_id, step } => {
                let current = self.task(&step.task.task_id)?;
                if current.active_attempt_id.as_deref() != Some(&attempt_id)
                    || current.lease_owner.as_deref() != Some(&self.instance)
                    || current.memory.retry_generation != step.task.memory.retry_generation
                {
                    return Ok(());
                }
                if !current.autonomous_consent
                    || current.memory.halt_requested
                    || matches!(current.status.as_str(), "Done" | "Cancelled")
                {
                    return Ok(());
                }
                let mut task = step.task;
                task.memory.governance_started = current.memory.governance_started;
                task.memory.applied_decisions = current.memory.applied_decisions;
                task.memory.decisions_log = current.memory.decisions_log;
                task.lease_owner = current.lease_owner;
                task.lease_expires_epoch = current.lease_expires_epoch;
                if step.next_operation == "PLAN_PREREQUISITES" {
                    task.memory.suspended_impl_attempt_id = Some(attempt_id);
                    task.memory.pipeline_checkpoint = None;
                    task.active_attempt_id = None;
                    task.status = "Ready".into();
                    task.current_stage = scheduler::determine_next_stage(&task);
                    self.save(&task)?;
                    return Ok(());
                }
                task.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
                    attempt_id,
                    operation: step.next_operation,
                });
                if let Some(op) = step.publication {
                    self.store
                        .checkpoint_with_lifecycle(&task, &op)
                        .map_err(|e| e.to_string())?;
                } else {
                    self.save(&task)?;
                }
            }
            WorkerResult::Lifecycle {
                operation_id,
                output,
            } => self.lifecycle_ack(&operation_id, &output)?,
            WorkerResult::Merge { task_id, result } => self.merge_result(&task_id, result)?,
        }
        Ok(())
    }

    fn observed(
        &mut self,
        id: &str,
        observation: UnitObservation,
        recovered: Option<PreparedResources>,
        manifest: Result<AttemptManifest, String>,
        recovery_error: Option<String>,
    ) -> Result<(), String> {
        let Some(mut attempt) = self
            .store
            .get_stage_attempt(id)
            .map_err(|e| e.to_string())?
        else {
            return Ok(());
        };
        let mut task = self.task(&attempt.task_id)?;
        task.lease_owner = Some(self.instance.clone());
        task.lease_expires_epoch = Some(now_epoch() + 30);
        self.save(&task)?;
        let observed_state = observation.state()?;
        let known_dead_exit = observed_state == UnitState::Dead
            && matches!(
                observation.exit_code_kind.as_str(),
                "1" | "2" | "3" | "exited" | "killed" | "dumped"
            )
            && observation.exit_code.is_some()
            && !observation.result.is_empty();
        let state = if known_dead_exit {
            UnitState::Exited
        } else {
            observed_state
        };
        let identity_conflict = attempt
            .invocation_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .is_some_and(|saved| {
                !observation.invocation_id.is_empty() && saved != observation.invocation_id
            });
        if !identity_conflict && !observation.invocation_id.is_empty() {
            attempt.invocation_id = Some(observation.invocation_id.clone());
        }
        let changed_cgroup =
            attempt.control_group.as_deref() != Some(observation.control_group.as_str());
        if !observation.control_group.is_empty() {
            attempt.control_group = Some(observation.control_group.clone());
        }
        attempt.exit_code = observation.exit_code;
        attempt.exit_code_kind = Some(observation.exit_code_kind.clone());
        if matches!(
            observation.result.as_str(),
            "timeout" | "resources" | "start-limit-hit"
        ) || matches!(
            observation.exit_code_kind.as_str(),
            "2" | "3" | "killed" | "dumped"
        ) {
            attempt.failure_class = Some("infra".into());
        }
        if let Some(resources) = recovered {
            self.resources.insert(id.to_owned(), resources);
        }
        if let Ok(manifest) = &manifest {
            self.manifests.insert(id.to_owned(), manifest.clone());
        }
        let force_reason = if identity_conflict {
            Some("InvocationID identity conflict".to_owned())
        } else if !task.autonomous_consent
            || task.memory.halt_requested
            || matches!(task.status.as_str(), "Done" | "Cancelled")
        {
            Some("autonomous_consent revoked or external terminal change".into())
        } else if state == UnitState::Running {
            recovery_error.or_else(|| manifest.as_ref().err().cloned())
        } else {
            None
        };
        if let Some(reason) = force_reason {
            attempt.status = "LOST".into();
            attempt.failure_class = Some("infra".into());
            attempt.summary = Some(reason);
            attempt.phase = "HARVESTED".into();
            attempt.ended_epoch = Some(now_epoch());
        } else {
            match state {
                UnitState::Running => {
                    let attaching = self.attached.insert(id.into());
                    let output_progress = observation.output_bytes > attempt.last_output_bytes;
                    let cpu_progress =
                        match (attempt.last_cpu_usage_usec, observation.cpu_usage_usec) {
                            (Some(old), Some(new)) => new > old,
                            _ => false,
                        };
                    let fresh_cpu = changed_cgroup
                        || matches!(
                            (attempt.last_cpu_usage_usec, observation.cpu_usage_usec),
                            (None, Some(_))
                        )
                        || matches!((attempt.last_cpu_usage_usec,observation.cpu_usage_usec),(Some(old),Some(new)) if new<old);
                    if attaching || output_progress || cpu_progress || fresh_cpu {
                        attempt.last_liveness_epoch = now_epoch();
                    }
                    // Unavailable counters are observation faults, never zero CPU.
                    if observation.cpu_usage_usec.is_none() {
                        let faults = self.observation_faults.entry(id.into()).or_default();
                        *faults += 1;
                        if *faults >= 10 {
                            attempt.status = "FAILED".into();
                            attempt.failure_class = Some("infra".into());
                            attempt.summary = Some(
                                "persistent cgroup observation fault; no stall inferred".into(),
                            );
                            attempt.phase = "HARVESTED".into();
                            attempt.ended_epoch = Some(now_epoch());
                            self.store
                                .record_stage_attempt(&attempt)
                                .map_err(|e| e.to_string())?;
                            return Ok(());
                        }
                    } else {
                        self.observation_faults.remove(id);
                    }
                    let timeout = manifest
                        .as_ref()
                        .map(|m| m.spec.stall_timeout_secs)
                        .unwrap_or(300) as i64;
                    if observation.cpu_usage_usec.is_some()
                        && attempt.last_cpu_usage_usec.is_some()
                        && !fresh_cpu
                        && now_epoch() - attempt.last_liveness_epoch >= timeout
                    {
                        attempt.status = "STALLED".into();
                        attempt.failure_class = Some("infra".into());
                        attempt.summary = Some("STALLED: no output and no CPU progress".into());
                        attempt.phase = "HARVESTED".into();
                        attempt.ended_epoch = Some(now_epoch());
                    } else {
                        attempt.phase = "RUNNING".into();
                    }
                    attempt.last_output_bytes = observation.output_bytes;
                    attempt.last_cpu_usage_usec = observation.cpu_usage_usec;
                }
                UnitState::Exited | UnitState::Failed => {
                    attempt.phase = "EXIT_OBSERVED".into();
                    attempt.ended_epoch = Some(now_epoch());
                    self.store
                        .record_stage_attempt(&attempt)
                        .map_err(|e| e.to_string())?;
                    match manifest {
                        Ok(manifest) => {
                            let id = id.to_owned();
                            self.submit(
                                format!("harvest:{id}"),
                                Some(task.task_id),
                                0,
                                Box::new(move || {
                                    Ok(WorkerResult::Harvested {
                                        attempt_id: id,
                                        result: runner::harvest_detached(&manifest, &observation),
                                    })
                                }),
                            );
                        }
                        Err(error) => {
                            attempt.status = "LOST".into();
                            attempt.failure_class = Some("infra".into());
                            attempt.summary = Some(error);
                            attempt.phase = "HARVESTED".into();
                        }
                    }
                }
                UnitState::Missing | UnitState::Dead => {
                    if attempt.phase == "LAUNCH_PENDING" && now_epoch() - attempt.started_epoch < 15
                    {
                        return Ok(());
                    }
                    attempt.status = "LOST".into();
                    attempt.failure_class = Some("infra".into());
                    attempt.summary =
                        Some("ORPHAN_LOST: unit not found without harvest receipt".into());
                    attempt.phase = "HARVESTED".into();
                    attempt.ended_epoch = Some(now_epoch());
                }
                UnitState::Starting => {
                    if now_epoch() - attempt.started_epoch > 30 {
                        attempt.status = "LOST".into();
                        attempt.failure_class = Some("infra".into());
                        attempt.summary = Some("unit startup observation timeout".into());
                        attempt.phase = "HARVESTED".into();
                    }
                }
                UnitState::Stopping => {}
            }
        }
        self.store
            .record_stage_attempt(&attempt)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn quarantine_task(&mut self, id: &str, error: &str) -> Result<(), String> {
        let task = self.task(id)?;
        self.store
            .open_decision(
                &format!(
                    "checkpoint-{}-{}",
                    task.task_id, task.memory.retry_generation
                ),
                &task.task_id,
                &task.task_group,
                "checkpoint_unverifiable",
                "Task recovery metadata requires reconciliation",
                &["Manual reconciliation".into(), "Abort task".into()],
                Some(0),
                error,
                task.reviewed_sha.as_deref(),
            )
            .map_err(|e| e.to_string())?;
        if task.active_attempt_id.is_none() && task.memory.merge_checkpoint.is_none() {
            self.store
                .release_path_locks(id)
                .map_err(|e| e.to_string())?;
            self.store
                .remove_merge_queue_entry(&task.repository, id)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn fail_task(&mut self, task_id: &str, error: &str, class: Option<&str>) -> Result<(), String> {
        let mut task = self.task(task_id)?;
        let stage = task.current_stage.clone().unwrap_or_else(|| "impl".into());
        let class =
            class.unwrap_or_else(|| pipeline::classify_failure_class(&stage, "FAILED", error));
        let attempts = self
            .store
            .list_stage_attempts(task_id)
            .map_err(|e| e.to_string())?;
        let active = task
            .active_attempt_id
            .as_deref()
            .and_then(|id| attempts.iter().find(|a| a.attempt_id == id))
            .cloned();
        let mut attempt = active.unwrap_or_else(|| StageAttemptRecord {
            attempt_id: format!("recovery-{}-{}-{}", task.task_id, now_epoch(), task.version),
            task_id: task.task_id.clone(),
            stage: stage.clone(),
            model: "unknown".into(),
            effort: "unknown".into(),
            systemd_unit: None,
            invocation_id: None,
            started_epoch: now_epoch(),
            ended_epoch: None,
            status: if error.contains("ORPHAN_LOST") {
                "LOST"
            } else {
                "FAILED"
            }
            .into(),
            failure_class: None,
            summary: None,
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
            sha_before: None,
            sha_after: None,
            phase: "COMPLETE".into(),
            last_liveness_epoch: now_epoch(),
            last_output_bytes: 0,
            last_cpu_usage_usec: None,
            control_group: None,
            exit_code: None,
            exit_code_kind: None,
            retry_generation: task.memory.retry_generation,
        });
        if matches!(attempt.status.as_str(), "RUNNING" | "PASSED") {
            attempt.status = "FAILED".into();
        }
        attempt.failure_class = Some(class.into());
        attempt.summary = Some(error.into());
        attempt.ended_epoch = Some(now_epoch());
        attempt.phase = "COMPLETE".into();
        let failures = attempts
            .iter()
            .filter(|a| {
                a.attempt_id != attempt.attempt_id
                    && a.stage == stage
                    && a.retry_generation == task.memory.retry_generation
                    && a.failure_class.as_deref() == Some(class)
            })
            .count()
            + 1;
        let limit = match class {
            "infra" => pipeline::MAX_INFRA_RETRIES,
            "semantic" => pipeline::MAX_SEMANTIC_RETRIES,
            _ => pipeline::MAX_POLICY_RETRIES,
        };
        task.retry_count += 1;
        task.active_attempt_id = None;
        task.memory.pipeline_checkpoint = None;
        task.lease_owner = None;
        task.lease_expires_epoch = None;
        task.memory.last_check_failure = Some(runner::truncate_utf8_bytes(error, 1024));
        let decision = if failures <= limit {
            task.status = "Ready".into();
            task.next_retry_epoch = now_epoch() + pipeline::retry_backoff(failures);
            None
        } else {
            task.status = "Blocked".into();
            let kind = if class == "policy" {
                "scope_violation"
            } else {
                "retries_exhausted"
            };
            Some(crate::v2::store::FailureDecision {
                decision_id: format!(
                    "{kind}-{}-{}-{}",
                    task.task_id, stage, task.memory.retry_generation
                ),
                kind: kind.into(),
                question: format!("{} failed; choose how to proceed", task.task_id),
                options: vec!["Retry stage".into(), "Abort task".into()],
                context: error.into(),
                sha: task.reviewed_sha.clone(),
            })
        };
        self.store
            .transition_attempt(&task, &attempt, true, decision.as_ref())
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn replay_lifecycle(&mut self) -> Result<(), String> {
        let ops = self.store.lifecycle_ops().map_err(|e| e.to_string())?;
        for op in &ops {
            if op.state != "PENDING" || op.retry_epoch > now_epoch() {
                continue;
            }
            if ops
                .iter()
                .take_while(|o| o.operation_id != op.operation_id)
                .any(|o| o.task_id == op.task_id && o.state != "ACKNOWLEDGED")
            {
                continue;
            }
            if op.depends_on.as_ref().is_some_and(|id| {
                !ops.iter()
                    .any(|o| &o.operation_id == id && o.state == "ACKNOWLEDGED")
            }) {
                continue;
            }
            let task = self.task(&op.task_id)?;
            if op.kind == "close"
                && !self
                    .store
                    .list_deliveries(Some(&task.task_id))
                    .map_err(|e| e.to_string())?
                    .is_empty()
                && !self.delivery_verified(&task)?
            {
                continue;
            }

            let negative_human = op.kind.starts_with("human-")
                && op
                    .args
                    .windows(2)
                    .any(|args| args[0] == "--verdict" && args[1] == "CHANGES_REQUESTED");
            if !task.autonomous_consent
                || (task.memory.halt_requested && !negative_human)
                || task.status == "Cancelled"
                || (task.status == "Done"
                    && !(op.kind == "close" && self.delivery_verified(&task)?))
            {
                self.store
                    .update_lifecycle(
                        &op.operation_id,
                        "FAILED",
                        Some("publication intent superseded by task stop/terminal state"),
                        0,
                    )
                    .map_err(|e| e.to_string())?;
                continue;
            }
            let decision = op
                .decision_id
                .as_deref()
                .map(|id| self.store.get_decision(id))
                .transpose()
                .map_err(|e| e.to_string())?
                .flatten();
            let state = self.state_dir.clone();
            let ws = self.ws.clone();
            let operation = op.clone();
            let key = format!("ws:{}", op.operation_id);
            if self.submit(
                key,
                Some(op.task_id.clone()),
                2,
                Box::new(move || {
                    if let Some(decision) = &decision {
                        let path = prepare_human_evidence(&state, decision)?;
                        if operation.body_path.as_deref() != path.to_str() {
                            return Err("human evidence path does not match durable intent".into());
                        }
                    }
                    let mut args = operation.args;
                    // Recover a successful remote start whose local receipt was lost.
                    if operation.kind == "start" && operation.attempts > 0 {
                        let export =
                            ws.execute(&["export".into(), "--sync".into(), "--json".into()])?;
                        let export: intake::ExportContract =
                            serde_json::from_str(&export).map_err(|e| e.to_string())?;
                        if let Some(task) = export.tasks.iter().find(|t| t.id == operation.task_id)
                            && task.executor.as_deref() == Some("zach")
                            && matches!(
                                task.status.as_str(),
                                "Planning"
                                    | "Plan Review"
                                    | "In Progress"
                                    | "PR Review"
                                    | "Blocked"
                            )
                        {
                            args.push("--resume".into());
                        }
                    }
                    let output = ws.execute(&args)?;
                    let output = if operation.kind == "close" {
                        String::new()
                    } else {
                        serde_json::to_string(&intake::parse_start_receipt(
                            &output,
                            &operation.task_id,
                        )?)
                        .map_err(|e| e.to_string())?
                    };
                    Ok(WorkerResult::Lifecycle {
                        operation_id: operation.operation_id,
                        output,
                    })
                }),
            ) {
                self.store
                    .update_lifecycle(&op.operation_id, "IN_FLIGHT", None, 0)
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    fn lifecycle_failed(&mut self, id: &str, error: &str) -> Result<(), String> {
        let Some(op) = self
            .store
            .lifecycle_ops()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|o| o.operation_id == id)
        else {
            return Ok(());
        };
        if op.state == "ACKNOWLEDGED" {
            return Ok(());
        }
        let current = self.task(&op.task_id)?;
        if !current.autonomous_consent
            || current.memory.halt_requested
            || current.status == "Cancelled"
            || (current.status == "Done"
                && !(op.kind == "close" && self.delivery_verified(&current)?))
        {
            self.store
                .update_lifecycle(id, "FAILED", Some(error), 0)
                .map_err(|e| e.to_string())?;
            return Ok(());
        }
        let failed = op.kind == "close" || op.attempts >= 3;
        self.store
            .update_lifecycle(
                id,
                if failed { "FAILED" } else { "PENDING" },
                Some(error),
                now_epoch() + pipeline::retry_backoff(op.attempts as usize),
            )
            .map_err(|e| e.to_string())?;
        if failed {
            let task = self.task(&op.task_id)?;
            let (kind, option) = if op.kind == "close" {
                ("governance_close_failed", "Retry close")
            } else {
                ("governance_publication_failed", "Retry publication")
            };
            self.store
                .open_decision(
                    &format!("publication-{}-{}", op.operation_id, op.attempts),
                    &task.task_id,
                    &task.task_group,
                    kind,
                    "Governance write-back failed",
                    &[option.into(), "Manual reconciliation".into()],
                    Some(0),
                    error,
                    task.reviewed_sha.as_deref(),
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn lifecycle_ack(&mut self, id: &str, output: &str) -> Result<(), String> {
        let op = self
            .store
            .lifecycle_ops()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|o| o.operation_id == id)
            .ok_or("unknown lifecycle operation")?;
        if op.state == "ACKNOWLEDGED" {
            return Ok(());
        }
        // Receipt and local transition commit atomically after external acknowledgment.
        let mut task = self.task(&op.task_id)?;
        if op.kind != "close"
            && (!task.autonomous_consent
                || task.memory.halt_requested
                || matches!(task.status.as_str(), "Done" | "Cancelled"))
        {
            self.store
                .acknowledge_lifecycle(&task, &op, op.attempt_id.as_deref())
                .map_err(|e| e.to_string())?;
            return Ok(());
        }
        if op.kind != "close" && output.trim().is_empty() && !cfg!(test) {
            return Err("Governance publication returned no structured receipt".into());
        }
        if op.kind != "close" && !output.trim().is_empty() {
            let receipt = intake::parse_start_receipt(output, &task.task_id)?;
            if !matches!(receipt["weight"].as_str(), Some("XS" | "S" | "M" | "L")) {
                return Err("Governance receipt lacks a valid weight".into());
            }
            if op.args.first().is_some_and(|a| a == "stage") {
                if receipt["stage"].as_str() != op.args.get(2).map(String::as_str) {
                    return Err("Governance stage receipt identity mismatch".into());
                }
                if let Some(sha) = op
                    .args
                    .windows(2)
                    .find(|args| args[0] == "--sha")
                    .map(|args| args[1].as_str())
                    && receipt["sha"].as_str() != Some(sha)
                {
                    return Err("Governance receipt SHA mismatch".into());
                }
            }
            if let Some(weight) = receipt["weight"].as_str().filter(|weight| {
                pipeline::weight_rank(weight) > pipeline::weight_rank(&task.weight)
            }) {
                task.weight = weight.into();
                task.context_pack.weight = weight.into();
                task.required_stages = intake::default_required_stages(weight);
            }
        }
        let mut completed_attempt = None;
        match op.kind.as_str() {
            "start" => {
                let value = intake::parse_start_receipt(output, &task.task_id)?;
                task.branch = Some(
                    value["branch"]
                        .as_str()
                        .ok_or("start missing canonical branch")?
                        .into(),
                );
                task.worktree_path = Some(
                    value["worktree"]
                        .as_str()
                        .ok_or("start missing canonical worktree")?
                        .into(),
                );
                if let Some(weight) = value["weight"].as_str().filter(|weight| {
                    pipeline::weight_rank(weight) > pipeline::weight_rank(&task.weight)
                }) {
                    task.weight = weight.into();
                    task.context_pack.weight = task.weight.clone();
                    task.required_stages = intake::default_required_stages(weight);
                }
                task.memory.governance_started = true;
                task.executor = Some("zach".into());
                task.status = "Ready".into();
            }
            "human-plan-approval" | "human-merge-approval" => {
                let decision_id = id
                    .strip_prefix("decision-")
                    .ok_or("invalid human publication identity")?;
                let decision = self
                    .store
                    .get_decision(decision_id)
                    .map_err(|e| e.to_string())?
                    .ok_or("human decision missing")?;
                let current_sha = if op.kind == "human-plan-approval" {
                    task.plan_base_sha.as_deref()
                } else {
                    task.reviewed_sha.as_deref()
                };
                let expected_id = format!(
                    "human-{}-{}-{}-{}-{}-p{}-r{}",
                    task.task_id,
                    decision.kind,
                    current_sha.unwrap_or(""),
                    task.memory.plan_rework_count,
                    task.memory.review_rework_count,
                    task.memory.plan_rework_generation,
                    task.memory.review_rework_generation
                );
                if decision.sha.as_deref() != current_sha || decision.decision_id != expected_id {
                    task.memory
                        .applied_decisions
                        .push(decision.decision_id.clone());
                    self.store
                        .acknowledge_lifecycle(&task, &op, None)
                        .map_err(|e| e.to_string())?;
                    return self.error_event(
                        Some(&task.task_id),
                        "stale human approval acknowledgment ignored",
                    );
                }
                if decision.choice.as_deref() == Some("Approve") {
                    if !task.stages_completed.contains(&op.kind) {
                        task.stages_completed.push(op.kind.clone());
                    }
                    task.status = if task.memory.merge_checkpoint.is_some() {
                        "Queued for Merge"
                    } else {
                        "Ready"
                    }
                    .into();
                } else if decision.choice.as_deref() == Some("Request Changes") {
                    self.review_rework(
                        &mut task,
                        if op.kind == "human-plan-approval" {
                            "plan-review"
                        } else {
                            "pr-review"
                        },
                    )?;
                }
                if !task
                    .memory
                    .applied_decisions
                    .contains(&decision.decision_id)
                {
                    task.memory.applied_decisions.push(decision.decision_id);
                }
            }
            "merge-parity" => {
                let target = task
                    .memory
                    .merge_checkpoint
                    .as_ref()
                    .ok_or("missing merge checkpoint")?
                    .target_sha
                    .clone();
                task.reviewed_sha = Some(target.clone());
                task.memory.last_pr_review_evidence_sha = Some(target.clone());
                task.memory
                    .merge_checkpoint
                    .as_mut()
                    .ok_or("missing checkpoint")?
                    .phase = "PUSH".into();

                if task.weight == "L" {
                    task.stages_completed
                        .retain(|s| s != "human-merge-approval");
                    task.status = "Ready".into();
                }
            }
            "close" => {
                if task
                    .memory
                    .merge_checkpoint
                    .as_ref()
                    .is_none_or(|c| c.phase != "CLOSE_PENDING" || !c.post_merge_verified)
                {
                    return Err("close acknowledgment without merge receipt".into());
                }
                task.status = "Done".into();
                task.current_stage = None;
                task.active_attempt_id = None;
            }
            stage => {
                let cp = task
                    .memory
                    .pipeline_checkpoint
                    .clone()
                    .ok_or("publication missing pipeline checkpoint")?;
                if cp.operation == "PUBLISH_CHANGES_REQUESTED" {
                    self.review_rework(&mut task, stage)?;
                } else {
                    if !task.stages_completed.iter().any(|s| s == stage) {
                        task.stages_completed.push(stage.into());
                    }
                    task.status = "Ready".into();
                }
                completed_attempt = Some(cp.attempt_id);
                task.active_attempt_id = None;
                task.memory.pipeline_checkpoint = None;
            }
        }
        self.store
            .acknowledge_lifecycle(&task, &op, completed_attempt.as_deref())
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn review_rework(&mut self, task: &mut TaskRecord, stage: &str) -> Result<(), String> {
        if task
            .memory
            .merge_checkpoint
            .as_ref()
            .is_some_and(|c| c.merge_sha.is_some())
        {
            return Err("cannot request implementation rework after merge".into());
        }
        task.memory.merge_checkpoint = None;
        self.store
            .remove_merge_queue_entry(&task.repository, &task.task_id)
            .map_err(|e| e.to_string())?;
        let planning = stage == "plan-review";
        if planning {
            task.memory.approved_plan = None;
            task.memory.approved_plan_artifact_path = None;
        } else {
            task.reviewed_sha = None;
            task.memory.last_pr_review_evidence = None;
            task.memory.last_pr_review_evidence_sha = None;
        }
        let count = if planning {
            &mut task.memory.plan_rework_count
        } else {
            &mut task.memory.review_rework_count
        };
        let exhausted = *count >= pipeline::MAX_REVIEW_REWORK_LOOPS;
        if !exhausted {
            *count += 1;
        }
        task.stages_completed.retain(|s| {
            if planning {
                false
            } else {
                matches!(s.as_str(), "plan" | "plan-review" | "human-plan-approval")
            }
        });
        task.current_stage = Some(if planning { "plan" } else { "impl" }.into());
        if exhausted {
            task.status = "Blocked".into();
            let kind = if planning {
                "plan_rework_limit"
            } else {
                "review_rework_limit"
            };
            self.store
                .open_decision(
                    &format!(
                        "{kind}-{}-{}-{}-{}",
                        task.task_id,
                        task.memory.retry_generation,
                        task.memory.plan_rework_generation,
                        task.memory.review_rework_generation
                    ),
                    &task.task_id,
                    &task.task_group,
                    kind,
                    "Review rework limit reached",
                    &["Authorize additional rework".into(), "Abort task".into()],
                    Some(0),
                    "Valid CHANGES_REQUESTED reviews use a separate rework budget",
                    task.reviewed_sha.as_deref(),
                )
                .map_err(|e| e.to_string())?;
            self.store
                .release_path_locks(&task.task_id)
                .map_err(|e| e.to_string())?;
        } else {
            task.status = "Ready".into();
        }
        Ok(())
    }

    fn evaluate_gates(&mut self) -> Result<(), String> {
        for mut task in self.store.list_tasks(None).map_err(|e| e.to_string())? {
            let stale_gate_wait = task.status == "Blocked"
                && !task.memory.halt_requested
                && task
                    .current_stage
                    .as_deref()
                    .is_some_and(|s| s.starts_with("human-"))
                && !self
                    .store
                    .list_decisions(true, None)
                    .map_err(|e| e.to_string())?
                    .iter()
                    .any(|d| d.task_id == task.task_id);
            if (task.status != "Ready" && !stale_gate_wait)
                || task.next_retry_epoch > now_epoch()
                || !task.autonomous_consent
                || self
                    .store
                    .has_pending_lifecycle(&task.task_id)
                    .map_err(|e| e.to_string())?
            {
                continue;
            }
            match scheduler::determine_next_stage(&task).as_deref() {
                Some(stage @ ("human-plan-approval" | "human-merge-approval")) => {
                    let stage = stage.to_owned();
                    if !self
                        .store
                        .acquire_path_locks(&task.repository, &["*".into()], &task.task_id)
                        .map_err(|e| e.to_string())?
                    {
                        continue;
                    }
                    let Some(sha) = (if stage == "human-plan-approval" {
                        task.plan_base_sha.clone()
                    } else {
                        task.reviewed_sha.clone()
                    }) else {
                        self.quarantine_task(&task.task_id, "human gate lacks its bound SHA")?;
                        continue;
                    };
                    let decision_id = format!(
                        "human-{}-{}-{}-{}-{}-p{}-r{}",
                        task.task_id,
                        stage,
                        sha,
                        task.memory.plan_rework_count,
                        task.memory.review_rework_count,
                        task.memory.plan_rework_generation,
                        task.memory.review_rework_generation
                    );
                    task.current_stage = Some(stage.clone());
                    task.status = "Blocked".into();
                    self.save(&task)?;
                    if self
                        .store
                        .get_decision(&decision_id)
                        .map_err(|e| e.to_string())?
                        .is_none()
                    {
                        self.store
                            .open_decision(
                                &decision_id,
                                &task.task_id,
                                &task.task_group,
                                &stage,
                                &format!("Approve {stage} for {} at {sha}?", task.task_id),
                                &[
                                    "Approve".into(),
                                    "Request Changes".into(),
                                    "Reject".into(),
                                    "Abort task".into(),
                                ],
                                Some(0),
                                "Approval is bound to the current plan/review SHA",
                                Some(&sha),
                            )
                            .map_err(|e| e.to_string())?;
                    }
                }
                None => {
                    let (Some(sha), Some(pr)) = (task.reviewed_sha.clone(), task.pr_number) else {
                        self.quarantine_task(
                            &task.task_id,
                            "finished pipeline lacks its reviewed SHA or PR",
                        )?;
                        continue;
                    };
                    if !self
                        .store
                        .acquire_path_locks(&task.repository, &["*".into()], &task.task_id)
                        .map_err(|e| e.to_string())?
                    {
                        continue;
                    }
                    self.store
                        .enqueue_merge_queue(&task.repository, &task.task_id, pr, &sha)
                        .map_err(|e| e.to_string())?;
                    task.status = "Queued for Merge".into();
                    task.memory.merge_lane_released = false;
                    task.current_stage = Some("merge".into());
                    if task.memory.merge_checkpoint.is_none() {
                        task.memory.merge_checkpoint = Some(MergeCheckpoint {
                            phase: "MERGE_DEFAULT".into(),
                            target_sha: sha,
                            pr_number: pr,
                            merge_sha: None,
                            post_merge_verified: false,
                            phase_started_epoch: now_epoch(),
                        });
                    }
                    self.save(&task)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn resume_decisions(&mut self) -> Result<(), String> {
        for decision in self
            .store
            .list_decisions(false, None)
            .map_err(|e| e.to_string())?
        {
            if decision.status == "RESOLVED"
                && !self
                    .task(&decision.task_id)?
                    .memory
                    .applied_decisions
                    .contains(&decision.decision_id)
                && let Err(error) = self.apply_decision(&decision)
            {
                self.error_event(Some(&decision.task_id), &error)?;
            }
        }
        Ok(())
    }

    fn apply_decision(
        &mut self,
        decision: &crate::v2::store::PendingDecisionRecord,
    ) -> Result<(), String> {
        let mut task = self.task(&decision.task_id)?;
        if task
            .memory
            .applied_decisions
            .contains(&decision.decision_id)
        {
            return Ok(());
        }
        if matches!(
            decision.kind.as_str(),
            "new_apk_required" | "prod_promotion_approval" | "delivery_contract_error"
        ) {
            // resolve_decision already atomically applied the delivery transition.
            task.memory
                .applied_decisions
                .push(decision.decision_id.clone());
            return self.save(&task);
        }
        let choice = decision
            .choice
            .as_deref()
            .ok_or("resolved decision lacks choice")?;
        if matches!(
            decision.kind.as_str(),
            "human-plan-approval" | "human-merge-approval"
        ) {
            let sha = if decision.kind == "human-plan-approval" {
                task.plan_base_sha.as_deref()
            } else {
                task.reviewed_sha.as_deref()
            };
            let expected_id = format!(
                "human-{}-{}-{}-{}-{}-p{}-r{}",
                task.task_id,
                decision.kind,
                sha.unwrap_or(""),
                task.memory.plan_rework_count,
                task.memory.review_rework_count,
                task.memory.plan_rework_generation,
                task.memory.review_rework_generation
            );
            if decision.sha.as_deref() != sha || decision.decision_id != expected_id {
                task.memory
                    .applied_decisions
                    .push(decision.decision_id.clone());
                self.save(&task)?;
                return self.error_event(
                    Some(&task.task_id),
                    "stale human decision; current SHA differs",
                );
            }
            runner::validate_attempt_id(&decision.decision_id)?;
            let path = self
                .state_dir
                .join("decisions")
                .join(format!("{}.md", decision.decision_id));
            let op = intake::stage_operation(
                &task,
                &format!("decision-{}", decision.decision_id),
                &decision.kind,
                &path,
                Some(if choice == "Approve" {
                    "APPROVED"
                } else {
                    "CHANGES_REQUESTED"
                }),
                sha,
                decision
                    .resolved_by
                    .as_deref()
                    .ok_or("human actor missing")?,
            );
            self.store
                .enqueue_lifecycle(&op)
                .map_err(|e| e.to_string())?;
            if !matches!(choice, "Approve" | "Request Changes") {
                task.memory.halt_requested = true;
                task.memory
                    .applied_decisions
                    .push(decision.decision_id.clone());
                self.save(&task)?;
                self.store
                    .release_path_locks(&task.task_id)
                    .map_err(|e| e.to_string())?;
                self.store
                    .remove_merge_queue_entry(&task.repository, &task.task_id)
                    .map_err(|e| e.to_string())?;
            }
            return Ok(());
        }
        match choice {
            "Retry stage" => {
                task.memory.halt_requested = false;
                if task.active_attempt_id.is_some() {
                    return Err("cannot retry while an attempt still needs cleanup".into());
                }
                task.memory.retry_generation += 1;
                task.memory.retry_reset_epoch = now_epoch();
                task.next_retry_epoch = 0;
                task.status = "Ready".into();
            }
            "Retry merge" => {
                task.memory.merge_lane_released = false;
                task.memory.merge_retry_count = 0;
                task.memory.merge_retry_generation += 1;
                task.next_retry_epoch = 0;
                if task.memory.merge_checkpoint.as_ref().is_some_and(|c| {
                    matches!(
                        c.phase.as_str(),
                        "MERGE_PENDING" | "POST_MERGE_CI" | "CLOSE_PENDING" | "LANE_BLOCKED"
                    )
                }) {
                    return Err("merge receipt requires checkpoint-specific recovery".into());
                }
                task.status = "Queued for Merge".into();
                if !self
                    .store
                    .acquire_path_locks(&task.repository, &["*".into()], &task.task_id)
                    .map_err(|e| e.to_string())?
                {
                    task.status = "Ready".into();
                    task.memory.merge_checkpoint = None;
                } else {
                    self.store
                        .enqueue_merge_queue(
                            &task.repository,
                            &task.task_id,
                            task.pr_number.ok_or("missing retry PR")?,
                            task.reviewed_sha.as_deref().ok_or("missing retry SHA")?,
                        )
                        .map_err(|e| e.to_string())?;
                }
            }
            "Retry close" | "Retry publication" => {
                if decision.decision_id.starts_with("delivery-close-readback-") {
                    task.memory.merge_retry_generation += 1;
                    self.merge_poll.remove(&task.task_id);
                }
                for op in self
                    .store
                    .lifecycle_ops()
                    .map_err(|e| e.to_string())?
                    .iter()
                    .filter(|o| {
                        o.task_id == task.task_id
                            && o.state == "FAILED"
                            && decision
                                .decision_id
                                .starts_with(&format!("publication-{}-", o.operation_id))
                    })
                {
                    self.store
                        .update_lifecycle(&op.operation_id, "PENDING", None, 0)
                        .map_err(|e| e.to_string())?;
                }
                task.status = if matches!(
                    task.status.as_str(),
                    "Done" | "Cancelled" | "Delivery Aborted"
                ) {
                    task.status.as_str()
                } else if choice == "Retry close" && self.delivery_verified(&task)? {
                    "Delivery Pending"
                } else if task.memory.merge_checkpoint.is_some() {
                    "Queued for Merge"
                } else {
                    "In Progress"
                }
                .into();
            }
            "Authorize additional rework" => {
                if decision.kind == "plan_rework_limit" {
                    task.memory.plan_rework_count = 0;
                    task.memory.plan_rework_generation += 1;
                } else if decision.kind == "review_rework_limit" {
                    task.memory.review_rework_count = 0;
                    task.memory.review_rework_generation += 1;
                } else {
                    return Err("decision does not authorize review budget reset".into());
                }
                task.status = "Ready".into();
            }
            "Record merge SHA manually" => {
                let sha=decision.note.as_deref().map(str::trim).filter(|sha|sha.len()==40&&sha.bytes().all(|b|b.is_ascii_hexdigit())).ok_or("manual merge SHA must be a full 40-character hexadecimal SHA in the decision note")?;
                let cp = task
                    .memory
                    .merge_checkpoint
                    .as_mut()
                    .filter(|cp| cp.phase == "LANE_BLOCKED" && cp.merge_sha.is_none())
                    .ok_or("manual SHA does not apply to this merge checkpoint")?;
                cp.merge_sha = Some(sha.into());
                cp.phase = "POST_MERGE_CI".into();
                cp.phase_started_epoch = now_epoch();
                if !self
                    .store
                    .acquire_path_locks(&task.repository, &["*".into()], &task.task_id)
                    .map_err(|e| e.to_string())?
                {
                    return Err("repository lane is currently owned by another task".into());
                }
                task.memory.merge_lane_released = false;
                task.status = "Queued for Merge".into();
                self.store
                    .update_merge_queue_state(&task.repository, &task.task_id, "QUEUED")
                    .map_err(|e| e.to_string())?;
            }
            "Unblock lane" | "Ignore failure and unblock" => {
                task.memory.merge_lane_released = true;
                // Explicit lane acknowledgment releases only this lane; the task
                // remains blocked for manual reconciliation of its merge receipt.
                self.store
                    .remove_merge_queue_entry(&task.repository, &task.task_id)
                    .map_err(|e| e.to_string())?;
                self.store
                    .release_path_locks(&task.task_id)
                    .map_err(|e| e.to_string())?;
                task.status = "Blocked".into();
            }
            _ => {
                if decision.decision_id.starts_with("delivery-close-readback-") {
                    task.memory.halt_requested = true;
                }
                if matches!(choice, "Abort task" | "Reject" | "Cancel / Block") {
                    task.memory.halt_requested = true;
                }
                task.status = "Blocked".into();
                if task.active_attempt_id.is_none()
                    && task.memory.merge_checkpoint.as_ref().is_none_or(|c| {
                        c.merge_sha.is_none()
                            && c.phase != "MERGE_PENDING"
                            && c.phase != "CLOSE_PENDING"
                    })
                {
                    task.memory.merge_checkpoint = None;
                    task.memory.merge_lane_released = true;
                    self.store
                        .remove_merge_queue_entry(&task.repository, &task.task_id)
                        .map_err(|e| e.to_string())?;
                    self.store
                        .release_path_locks(&task.task_id)
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        task.memory
            .applied_decisions
            .push(decision.decision_id.clone());
        self.save(&task)
    }

    fn delivery_verified(&self, task: &TaskRecord) -> Result<bool, String> {
        Ok(task.status == "Delivery Pending" && self.delivery_receipt_verified(task)?)
    }

    fn delivery_receipt_verified(&self, task: &TaskRecord) -> Result<bool, String> {
        let rows = self
            .store
            .list_deliveries(Some(&task.task_id))
            .map_err(|e| e.to_string())?;
        Ok(!rows.is_empty()
            && rows.iter().all(|r| r.state == "verified")
            && task.memory.merge_checkpoint.as_ref().is_some_and(|cp| {
                cp.post_merge_verified
                    && rows
                        .iter()
                        .all(|row| Some(&row.merge_sha) == cp.merge_sha.as_ref())
            })
            && self
                .store
                .delivery_verification_recorded(&task.task_id, &rows[0].merge_sha)
                .map_err(|e| e.to_string())?)
    }

    fn poll_deliveries(&mut self) -> Result<(), String> {
        // Recover the small gap between the durable handoff and lane release.
        for mut task in self.store.list_tasks(None).map_err(|e| e.to_string())? {
            if let Some(recovered) = self
                .store
                .recover_unclosed_delivery(&task.task_id)
                .map_err(|e| e.to_string())?
            {
                task = recovered;
            }
            let rows = self
                .store
                .list_deliveries(Some(&task.task_id))
                .map_err(|e| e.to_string())?;
            if rows.is_empty() {
                continue;
            }
            self.store
                .release_path_locks(&task.task_id)
                .map_err(|e| e.to_string())?;
            self.store
                .remove_merge_queue_entry(&task.repository, &task.task_id)
                .map_err(|e| e.to_string())?;
            if !self.delivery_verified(&task)?
                || !task.autonomous_consent
                || task.memory.halt_requested
            {
                continue;
            }
            let Some(cp) = task.memory.merge_checkpoint.as_mut() else {
                continue;
            };
            if !matches!(cp.phase.as_str(), "DELIVERY_PENDING" | "CLOSE_PENDING")
                || self
                    .store
                    .lifecycle_ops()
                    .map_err(|e| e.to_string())?
                    .iter()
                    .any(|op| op.task_id == task.task_id && op.kind == "close")
                || self
                    .store
                    .list_decisions(true, Some(&task.task_group))
                    .map_err(|e| e.to_string())?
                    .iter()
                    .any(|d| d.task_id == task.task_id && d.kind == "governance_close_failed")
                || self
                    .merge_poll
                    .get(&task.task_id)
                    .is_some_and(|time| time.elapsed() < Duration::from_secs(2))
            {
                continue;
            }
            cp.phase = "CLOSE_PENDING".into();
            self.save(&task)?;
            let state = self.state_dir.clone();
            let sem = self.semaphore.clone();
            let id = task.task_id.clone();
            if self.submit(
                format!("delivery-close:{id}"),
                Some(id.clone()),
                0,
                Box::new(move || {
                    let result =
                        merge_queue::run_merge_phase(&state, &task, &mut SystemMergeDriver, &sem)?;
                    match result {
                        MergePhaseResult::Publication(_) => Ok(WorkerResult::Merge {
                            task_id: task.task_id,
                            result,
                        }),
                        MergePhaseResult::LaneBlocked(reason) => Err(reason),
                        _ => Err("delivery close did not verify the saved merge receipt".into()),
                    }
                }),
            ) {
                self.merge_poll.insert(id, Instant::now());
            }
        }
        if self.last_delivery_poll.elapsed() < Duration::from_secs(2)
            || self.jobs.contains("post-merge-deliveries")
            || self
                .store
                .list_deliveries(None)
                .map_err(|e| e.to_string())?
                .is_empty()
        {
            return Ok(());
        }
        #[cfg(test)]
        if let Some(driver) = self.rehearsal_delivery.clone() {
            self.submit_delivery_poll(tests::SharedRehearsalDelivery(driver));
            return Ok(());
        }
        self.submit_delivery_poll(SystemDeliveryDriver);
        Ok(())
    }

    fn submit_delivery_poll(&mut self, mut driver: impl delivery::DeliveryDriver + Send + 'static) {
        let commands = self.commands.clone();
        #[cfg(test)]
        let progress = self.rehearsal_poll_progress.clone();
        if self.submit(
            "post-merge-deliveries".into(),
            None,
            0,
            Box::new(move || {
                #[cfg(test)]
                if let Some(p) = &progress {
                    p[0].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                delivery::poll_post_merge_deliveries(
                    &mut CoordinatorDeliveryStore { commands },
                    &mut driver,
                )?;
                #[cfg(test)]
                if let Some(p) = &progress {
                    p[1].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Ok(WorkerResult::DeliveryPolled)
            }),
        ) {
            self.last_delivery_poll = Instant::now();
        }
    }

    fn drive_merges(&mut self) -> Result<(), String> {
        if self.jobs.iter().any(|k| k.starts_with("merge:")) {
            return Ok(());
        }
        for entry in self
            .store
            .list_merge_queue(None)
            .map_err(|e| e.to_string())?
        {
            let task = self.task(&entry.task_id)?;
            if task.status != "Queued for Merge"
                || task.memory.merge_lane_released
                || task.next_retry_epoch > now_epoch()
                || !task.autonomous_consent
                || self
                    .store
                    .has_pending_lifecycle(&task.task_id)
                    .map_err(|e| e.to_string())?
            {
                continue;
            }
            if self
                .merge_poll
                .get(&task.task_id)
                .is_some_and(|t| t.elapsed() < Duration::from_secs(2))
            {
                continue;
            }
            if !self
                .store
                .acquire_path_locks(&task.repository, &["*".into()], &task.task_id)
                .map_err(|e| e.to_string())?
            {
                continue;
            }
            let state = self.state_dir.clone();
            let sem = self.semaphore.clone();
            let id = task.task_id.clone();
            if self.submit(
                format!("merge:{id}"),
                Some(id.clone()),
                0,
                Box::new(move || {
                    Ok(WorkerResult::Merge {
                        task_id: task.task_id.clone(),
                        result: merge_queue::run_merge_phase(
                            &state,
                            &task,
                            &mut SystemMergeDriver,
                            &sem,
                        )?,
                    })
                }),
            ) {
                self.merge_poll.insert(id, Instant::now());
                break;
            }
        }
        Ok(())
    }

    fn merge_result(&mut self, id: &str, result: MergePhaseResult) -> Result<(), String> {
        let mut task = self.task(id)?;
        match result {
            MergePhaseResult::Advanced(mut checkpoint) => {
                checkpoint.phase_started_epoch = now_epoch();
                task.memory.merge_checkpoint = Some(checkpoint);
                self.save(&task)?;
            }
            MergePhaseResult::Waiting(mut checkpoint) => {
                if checkpoint.phase_started_epoch == 0 {
                    checkpoint.phase_started_epoch = now_epoch();
                }
                if now_epoch() - checkpoint.phase_started_epoch
                    >= merge_queue::CiPollConfig::from_env().timeout.as_secs() as i64
                {
                    if checkpoint.merge_sha.is_some() {
                        return self.merge_result(
                            id,
                            MergePhaseResult::LaneBlocked(
                                "post-merge CI observation timed out".into(),
                            ),
                        );
                    }
                    return self.merge_failed(id, "exact-SHA CI observation timed out");
                }
                task.memory.merge_checkpoint = Some(checkpoint);
                self.save(&task)?;
            }
            MergePhaseResult::DeliveryHandoff {
                checkpoint,
                deliveries,
            } => {
                task.memory.merge_checkpoint = Some(checkpoint);
                task.memory.merge_lane_released = true;
                if !matches!(
                    task.status.as_str(),
                    "Done" | "Cancelled" | "Delivery Aborted"
                ) {
                    task.status = "Delivery Pending".into();
                }
                task.current_stage = None;
                task.active_attempt_id = None;
                self.store
                    .save_deliveries_and_task(&task, &deliveries)
                    .map_err(|e| e.to_string())?;
                self.store
                    .release_path_locks(id)
                    .map_err(|e| e.to_string())?;
                self.store
                    .remove_merge_queue_entry(&task.repository, id)
                    .map_err(|e| e.to_string())?;
            }
            MergePhaseResult::Publication(op) => {
                if op.kind == "close"
                    && !self
                        .store
                        .list_deliveries(Some(id))
                        .map_err(|e| e.to_string())?
                        .is_empty()
                    && !self.delivery_verified(&task)?
                {
                    return Ok(());
                }

                self.store
                    .enqueue_lifecycle(&op)
                    .map_err(|e| e.to_string())?;
            }
            MergePhaseResult::Rereview(reason) => {
                let cycles = task
                    .memory
                    .recent_attempts
                    .iter()
                    .filter(|s| s.starts_with("[MERGE_REREVIEW]"))
                    .count();
                if cycles >= merge_queue::MAX_REREVIEW_CYCLES {
                    return self.merge_failed(id, &reason);
                }
                pipeline::push_bounded_recent_attempt(
                    &mut task,
                    format!("[MERGE_REREVIEW] {reason}"),
                );
                let has_review = task.required_stages.iter().any(|s| s == "pr-review");
                task.stages_completed.retain(|s| {
                    s != "pr-review" && s != "human-merge-approval" && (has_review || s != "impl")
                });
                if let Some(checkpoint) = &task.memory.merge_checkpoint {
                    task.reviewed_sha = Some(checkpoint.target_sha.clone());
                }
                task.memory.merge_checkpoint = None;
                task.status = "Ready".into();
                self.store
                    .remove_merge_queue_entry(&task.repository, &task.task_id)
                    .map_err(|e| e.to_string())?;
                self.save(&task)?;
            }
            MergePhaseResult::LaneBlocked(reason) => {
                if let Some(checkpoint) = task.memory.merge_checkpoint.as_mut() {
                    checkpoint.phase = "LANE_BLOCKED".into();
                }
                task.status = "Blocked".into();
                task.memory.merge_lane_released = false;
                let mut options = vec!["Manual reconciliation".into(), "Unblock lane".into()];
                if task
                    .memory
                    .merge_checkpoint
                    .as_ref()
                    .is_some_and(|c| c.merge_sha.is_none())
                {
                    options.insert(0, "Record merge SHA manually".into());
                }
                let decision = crate::v2::store::FailureDecision {
                    decision_id: format!("lane-{id}-{}", task.memory.merge_retry_generation),
                    kind: "post_merge_failure".into(),
                    question: "Repository lane requires manual reconciliation".into(),
                    options,
                    context: reason,
                    sha: task.reviewed_sha.clone(),
                };
                self.store
                    .transition_task(&task, None, false, Some(&decision))
                    .map_err(|e| e.to_string())?;
                self.store
                    .update_merge_queue_state(&task.repository, id, "MERGE_QUEUE_BLOCKED")
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    fn merge_failed(&mut self, id: &str, error: &str) -> Result<(), String> {
        let mut task = self.task(id)?;
        let close = task
            .memory
            .merge_checkpoint
            .as_ref()
            .is_some_and(|c| c.phase == "CLOSE_PENDING");
        let uncertain = task.memory.merge_checkpoint.as_ref().is_some_and(|c| {
            c.merge_sha.is_some()
                || matches!(
                    c.phase.as_str(),
                    "MERGE_PENDING" | "POST_MERGE_CI" | "LANE_BLOCKED"
                )
        });
        let class = pipeline::classify_failure_class("merge", "FAILED", error);
        if !close
            && !uncertain
            && task.weight != "L"
            && class != "policy"
            && task.memory.merge_retry_count < merge_queue::MAX_MERGE_RETRIES as u32
        {
            task.memory.merge_retry_count += 1;
            task.retry_count += 1;
            task.next_retry_epoch =
                now_epoch() + pipeline::retry_backoff(task.memory.merge_retry_count as usize);
            task.status = "Ready".into();
            task.memory.merge_lane_released = true;
            // Executed merge checks/conflicts need implementation rework; transport
            // failures resume their saved merge phase after reacquiring the lane.
            if class == "semantic" || error.to_ascii_lowercase().contains("conflict") {
                task.memory.merge_checkpoint = None;
                task.stages_completed.retain(|s| {
                    matches!(s.as_str(), "plan" | "plan-review" | "human-plan-approval")
                });
                task.current_stage = Some("impl".into());
            }
            task.memory.last_check_failure = Some(runner::truncate_utf8_bytes(error, 1024));
            return self
                .store
                .transition_task(&task, None, true, None)
                .map_err(|e| e.to_string());
        }
        task.status = "Blocked".into();
        task.memory.merge_lane_released = !uncertain && !close;
        let options = if close {
            vec!["Retry close".into(), "Manual reconciliation".into()]
        } else if uncertain {
            vec!["Manual reconciliation".into(), "Unblock lane".into()]
        } else {
            vec!["Retry merge".into(), "Abort task".into()]
        };
        let decision = crate::v2::store::FailureDecision {
            decision_id: format!(
                "merge-error-{id}-{}-{}-{}",
                task.memory.retry_generation,
                task.memory.merge_retry_count,
                task.memory.merge_retry_generation
            ),
            kind: if close {
                "governance_close_failed"
            } else {
                "merge_failed"
            }
            .into(),
            question: "Merge operation failed".into(),
            options,
            context: error.into(),
            sha: task.reviewed_sha.clone(),
        };
        self.store
            .transition_task(&task, None, !uncertain && !close, Some(&decision))
            .map_err(|e| e.to_string())
    }
}

fn reconcile_attempt_snapshots(
    controller: &dyn UnitController,
    state: &Path,
    snapshots: Vec<(TaskRecord, Vec<StageAttemptRecord>)>,
) -> Result<WorkerResult, String> {
    let mut known = BTreeSet::new();
    let mut adopted = Vec::new();
    let mut retired = Vec::new();
    for (task, attempts) in snapshots {
        let selected = task.active_attempt_id.clone().or_else(|| {
            attempts
                .iter()
                .rev()
                .find(|a| {
                    a.phase != "COMPLETE"
                        && task.memory.suspended_impl_attempt_id.as_deref() != Some(&a.attempt_id)
                        && !task.stages_completed.contains(&a.stage)
                        && task.current_stage.as_deref() == Some(&a.stage)
                })
                .map(|a| a.attempt_id.clone())
        });
        for mut attempt in attempts {
            let Some(unit) = attempt.systemd_unit.as_deref() else {
                continue;
            };
            if selected.as_deref() == Some(&attempt.attempt_id) && attempt.phase == "COMPLETE" {
                runner::stop_and_cleanup(
                    controller,
                    unit,
                    &state.join("attempts").join(&attempt.attempt_id),
                    None,
                    true,
                )?;
                if attempt.status == "PASSED" && !task.stages_completed.contains(&attempt.stage) {
                    attempt.phase = "POSTPROCESSING".into();
                    adopted.push(attempt);
                } else {
                    retired.push(attempt);
                }
            } else if selected.as_deref() == Some(&attempt.attempt_id)
                && attempt.phase != "COMPLETE"
            {
                // Inspect exact identities even if list-units omits them. The
                // monitor restores listeners only after this recovery barrier.
                let observed = controller.inspect(unit)?;
                if attempt
                    .invocation_id
                    .as_deref()
                    .filter(|id| !id.is_empty())
                    .is_some_and(|saved| {
                        !observed.invocation_id.is_empty() && saved != observed.invocation_id
                    })
                {
                    attempt.status = "LOST".into();
                    attempt.failure_class = Some("infra".into());
                    attempt.summary = Some("InvocationID identity conflict during startup".into());
                    attempt.phase = "HARVESTED".into();
                } else if attempt.phase == "POSTPROCESSING"
                    && matches!(
                        observed.state()?,
                        UnitState::Running | UnitState::Starting | UnitState::Stopping
                    )
                {
                    runner::stop_and_cleanup(
                        controller,
                        unit,
                        &state.join("attempts").join(&attempt.attempt_id),
                        None,
                        false,
                    )?;
                }
                known.insert(format!("{}.service", unit.trim_end_matches(".service")));
                if attempt.ended_epoch.is_some()
                    && attempt.status == "PASSED"
                    && attempt.phase == "RUNNING"
                {
                    let dir = state.join("attempts").join(&attempt.attempt_id);
                    if let Ok(bytes) = std::fs::read(dir.join("result.json")) {
                        let value: serde_json::Value =
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                        if let Some(result) = value.get("result") {
                            runner::write_secure_file(
                                &dir.join("harvest.json"),
                                &serde_json::to_vec(result).map_err(|e| e.to_string())?,
                            )?;
                            attempt.phase = "HARVESTED".into();
                        }
                    }
                }
                adopted.push(attempt);
            } else if task.memory.suspended_impl_attempt_id.as_deref() == Some(&attempt.attempt_id)
            {
                // This stopped implementation is waiting for escalated planning
                // and human prerequisites; retain its validated output checkpoint.
                if matches!(
                    attempt.phase.as_str(),
                    "RUNNING" | "LAUNCH_PENDING" | "EXIT_OBSERVED"
                ) {
                    return Err("suspended implementation was not confirmed stopped".into());
                }
            } else if attempt.phase != "COMPLETE" {
                runner::stop_and_cleanup(
                    controller,
                    unit,
                    &state.join("attempts").join(&attempt.attempt_id),
                    None,
                    true,
                )?;
                attempt.phase = "COMPLETE".into();
                if attempt.ended_epoch.is_none() {
                    attempt.status = "LOST".into();
                    attempt.failure_class = Some("infra".into());
                    attempt.summary = Some(
                        "ORPHAN_LOST: superseded attempt stopped during reconciliation".into(),
                    );
                    attempt.ended_epoch = Some(now_epoch());
                }
                retired.push(attempt);
            }
        }
        if task.active_attempt_id.is_none()
            && let Some(cp) = task
                .memory
                .pipeline_checkpoint
                .as_ref()
                .filter(|c| c.operation == "PREPARING")
            && let Ok(manifest) = runner::read_attempt_manifest(state, &cp.attempt_id)
        {
            runner::stop_and_cleanup(
                controller,
                &manifest.spec.unit_name,
                &manifest.attempt_dir,
                None,
                true,
            )?;
        }
    }
    for unit in controller.list_units()? {
        if !known.contains(&unit) {
            controller.stop(&unit)?;
            controller.reset_failed(&unit)?;
        }
    }
    Ok(WorkerResult::StartupReconciled { adopted, retired })
}

fn prepare_human_evidence(
    state: &Path,
    decision: &crate::v2::store::PendingDecisionRecord,
) -> Result<PathBuf, String> {
    runner::validate_attempt_id(&decision.decision_id)?;
    let root = runner::ensure_secure_dir(&state.join("decisions"))?;
    let path = root.join(format!("{}.md", decision.decision_id));
    let body = format!(
        "Decision: {}\nChoice: {}\nActor: {}\nBound SHA: {}\n\n{}\n",
        decision.decision_id,
        decision.choice.as_deref().ok_or("missing human choice")?,
        decision
            .resolved_by
            .as_deref()
            .ok_or("missing human actor")?,
        decision.sha.as_deref().ok_or("missing human SHA")?,
        decision
            .note
            .as_deref()
            .unwrap_or("Human decision recorded through the authenticated local socket.")
    );
    isolation::reject_symlink_components(&path)?;
    match std::fs::read(&path) {
        Ok(existing) if existing == body.as_bytes() => {}
        Ok(_) => return Err("human evidence differs from existing durable artifact".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            runner::write_secure_file(&path, body.as_bytes())?
        }
        Err(error) => return Err(error.to_string()),
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::store::{AcceptanceCriterionSpec, ContextPackSpec, TaskMemory};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/z25");
            std::fs::create_dir_all(&root).unwrap();
            let dir = root.join(format!(
                "{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            runner::ensure_secure_dir(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn task(id: &str) -> TaskRecord {
        TaskRecord {
            task_id: id.into(),
            task_group: "test".into(),
            title: id.into(),
            repository: id.into(),
            github_repo: None,
            issue_number: Some(1),
            weight: "S".into(),
            status: "Ready".into(),
            worktree_path: Some("/governed".into()),
            branch: Some(format!("task/{id}")),
            context_pack: ContextPackSpec {
                weight: "S".into(),
                acceptance_criteria: vec![AcceptanceCriterionSpec {
                    id: "AC-1".into(),
                    description: "criterion".into(),
                }],
                ..ContextPackSpec::default()
            },
            depends_on: vec![],
            required_stages: intake::default_required_stages("S"),
            stages_completed: vec![],
            current_stage: Some("impl".into()),
            active_attempt_id: None,
            plan_base_sha: Some("base".into()),
            reviewed_sha: Some("head".into()),
            pr_number: Some(9),
            executor: Some("zach".into()),
            autonomous_consent: true,
            retry_count: 0,
            next_retry_epoch: 0,
            lease_owner: None,
            lease_expires_epoch: None,
            memory: TaskMemory {
                governance_started: true,
                ..TaskMemory::default()
            },
            version: 1,
            updated_epoch: now_epoch(),
        }
    }
    fn coordinator(dir: &Path) -> Coordinator {
        let (mut c, _) = Coordinator::create(V2Store::open_in_memory().unwrap(), dir.into());
        c.preflight = true;
        c.reconciled = true;
        c.synced = true;
        c.last_export = Instant::now();
        c
    }
    fn attempt(task: &TaskRecord, id: &str) -> StageAttemptRecord {
        StageAttemptRecord {
            attempt_id: id.into(),
            task_id: task.task_id.clone(),
            stage: task.current_stage.clone().unwrap(),
            model: "gpt-6.1-sol".into(),
            effort: "high".into(),
            systemd_unit: Some(format!("zach-stage-{id}")),
            invocation_id: None,
            started_epoch: now_epoch() - 100,
            ended_epoch: None,
            status: "RUNNING".into(),
            failure_class: None,
            summary: None,
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
            sha_before: Some("before".into()),
            sha_after: None,
            phase: "RUNNING".into(),
            last_liveness_epoch: now_epoch() - 100,
            last_output_bytes: 0,
            last_cpu_usage_usec: Some(100),
            control_group: Some("/mock".into()),
            exit_code: None,
            exit_code_kind: None,
            retry_generation: task.memory.retry_generation,
        }
    }
    fn seed_attempt(c: &mut Coordinator, mut task: TaskRecord, id: &str) -> StageAttemptRecord {
        task.active_attempt_id = Some(id.into());
        task.status = "In Progress".into();
        c.save(&task).unwrap();
        let attempt = attempt(&task, id);
        c.store.record_stage_attempt(&attempt).unwrap();
        attempt
    }
    fn op(task: &TaskRecord, id: &str, kind: &str) -> LifecycleOperation {
        LifecycleOperation {
            attempt_id: None,
            decision_id: None,
            operation_id: id.into(),
            task_id: task.task_id.clone(),
            kind: kind.into(),
            args: vec![kind.into()],
            body_path: None,
            depends_on: None,
            state: "PENDING".into(),
            retry_epoch: 0,
            attempts: 0,
            last_error: None,
        }
    }
    fn manifest(dir: &Path, task: &TaskRecord, id: &str) -> AttemptManifest {
        let route = crate::v2::router::resolve_stage_route("S", "impl", 0, None)
            .unwrap()
            .unwrap();
        AttemptManifest {
            mount_layout_version: 1,
            attempt_id: id.into(),
            task_id: task.task_id.clone(),
            route: route.clone(),
            spec: runner::build_systemd_stage_command(task, id, &route, "prompt").unwrap(),
            sha_before: "before".into(),
            attempt_dir: dir.into(),
        }
    }
    fn running() -> UnitObservation {
        UnitObservation {
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            result: "success".into(),
            exit_code_kind: "0".into(),
            exit_code: Some(0),
            invocation_id: "invocation".into(),
            control_group: "/mock".into(),
            output_bytes: 0,
            cpu_usage_usec: Some(100),
        }
    }

    #[derive(Default)]
    struct RehearsalUnits {
        reads: AtomicUsize,
        mutations: AtomicUsize,
    }
    impl UnitController for RehearsalUnits {
        fn inspect(&self, _: &str) -> Result<UnitObservation, String> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Err("rehearsal unit evidence refused".into())
        }
        fn list_units(&self) -> Result<Vec<String>, String> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(vec![])
        }
        fn launch(&self, _: &AttemptManifest) -> Result<(), String> {
            self.mutations.fetch_add(1, Ordering::Relaxed);
            Err("rehearsal unit mutation refused".into())
        }
        fn stop(&self, _: &str) -> Result<(), String> {
            self.mutations.fetch_add(1, Ordering::Relaxed);
            Err("rehearsal unit mutation refused".into())
        }
        fn reset_failed(&self, _: &str) -> Result<(), String> {
            self.mutations.fetch_add(1, Ordering::Relaxed);
            Err("rehearsal unit mutation refused".into())
        }
    }

    struct RehearsalWs {
        export: String,
        reads: AtomicUsize,
        mutations: AtomicUsize,
    }
    impl WsTaskClient for RehearsalWs {
        fn execute(&self, args: &[String]) -> Result<String, String> {
            if args == ["export", "--sync", "--json"] {
                self.reads.fetch_add(1, Ordering::Relaxed);
                Ok(self.export.clone())
            } else {
                self.mutations.fetch_add(1, Ordering::Relaxed);
                Err("rehearsal publication refused".into())
            }
        }
    }

    #[derive(Default)]
    pub(super) struct RehearsalDelivery {
        reads: usize,
        mutations: usize,
    }
    impl delivery::DeliveryDriver for RehearsalDelivery {
        fn contract(&mut self, _: &str, _: &str) -> delivery::ContractLookup {
            self.reads += 1;
            delivery::ContractLookup::FetchError("rehearsal delivery read refused".into())
        }
        fn changed_paths(&mut self, _: &str, _: &str) -> Result<Vec<String>, String> {
            self.reads += 1;
            Err("rehearsal delivery read refused".into())
        }
        fn find_run(
            &mut self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: u64,
        ) -> Result<Option<delivery::WorkflowRun>, String> {
            self.reads += 1;
            Err("rehearsal delivery read refused".into())
        }
        fn artifact(
            &mut self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: bool,
        ) -> Result<Vec<u8>, String> {
            self.reads += 1;
            Err("rehearsal delivery read refused".into())
        }
        fn failed_logs(&mut self, _: &str, _: &str) -> Result<String, String> {
            self.reads += 1;
            Err("rehearsal delivery read refused".into())
        }
        fn dispatch(
            &mut self,
            _: &str,
            _: &str,
            _: &str,
            _: &BTreeMap<String, String>,
        ) -> Result<String, String> {
            self.mutations += 1;
            Err("rehearsal delivery mutation refused".into())
        }
        fn query_run(
            &mut self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<Option<delivery::WorkflowRun>, String> {
            self.reads += 1;
            Err("rehearsal delivery read refused".into())
        }
        fn get_https(&mut self, _: &str) -> Result<String, String> {
            self.reads += 1;
            Err("rehearsal delivery read refused".into())
        }
        fn sync_board(&mut self, _: &TaskRecord) -> Result<(), String> {
            self.mutations += 1;
            Err("rehearsal delivery mutation refused".into())
        }
    }

    pub(super) struct SharedRehearsalDelivery(pub Arc<Mutex<RehearsalDelivery>>);
    impl delivery::DeliveryDriver for SharedRehearsalDelivery {
        fn contract(&mut self, a: &str, b: &str) -> delivery::ContractLookup {
            match self.0.lock() {
                Ok(mut d) => d.contract(a, b),
                Err(_) => {
                    delivery::ContractLookup::FetchError("rehearsal driver unavailable".into())
                }
            }
        }
        fn changed_paths(&mut self, a: &str, b: &str) -> Result<Vec<String>, String> {
            self.0
                .lock()
                .map_err(|_| "rehearsal driver unavailable")?
                .changed_paths(a, b)
        }
        fn find_run(
            &mut self,
            a: &str,
            b: &str,
            c: &str,
            d: &str,
            e: u64,
        ) -> Result<Option<delivery::WorkflowRun>, String> {
            self.0
                .lock()
                .map_err(|_| "rehearsal driver unavailable")?
                .find_run(a, b, c, d, e)
        }
        fn artifact(
            &mut self,
            a: &str,
            b: &str,
            c: &str,
            d: &str,
            e: bool,
        ) -> Result<Vec<u8>, String> {
            self.0
                .lock()
                .map_err(|_| "rehearsal driver unavailable")?
                .artifact(a, b, c, d, e)
        }
        fn failed_logs(&mut self, a: &str, b: &str) -> Result<String, String> {
            self.0
                .lock()
                .map_err(|_| "rehearsal driver unavailable")?
                .failed_logs(a, b)
        }
        fn dispatch(
            &mut self,
            a: &str,
            b: &str,
            c: &str,
            d: &BTreeMap<String, String>,
        ) -> Result<String, String> {
            self.0
                .lock()
                .map_err(|_| "rehearsal driver unavailable")?
                .dispatch(a, b, c, d)
        }
        fn query_run(
            &mut self,
            a: &str,
            b: &str,
            c: &str,
        ) -> Result<Option<delivery::WorkflowRun>, String> {
            self.0
                .lock()
                .map_err(|_| "rehearsal driver unavailable")?
                .query_run(a, b, c)
        }
        fn get_https(&mut self, a: &str) -> Result<String, String> {
            self.0
                .lock()
                .map_err(|_| "rehearsal driver unavailable")?
                .get_https(a)
        }
        fn sync_board(&mut self, a: &TaskRecord) -> Result<(), String> {
            self.0
                .lock()
                .map_err(|_| "rehearsal driver unavailable")?
                .sync_board(a)
        }
    }

    type DatabaseImage = BTreeMap<String, Vec<Vec<rusqlite::types::Value>>>;
    fn database_image(store: &mut V2Store) -> Result<DatabaseImage, String> {
        database_image_connection(store.connection_mut())
    }
    fn database_image_connection(conn: &rusqlite::Connection) -> Result<DatabaseImage, String> {
        let tables = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .and_then(|mut s| {
                s.query_map([], |r| r.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(|_| "DATABASE_SNAPSHOT")?;
        let mut image = BTreeMap::new();
        for table in tables {
            // Identifiers come from SQLite, never interpolated as values.
            let quoted = table.replace('"', "\"\"");
            let mut stmt = conn
                .prepare(&format!("SELECT * FROM \"{quoted}\" ORDER BY rowid"))
                .map_err(|_| "DATABASE_SNAPSHOT")?;
            let n = stmt.column_count();
            let rows = stmt
                .query_map([], |r| (0..n).map(|i| r.get(i)).collect())
                .and_then(|r| r.collect::<Result<Vec<_>, _>>())
                .map_err(|_| "DATABASE_SNAPSHOT")?;
            image.insert(table, rows);
        }
        Ok(image)
    }

    fn rehearsal_startup(c: &mut Coordinator) -> Result<(), String> {
        c.startup_ownership()?;
        let snapshots = c
            .store
            .list_tasks(None)
            .map_err(|_| "rehearsal task read failed")?
            .into_iter()
            .map(|t| c.store.list_stage_attempts(&t.task_id).map(|a| (t, a)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "rehearsal attempt read failed")?;
        let result = reconcile_attempt_snapshots(c.controller.as_ref(), &c.state_dir, snapshots)?;
        c.worker_result(result)
    }

    // Every real coordinator eligibility pass runs. Only asynchronous closures
    // are intercepted; synchronous lock/decision/retry/outbox writes remain visible.
    fn rehearsal_pass(c: &mut Coordinator, _driver: &mut RehearsalDelivery) -> Result<(), String> {
        let before = database_image(&mut c.store)?;
        c.monitor_attempts()?;
        c.reconcile_terminal_tasks()?;
        c.replay_lifecycle()?;
        c.resume_pipeline_steps()?;
        c.resume_decisions()?;
        c.reconcile_terminal_tasks()?;
        c.evaluate_gates()?;
        c.dispatch()?;
        c.drive_merges()?;
        c.last_delivery_poll = Instant::now() - Duration::from_secs(10);
        if c.rehearsal_delivery.is_none() {
            c.rehearsal_delivery = Some(Arc::new(Mutex::new(RehearsalDelivery::default())));
            c.rehearsal_poll_progress = Some(Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]));
        }
        c.poll_deliveries()?;
        let probe = c
            .submission_probe
            .as_ref()
            .ok_or("rehearsal barrier absent")?;
        if probe
            .iter()
            .any(|(class, count)| *class != "delivery-poll" && *count != 0)
        {
            return Err("rehearsal forbidden job intent".into());
        }
        // Service the actual CoordinatorDeliveryStore messages and completion.
        // A finite event budget and deadline turn every stalled poll into refusal.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut messages = 0;
        while !c.jobs.is_empty() {
            if Instant::now() >= deadline || messages >= 1024 {
                return Err("rehearsal poll did not quiesce".into());
            }
            let event =
                c.rx.recv_timeout(Duration::from_millis(100))
                    .map_err(|_| "rehearsal poll did not quiesce")?;
            c.handle_event(event)
                .map_err(|_| "rehearsal poll completion failed")?;
            messages += 1;
        }
        while let Ok(event) = c.rx.try_recv() {
            if messages >= 1024 {
                return Err("rehearsal poll did not quiesce".into());
            }
            c.handle_event(event)
                .map_err(|_| "rehearsal trailing event failed")?;
            messages += 1;
        }
        let driver = c
            .rehearsal_delivery
            .as_ref()
            .ok_or("rehearsal fake absent")?
            .lock()
            .map_err(|_| "rehearsal fake unavailable")?;
        if driver.reads != 0 || driver.mutations != 0 {
            return Err("rehearsal delivery driver intent".into());
        }
        drop(driver);
        let progress = c
            .rehearsal_poll_progress
            .as_ref()
            .ok_or("rehearsal progress absent")?;
        let attempts = c
            .submission_probe
            .as_ref()
            .and_then(|p| p.get("delivery-poll"))
            .copied()
            .unwrap_or(0);
        if attempts != progress[0].load(Ordering::Relaxed)
            || attempts != progress[1].load(Ordering::Relaxed)
        {
            return Err("rehearsal poll completion mismatch".into());
        }
        if database_image(&mut c.store)? != before {
            return Err("rehearsal database effect".into());
        }
        Ok(())
    }

    fn manual_task(id: &str, status: &str) -> TaskRecord {
        let mut t = task(id);
        t.repository = "human-shared-repo".into();
        t.status = status.into();
        t.executor = None;
        t.autonomous_consent = false;
        t.current_stage = None;
        t.memory = TaskMemory::default();
        // Canonical plan metadata is not an execution identity.
        t.stages_completed = vec!["human-plan".into()];
        t
    }

    #[test]
    fn startup_manual_metadata_is_inert_in_both_loops_and_actual_passes() {
        let dir = TestDirectory::new();
        let (mut c, _handle) =
            Coordinator::create(V2Store::open_in_memory().unwrap(), dir.0.clone());
        c.submission_probe = Some(BTreeMap::new());
        let units = Arc::new(RehearsalUnits::default());
        c.controller = units.clone();
        for (i, status) in [
            "Planning",
            "Plan Review",
            "In Progress",
            "PR Review",
            "PR Review",
        ]
        .iter()
        .enumerate()
        {
            let mut t = manual_task(&format!("manual-{i}"), status);
            if i % 2 == 0 {
                t.executor = Some("external".into());
            }
            c.save(&t).unwrap();
        }
        let before = database_image(&mut c.store).unwrap();
        rehearsal_startup(&mut c).unwrap();
        assert_eq!(database_image(&mut c.store).unwrap(), before);
        rehearsal_pass(&mut c, &mut RehearsalDelivery::default()).unwrap();
        assert_eq!(database_image(&mut c.store).unwrap(), before);
        assert_eq!(units.mutations.load(Ordering::Relaxed), 0);
        assert_eq!(units.reads.load(Ordering::Relaxed), 1);
        assert!(c.submission_probe.unwrap().is_empty());
    }

    #[test]
    fn startup_ambiguous_raw_proof_fails_before_cleanup_locks_or_orphan_writes() {
        for memory in [
            "{\"pipeline_checkpoint\":{\"attempt_id\":\"hidden\",\"operation\":\"PUSH\"},\"halt_requested\":0}",
            "{\"unknown\":false}",
            "{\"governance_started\":false,\"governance_started\":true}",
        ] {
            let dir = TestDirectory::new();
            let mut c = coordinator(&dir.0);
            c.save(&manual_task("manual-invalid", "In Progress"))
                .unwrap();
            c.store
                .connection_mut()
                .execute("UPDATE tasks SET memory_json=?1", [memory])
                .unwrap();
            let before = database_image(&mut c.store).unwrap();
            assert!(
                c.worker_result(WorkerResult::StartupReconciled {
                    adopted: vec![],
                    retired: vec![]
                })
                .is_err()
            );
            assert_eq!(database_image(&mut c.store).unwrap(), before);
        }
    }

    #[test]
    fn native_startup_evidence_survives_revocation_and_executor_changes() {
        for evidence in ["attempt", "checkpoint", "start", "outbox", "merge", "lease"] {
            let dir = TestDirectory::new();
            let mut c = coordinator(&dir.0);
            let mut t = manual_task(evidence, "In Progress");
            t.stages_completed.clear();
            c.save(&t).unwrap();
            match evidence {
                "attempt" => {
                    t.active_attempt_id = Some("native".into());
                    let mut fixture = t.clone();
                    fixture.current_stage = Some("impl".into());
                    c.store
                        .record_stage_attempt(&attempt(&fixture, "native"))
                        .unwrap();
                }
                "checkpoint" => {
                    t.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
                        attempt_id: "native".into(),
                        operation: "PREPARING".into(),
                    })
                }
                "start" => t.memory.governance_started = true,
                "outbox" => c
                    .store
                    .enqueue_lifecycle(&op(&t, "native-start", "start"))
                    .unwrap(),
                "merge" => {
                    t.status = "Queued for Merge".into();
                    t.memory.merge_checkpoint = Some(MergeCheckpoint {
                        phase: "MERGE_PENDING".into(),
                        ..Default::default()
                    })
                }
                "lease" => t.lease_expires_epoch = Some(0),
                _ => unreachable!(),
            }
            c.save(&t).unwrap();
            assert!(c.store.native_startup_owned(&t).unwrap(), "{evidence}");
            c.worker_result(WorkerResult::Reconciled).unwrap();
            if evidence == "start" || evidence == "outbox" || evidence == "lease" {
                assert_eq!(
                    c.store.list_stage_attempts(&t.task_id).unwrap().len(),
                    1,
                    "{evidence}"
                );
                assert!(c.task(&t.task_id).unwrap().retry_count > 0);
            } else if evidence == "checkpoint" {
                assert!(
                    c.task(&t.task_id)
                        .unwrap()
                        .memory
                        .pipeline_checkpoint
                        .is_none()
                );
            } else {
                assert!(!c.store.list_path_locks(None).unwrap().is_empty());
            }
        }
    }

    #[test]
    fn reopened_manual_task_keeps_completed_native_markers_as_history() {
        for (stage, aborted) in [
            ("impl", false),
            ("merge_queue", false),
            ("merge_queue", true),
        ] {
            let dir = TestDirectory::new();
            let mut c = coordinator(&dir.0);
            c.controller = Arc::new(RehearsalUnits::default());
            c.submission_probe = Some(BTreeMap::new());
            let mut t = task("reopened-manual");
            t.status = "Done".into();
            t.stages_completed = vec!["impl".into()];
            t.memory.governance_terminal_observed = true;
            t.current_stage = Some("impl".into());
            c.save(&t).unwrap();
            let mut a = attempt(&t, "historical-complete");
            a.phase = "COMPLETE".into();
            a.status = "PASSED".into();
            a.ended_epoch = Some(now_epoch());
            c.store.record_stage_attempt(&a).unwrap();
            t.current_stage = Some(stage.into());
            c.save(&t).unwrap();
            if aborted {
                let mut row = delivery_rows(&t).remove(0);
                row.state = "aborted".into();
                c.store.upsert_delivery(&row).unwrap();
            }
            let export = serde_json::json!({"schema_version":2,"tasks":[{"id":t.task_id,"repository":t.repository,"status":"In Progress","executor":"external","autonomous_consent":false,"stages_completed":[]}]});
            c.worker_result(WorkerResult::Export(
                intake::decode_export_records(&export.to_string()).unwrap(),
            ))
            .unwrap();
            let reopened = c.task(&t.task_id).unwrap();
            assert!(
                reopened.memory.governance_started && reopened.memory.governance_terminal_observed
            );
            assert_eq!(reopened.current_stage.as_deref(), Some(stage));
            assert!(!c.store.native_startup_owned(&reopened).unwrap());
            let before = database_image(&mut c.store).unwrap();
            rehearsal_startup(&mut c).unwrap();
            rehearsal_pass(&mut c, &mut RehearsalDelivery::default()).unwrap();
            assert_eq!(database_image(&mut c.store).unwrap(), before);
            assert_eq!(c.store.list_stage_attempts(&t.task_id).unwrap(), vec![a]);
        }
    }

    #[test]
    fn conflicting_active_status_and_native_checkpoint_refuses_without_fabricated_attempt() {
        for suspended in [false, true] {
            let dir = TestDirectory::new();
            let mut c = coordinator(&dir.0);
            let mut t = manual_task("ambiguous-native", "In Progress");
            if suspended {
                t.memory.suspended_impl_attempt_id = Some("native".into());
            } else {
                t.memory.merge_checkpoint = Some(MergeCheckpoint {
                    phase: "MERGE_PENDING".into(),
                    ..Default::default()
                });
            }
            c.save(&t).unwrap();
            let before = database_image(&mut c.store).unwrap();
            assert!(
                c.worker_result(WorkerResult::StartupReconciled {
                    adopted: vec![],
                    retired: vec![]
                })
                .is_err()
            );
            assert_eq!(database_image(&mut c.store).unwrap(), before);
            assert!(c.store.list_stage_attempts(&t.task_id).unwrap().is_empty());
        }
    }

    #[test]
    fn terminal_offline_then_real_standard_and_restart_never_replays_native_history() {
        for executor in ["external", "zach"] {
            for labels in [
                Some(vec!["impl"]),
                Some(vec!["impl", "manual-extra"]),
                Some(vec![]),
                None,
            ] {
                let dir = TestDirectory::new();
                let db = dir.0.join("synthetic.sqlite3");
                let (mut c, _handle) =
                    Coordinator::create(V2Store::open(&db).unwrap(), dir.0.clone());
                c.controller = Arc::new(RehearsalUnits::default());
                c.submission_probe = Some(BTreeMap::new());
                let mut t = task("terminal-native");
                t.status = "Queued for Merge".into();
                t.stages_completed = vec!["impl".into()];
                t.memory.applied_decisions = vec!["already-applied".into()];
                t.memory.recent_attempts = vec!["preserved history".into()];
                t.active_attempt_id = Some("complete-native".into());
                c.save(&t).unwrap();
                let mut a = attempt(&t, "complete-native");
                a.phase = "COMPLETE".into();
                a.status = "PASSED".into();
                a.ended_epoch = Some(now_epoch());
                c.store.record_stage_attempt(&a).unwrap();
                c.store
                    .open_decision(
                        "already-applied",
                        &t.task_id,
                        "test",
                        "human-plan-approval",
                        "q",
                        &["Approve".into()],
                        None,
                        "ctx",
                        Some("base"),
                    )
                    .unwrap();
                c.store
                    .resolve_decision("already-applied", "Approve", "synthetic", None)
                    .unwrap();
                let mut receipt = delivery_rows(&t).remove(0);
                receipt.state = "verified".into();
                receipt.evidence_json["board_synced_status"] = "Done".into();
                c.store.upsert_delivery(&receipt).unwrap();
                let mut export = serde_json::json!({"schema_version":2,"tasks":[{"id":t.task_id,"repository":t.repository,"status":"Done","executor":executor,"autonomous_consent":true,"weight":"S"}]});
                if let Some(labels) = labels {
                    export["tasks"][0]["stages_completed"] = serde_json::json!(labels);
                }
                let input = intake::decode_export_records(&export.to_string()).unwrap();
                assert_eq!(input[0].memory, TaskMemory::default());
                c.store
                    .sync_task_with_mode(
                        &input[0],
                        crate::v2::store::SyncMode::ReconcileFinishedLegacy,
                    )
                    .unwrap();
                let before = database_image(&mut c.store).unwrap();
                rehearsal_startup(&mut c).unwrap();
                rehearsal_pass(&mut c, &mut RehearsalDelivery::default()).unwrap();
                assert_eq!(database_image(&mut c.store).unwrap(), before);
                let progress = c.rehearsal_poll_progress.as_ref().unwrap();
                assert!(progress[0].load(Ordering::Relaxed) >= 1);
                assert_eq!(
                    progress[0].load(Ordering::Relaxed),
                    progress[1].load(Ordering::Relaxed)
                );
                rehearsal_standard(&mut c, input).unwrap();
                let standard = database_image(&mut c.store).unwrap();
                for (table, rows) in &before {
                    if table == "daemon_meta" {
                        let clean = |r: &Vec<Vec<rusqlite::types::Value>>| {
                            r.iter()
                                .filter(|row| {
                                    row.first()
                                        != Some(&rusqlite::types::Value::Text(
                                            "last_sync_epoch".into(),
                                        ))
                                })
                                .cloned()
                                .collect::<Vec<_>>()
                        };
                        assert_eq!(clean(standard.get(table).unwrap()), clean(rows));
                    } else if table != "tasks" {
                        assert_eq!(standard.get(table), Some(rows), "{table}");
                    }
                }
                assert!(c.task(&t.task_id).unwrap().active_attempt_id.is_none());
                assert!(
                    c.task(&t.task_id)
                        .unwrap()
                        .memory
                        .applied_decisions
                        .contains(&"already-applied".into())
                );
                rehearsal_pass(&mut c, &mut RehearsalDelivery::default()).unwrap();
                let messages = c
                    .socket_command(ClientCommand::Subscribe {
                        group: None,
                        since_seq: None,
                        once: None,
                    })
                    .unwrap();
                assert!(messages.iter().any(|m| matches!(m,ServerMessage::Snapshot{tasks,..} if tasks.iter().any(|t| t.status == "Done"))));
                drop(c);
                let (mut reopened, _handle) =
                    Coordinator::create(V2Store::open(&db).unwrap(), dir.0.clone());
                reopened.controller = Arc::new(RehearsalUnits::default());
                reopened.submission_probe = Some(BTreeMap::new());
                rehearsal_startup(&mut reopened).unwrap();
                rehearsal_pass(&mut reopened, &mut RehearsalDelivery::default()).unwrap();
                assert_eq!(database_image(&mut reopened.store).unwrap(), standard);
            }
        }
    }

    #[test]
    fn real_coordinator_positive_controls_detect_jobs_and_direct_database_effects() {
        for case in [
            "pipeline",
            "publication",
            "worker",
            "merge",
            "decision",
            "dispatch",
            "delivery",
            "orphan",
        ] {
            let dir = TestDirectory::new();
            let mut c = coordinator(&dir.0);
            c.submission_probe = Some(BTreeMap::new());
            c.controller = Arc::new(RehearsalUnits::default());
            let mut t = task("positive");
            c.save(&t).unwrap();
            match case {
                "pipeline" => {
                    t.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
                        attempt_id: "positive-attempt".into(),
                        operation: "CHECKS".into(),
                    });
                    let mut a = attempt(&t, "positive-attempt");
                    a.phase = "POSTPROCESSING".into();
                    a.status = "PASSED".into();
                    a.ended_epoch = Some(now_epoch());
                    c.store.record_stage_attempt(&a).unwrap();
                }
                "publication" => c
                    .store
                    .enqueue_lifecycle(&op(&t, "positive-op", "stage"))
                    .unwrap(),
                "worker" => {
                    t.active_attempt_id = Some("positive-attempt".into());
                    c.store
                        .record_stage_attempt(&attempt(&t, "positive-attempt"))
                        .unwrap();
                }
                "merge" => {
                    t.status = "Queued for Merge".into();
                    t.memory.merge_checkpoint = Some(MergeCheckpoint {
                        phase: "MERGE_DEFAULT".into(),
                        target_sha: "head".into(),
                        pr_number: 9,
                        ..Default::default()
                    });
                    c.store
                        .enqueue_merge_queue(&t.repository, &t.task_id, 9, "head")
                        .unwrap();
                }
                "decision" => {
                    t.weight = "L".into();
                    t.required_stages = vec!["human-plan-approval".into()];
                }
                "dispatch" => {}
                "delivery" => {
                    t.status = "Done".into();
                    let mut row = delivery_rows(&t).remove(0);
                    row.state = "verified".into();
                    c.store.upsert_delivery(&row).unwrap();
                }
                "orphan" => {
                    t.status = "In Progress".into();
                }
                _ => unreachable!(),
            }
            c.save(&t).unwrap();
            let before = database_image(&mut c.store).unwrap();
            if case == "orphan" {
                c.worker_result(WorkerResult::Reconciled).unwrap();
                assert_ne!(database_image(&mut c.store).unwrap(), before);
            } else {
                assert!(
                    rehearsal_pass(&mut c, &mut RehearsalDelivery::default()).is_err(),
                    "{case}"
                );
                let p = c.submission_probe.as_ref().unwrap();
                match case {
                    "pipeline" => assert!(p.contains_key("pipeline")),
                    "publication" => assert!(p.contains_key("publication")),
                    "worker" => assert!(p.contains_key("inspection")),
                    "merge" => assert!(p.contains_key("merge")),
                    "decision" | "dispatch" => {
                        assert_ne!(database_image(&mut c.store).unwrap(), before)
                    }
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn rehearsal_barrier_and_fake_mutations_are_non_vacuous() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        c.submission_probe = Some(BTreeMap::new());
        let ran = Arc::new(AtomicUsize::new(0));
        for key in [
            "prepare:synthetic",
            "launch:synthetic",
            "pipeline:synthetic",
            "ws:synthetic",
            "merge:synthetic",
            "delivery-close:synthetic",
            "deploy:synthetic",
            "post-merge-deliveries",
            "identity:synthetic",
            "observe:synthetic",
            "stop:synthetic",
            "cleanup:synthetic",
            "unexpected",
        ] {
            let ran = ran.clone();
            assert!(!c.submit(
                key.into(),
                None,
                0,
                Box::new(move || {
                    ran.fetch_add(1, Ordering::Relaxed);
                    Ok(WorkerResult::DeliveryPolled)
                })
            ));
        }
        assert_eq!(ran.load(Ordering::Relaxed), 0);
        let p = c.submission_probe.as_ref().unwrap();
        for class in [
            "worker",
            "preparation",
            "pipeline",
            "deploy",
            "publication",
            "merge",
            "delivery",
            "delivery-poll",
            "inspection",
            "unit-mutation",
            "other",
        ] {
            assert!(p.get(class).copied().unwrap_or(0) > 0, "{class}");
        }
        assert!(rehearsal_pass(&mut c, &mut RehearsalDelivery::default()).is_err());
        let units = RehearsalUnits::default();
        assert!(units.stop("synthetic").is_err());
        assert!(units.reset_failed("synthetic").is_err());
        assert!(
            units
                .launch(&manifest(&dir.0, &task("synthetic"), "synthetic"))
                .is_err()
        );
        assert_eq!(units.mutations.load(Ordering::Relaxed), 3);
        let ws = RehearsalWs {
            export: String::new(),
            reads: AtomicUsize::new(0),
            mutations: AtomicUsize::new(0),
        };
        assert!(ws.execute(&["stage".into()]).is_err());
        assert_eq!(ws.mutations.load(Ordering::Relaxed), 1);
        let mut d = RehearsalDelivery::default();
        assert!(
            delivery::DeliveryDriver::dispatch(
                &mut d,
                "synthetic",
                "synthetic",
                "synthetic",
                &BTreeMap::new()
            )
            .is_err()
        );
        assert!(delivery::DeliveryDriver::sync_board(&mut d, &task("synthetic")).is_err());
        assert_eq!(d.mutations, 2);
        // Direct writes must also be caught, independently of submission counts.
        let before = database_image(&mut c.store).unwrap();
        c.save(&task("synthetic-effect")).unwrap();
        assert_ne!(database_image(&mut c.store).unwrap(), before);
    }

    // Test-only hashing avoids subprocesses and new production dependencies.
    fn rehearsal_sha256(bytes: &[u8]) -> String {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut padded = bytes.to_vec();
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&((bytes.len() as u64) * 8).to_be_bytes());
        for block in padded.chunks_exact(64) {
            let mut w = [0u32; 64];
            for (i, chunk) in block.chunks_exact(4).enumerate() {
                w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
            for i in 16..64 {
                let a = w[i - 15];
                let b = w[i - 2];
                w[i] = w[i - 16]
                    .wrapping_add(a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3))
                    .wrapping_add(w[i - 7])
                    .wrapping_add(b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10));
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
            for i in 0..64 {
                let t1 = h
                    .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
                    .wrapping_add((e & f) ^ (!e & g))
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let t2 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                    .wrapping_add((a & b) ^ (a & c) ^ (b & c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            for (v, n) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
                *v = v.wrapping_add(n);
            }
        }
        state.iter().map(|v| format!("{v:08x}")).collect()
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RehearsalMarker {
        schema_version: u32,
        purpose: String,
        run_id: String,
        database_sha256: String,
        export_sha256: String,
        native_candidate_sha256: String,
        infra_candidate_sha256: String,
    }
    fn digest_shape(s: &str) -> bool {
        s.len() == 64
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    }
    type FileIdentity = (u64, u64, u32, u32, u64);
    fn rehearsal_file(path: &Path, uid: u32) -> Result<(File, FileIdentity), String> {
        use std::os::unix::fs::MetadataExt;
        isolation::reject_symlink_components(path).map_err(|_| "UNSAFE_INPUT")?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| "UNSAFE_INPUT")?;
        let m = file.metadata().map_err(|_| "UNSAFE_INPUT")?;
        if !m.is_file() || m.uid() != uid || m.mode() & 0o7777 != 0o600 || m.nlink() != 1 {
            return Err("UNSAFE_INPUT".into());
        }
        Ok((file, (m.dev(), m.ino(), m.uid(), m.mode(), m.nlink())))
    }
    fn rehearsal_bytes(mut file: File, limit: usize) -> Result<Vec<u8>, String> {
        use std::io::Read;
        let mut bytes = Vec::new();
        (&mut file)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "INPUT_READ")?;
        if bytes.len() > limit {
            return Err("INPUT_SIZE".into());
        }
        Ok(bytes)
    }
    fn rehearsal_directory() -> Result<(PathBuf, u32, (u64, u64)), String> {
        use std::os::unix::fs::MetadataExt;
        let dir = PathBuf::from(std::env::var_os("ZACH039_REHEARSAL_DIR").ok_or("NO_SELECTOR")?);
        // Root means the orchestrating role. The reviewed operator is ubuntu,
        // running with its own UID and real user bus, never sudo/root.
        let uid = unsafe { libc::geteuid() };
        let account = unsafe { libc::getpwnam(c"ubuntu".as_ptr()) };
        if uid == 0
            || uid != unsafe { libc::getuid() }
            || account.is_null()
            || unsafe { (*account).pw_uid } != uid
        {
            return Err("OPERATOR_IDENTITY".into());
        }
        let runtime = format!("/run/user/{uid}");
        if std::env::var("XDG_RUNTIME_DIR").ok().as_deref() != Some(&runtime)
            || std::env::var("DBUS_SESSION_BUS_ADDRESS").ok().as_deref()
                != Some(&format!("unix:path={runtime}/bus"))
        {
            return Err("OPERATOR_BUS".into());
        }
        isolation::reject_symlink_components(&dir).map_err(|_| "UNSAFE_DIRECTORY")?;
        let canonical = std::fs::canonicalize(&dir).map_err(|_| "UNSAFE_DIRECTORY")?;
        if canonical != dir
            || dir.parent() != Some(Path::new("/var/tmp"))
            || !dir.file_name().and_then(|s| s.to_str()).is_some_and(|s| {
                s.starts_with("zach039-rehearsal-")
                    && s.len() > 26
                    && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
        {
            return Err("UNSAFE_DIRECTORY".into());
        }
        let m = std::fs::symlink_metadata(&dir).map_err(|_| "UNSAFE_DIRECTORY")?;
        if !m.is_dir() || m.uid() != uid || m.mode() & 0o7777 != 0o700 {
            return Err("UNSAFE_DIRECTORY".into());
        }
        rehearsal_entries(&dir, uid, false)?;
        Ok((dir, uid, (m.dev(), m.ino())))
    }
    fn rehearsal_entries(dir: &Path, uid: u32, after_open: bool) -> Result<(), String> {
        for entry in std::fs::read_dir(dir).map_err(|_| "UNSAFE_DIRECTORY")? {
            let entry = entry.map_err(|_| "UNSAFE_DIRECTORY")?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("UNEXPECTED_ENTRY")?;
            let input = matches!(
                name,
                "zach-v2.sqlite3" | "canonical-export.json" | "copy-only.json"
            );
            let sidecar =
                after_open && matches!(name, "zach-v2.sqlite3-wal" | "zach-v2.sqlite3-shm");
            let log = name.ends_with(".log")
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'));
            if !input && !sidecar && !log {
                return Err("UNEXPECTED_ENTRY".into());
            }
            rehearsal_file(&entry.path(), uid)?;
        }
        Ok(())
    }

    // Standard's one named metadata allowance is checked by key, never a blanket
    // exclusion of daemon_meta or task history. Every task column is inspected.
    fn rehearsal_standard(c: &mut Coordinator, export: Vec<TaskRecord>) -> Result<(), String> {
        let before = database_image(&mut c.store)?;
        let old = c.store.list_tasks(None).map_err(|_| "STANDARD_READ")?;
        if old.len() != export.len()
            || export.iter().any(|t| {
                !old.iter().any(|o| {
                    o.task_id == t.task_id && o.repository == t.repository && o.status == t.status
                })
            })
        {
            return Err("STANDARD_INVENTORY".into());
        }
        c.worker_result(WorkerResult::Export(export.clone()))
            .map_err(|_| "STANDARD_INTAKE")?;
        let after = database_image(&mut c.store)?;
        for (table, rows) in &before {
            let Some(actual) = after.get(table) else {
                return Err("STANDARD_HISTORY".into());
            };
            if table == "tasks" {
                continue;
            }
            if table == "daemon_meta" {
                let clean = |r: &Vec<Vec<rusqlite::types::Value>>| {
                    r.iter()
                        .filter(|r| {
                            r.first()
                                != Some(&rusqlite::types::Value::Text("last_sync_epoch".into()))
                        })
                        .cloned()
                        .collect::<Vec<_>>()
                };
                if clean(rows) != clean(actual) {
                    return Err("STANDARD_HISTORY".into());
                }
            } else if rows != actual {
                return Err("STANDARD_HISTORY".into());
            }
        }
        if before.keys().ne(after.keys()) {
            return Err("STANDARD_HISTORY".into());
        }
        let columns = c
            .store
            .connection_mut()
            .prepare("SELECT * FROM tasks LIMIT 0")
            .map_err(|_| "STANDARD_READ")?
            .column_names()
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let allowed = [
            "task_group",
            "title",
            "github_repo",
            "issue_number",
            "weight",
            "worktree_path",
            "branch",
            "context_pack_json",
            "depends_on_json",
            "required_stages_json",
            "stages_completed_json",
            "plan_base_sha",
            "reviewed_sha",
            "executor",
            "autonomous_consent",
            "version",
            "updated_epoch",
            "memory_json",
        ];
        let b = before.get("tasks").ok_or("STANDARD_READ")?;
        let a = after.get("tasks").ok_or("STANDARD_READ")?;
        if b.len() != a.len() {
            return Err("STANDARD_INVENTORY".into());
        }
        for (b, a) in b.iter().zip(a) {
            for ((name, b), a) in columns.iter().zip(b).zip(a) {
                if b != a && !allowed.contains(&name.as_str()) {
                    return Err("STANDARD_RUNTIME".into());
                }
            }
        }
        for t in c.store.list_tasks(None).map_err(|_| "STANDARD_READ")? {
            let o = old
                .iter()
                .find(|o| o.task_id == t.task_id)
                .ok_or("STANDARD_INVENTORY")?;
            let incoming = export
                .iter()
                .find(|i| i.task_id == t.task_id)
                .ok_or("STANDARD_INVENTORY")?;
            let mut memory = o.memory.clone();
            memory.governance_terminal_observed |=
                matches!(incoming.status.as_str(), "Done" | "Cancelled");
            memory.governance_started |= incoming.memory.governance_started;
            if t.memory != memory || t.version != o.version + 1 {
                return Err("STANDARD_RUNTIME".into());
            }
        }
        Ok(())
    }

    fn rehearsal_result(marker: &RehearsalMarker, binary: &str) -> serde_json::Value {
        serde_json::json!({"schema_version":1,"run_id":marker.run_id,"status":"REFUSED","failure_class":"INCOMPLETE",
            "identity":{"native_candidate_sha256":marker.native_candidate_sha256,"infra_candidate_sha256":marker.infra_candidate_sha256,"harness_binary_sha256":binary,"database_input_sha256":marker.database_sha256,"export_input_sha256":marker.export_sha256},
            "phases":{"startup_before_export_completed":false,"standard_intake_completed":false,"restart_completed":false,"terminal_reconciliation_completed":false,"lifecycle_completed":false,"decisions_completed":false,"gates_completed":false,"dispatch_completed":false,"merge_completed":false,"delivery_completed":false,"quiescent":false},
            "delivery_poll":{"attempted":0,"executed":0,"completed":0,"fake_reads":0,"fake_mutation_attempts":0},
            "forbidden_intents":{"stage_launch":0,"preparation_apply":0,"lifecycle_mutation":0,"publication":0,"pr_merge":0,"deploy":0,"delivery_apply":0,"other":0},
            "effects":{"unexpected_task_changes":0,"attempts":0,"retries_or_failures":0,"locks":0,"decisions":0,"lifecycle":0,"queue":0,"delivery":0,"other":0},
            "checks":{"raw_inventory_and_history_compared":false,"only_reviewed_differences":false,"input_identity_rechecked":false,"system_driver_executions":0},
            "positive_controls":{"poll_completed_with_fake":false,"mutation_intercepted":false,"forbidden_classes_intercepted":false}})
    }
    fn rehearsal_counts(c: &Coordinator, result: &mut serde_json::Value) -> Result<(), String> {
        let p = c.submission_probe.as_ref().ok_or("BARRIER_ABSENT")?;
        let n = |key| p.get(key).copied().unwrap_or(0);
        let progress = c.rehearsal_poll_progress.as_ref();
        let executed = progress.map(|p| p[0].load(Ordering::Relaxed)).unwrap_or(0);
        let completed = progress.map(|p| p[1].load(Ordering::Relaxed)).unwrap_or(0);
        let (reads, mutations) = if let Some(d) = &c.rehearsal_delivery {
            let d = d.lock().map_err(|_| "FAKE_UNAVAILABLE")?;
            (d.reads, d.mutations)
        } else {
            (0, 0)
        };
        for (key, value) in [
            ("attempted", n("delivery-poll")),
            ("executed", executed),
            ("completed", completed),
            ("fake_reads", reads),
            ("fake_mutation_attempts", mutations),
        ] {
            let old = result["delivery_poll"][key]
                .as_u64()
                .ok_or("RESULT_SCHEMA")?;
            result["delivery_poll"][key] = serde_json::json!(old + value as u64);
        }
        for (key, value) in [
            ("stage_launch", n("worker")),
            ("preparation_apply", n("preparation") + n("pipeline")),
            ("lifecycle_mutation", n("publication")),
            ("deploy", n("deploy")),
            ("publication", n("publication")),
            ("pr_merge", n("merge")),
            ("delivery_apply", n("delivery")),
            (
                "other",
                n("other") + n("inspection") + n("unit-mutation") + n("control"),
            ),
        ] {
            result["forbidden_intents"][key] = serde_json::json!(
                result["forbidden_intents"][key]
                    .as_u64()
                    .ok_or("RESULT_SCHEMA")?
                    + value as u64
            );
        }
        Ok(())
    }
    fn rehearsal_effects(
        before: &DatabaseImage,
        after: &DatabaseImage,
        result: &mut serde_json::Value,
    ) {
        for table in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
            if before.get(table) == after.get(table) {
                continue;
            }
            let key = match table.as_str() {
                "tasks" => "unexpected_task_changes",
                "stage_attempts" => "attempts",
                "path_locks" => "locks",
                "pending_decisions" => "decisions",
                "lifecycle_ops" => "lifecycle",
                "merge_queue" => "queue",
                "post_merge_deliveries" => "delivery",
                _ => "other",
            };
            result["effects"][key] =
                serde_json::json!(result["effects"][key].as_u64().unwrap_or(0) + 1);
            if table == "tasks" {
                result["effects"]["retries_or_failures"] = serde_json::json!(1);
            }
        }
    }

    /// ROOT ORCHESTRATOR ONLY. Never invoke from a worker, ordinary cargo test,
    /// production CLI or daemon. Inputs are exclusive operator-owned copies.
    #[test]
    #[ignore = "root orchestrator only: reviewed binary and exclusive private copied inputs required"]
    fn private_copy_activation_rehearsal() -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;
        let (dir, uid, dir_identity) = rehearsal_directory()?;
        let (db, db_id) = rehearsal_file(&dir.join("zach-v2.sqlite3"), uid)?;
        let (export, export_id) = rehearsal_file(&dir.join("canonical-export.json"), uid)?;
        let (marker_file, marker_id) = rehearsal_file(&dir.join("copy-only.json"), uid)?;
        let db_hash = rehearsal_sha256(&rehearsal_bytes(db, 256 * 1024 * 1024)?);
        let export_bytes = rehearsal_bytes(export, 16 * 1024 * 1024)?;
        let marker_bytes = rehearsal_bytes(marker_file, 16 * 1024)?;
        let marker: RehearsalMarker =
            serde_json::from_slice(&marker_bytes).map_err(|_| "MARKER_SCHEMA")?;
        if marker.schema_version != 1
            || marker.purpose != "zach039-exclusive-copy"
            || !(8..=128).contains(&marker.run_id.len())
            || !marker
                .run_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || [
                &marker.database_sha256,
                &marker.export_sha256,
                &marker.native_candidate_sha256,
                &marker.infra_candidate_sha256,
            ]
            .iter()
            .any(|s| !digest_shape(s))
            || marker.database_sha256 != db_hash
            || marker.export_sha256 != rehearsal_sha256(&export_bytes)
        {
            return Err("INPUT_BINDING".into());
        }
        let binary = rehearsal_sha256(&rehearsal_bytes(
            File::open("/proc/self/exe").map_err(|_| "BINARY_IDENTITY")?,
            256 * 1024 * 1024,
        )?);
        let mut result = rehearsal_result(&marker, &binary);
        let mut driver_counters = None;
        let mut outcome = (|| -> Result<(), String> {
            // No private input enters synthetic controls or their diagnostics.
            std::panic::catch_unwind(|| {
                rehearsal_barrier_and_fake_mutations_are_non_vacuous();
                real_coordinator_positive_controls_detect_jobs_and_direct_database_effects();
                terminal_offline_then_real_standard_and_restart_never_replays_native_history();
            })
            .map_err(|_| "POSITIVE_CONTROL")?;
            for key in [
                "poll_completed_with_fake",
                "mutation_intercepted",
                "forbidden_classes_intercepted",
            ] {
                result["positive_controls"][key] = true.into();
            }
            let export = std::str::from_utf8(&export_bytes).map_err(|_| "EXPORT_SCHEMA")?;
            let records = intake::decode_export_records(export).map_err(|_| "EXPORT_SCHEMA")?;
            if records
                .iter()
                .map(|t| &t.task_id)
                .collect::<BTreeSet<_>>()
                .len()
                != records.len()
            {
                return Err("EXPORT_DUPLICATE".into());
            }
            let check = rusqlite::Connection::open_with_flags(
                dir.join("zach-v2.sqlite3"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .map_err(|_| "DATABASE_OPEN")?;
            let version: String = check
                .query_row(
                    "SELECT value FROM daemon_meta WHERE key='schema_version'",
                    [],
                    |r| r.get(0),
                )
                .map_err(|_| "DATABASE_SCHEMA")?;
            if version != "4" {
                return Err("DATABASE_SCHEMA".into());
            }
            let opened_before = database_image_connection(&check)?;
            drop(check);
            if rehearsal_file(&dir.join("zach-v2.sqlite3"), uid)?.1 != db_id {
                return Err("IDENTITY_CHANGED".into());
            }
            let store = V2Store::open(&dir.join("zach-v2.sqlite3")).map_err(|_| "DATABASE_OPEN")?;
            let (mut c, _handle) = Coordinator::create(store, dir.clone());
            let units = Arc::new(RehearsalUnits::default());
            let ws = Arc::new(RehearsalWs {
                export: export.to_string(),
                reads: AtomicUsize::new(0),
                mutations: AtomicUsize::new(0),
            });
            driver_counters = Some((units.clone(), ws.clone()));
            c.controller = units.clone();
            c.ws = ws.clone();
            c.submission_probe = Some(BTreeMap::new());
            let before = database_image(&mut c.store)?;
            if before != opened_before {
                return Err("DATABASE_OPEN_EFFECT".into());
            }
            let startup = rehearsal_startup(&mut c).map_err(|_| "STARTUP_REFUSED");
            rehearsal_effects(&before, &database_image(&mut c.store)?, &mut result);
            startup?;
            if before != database_image(&mut c.store)? {
                return Err("STARTUP_EFFECT".into());
            }
            result["phases"]["startup_before_export_completed"] = true.into();
            let pass = rehearsal_pass(&mut c, &mut RehearsalDelivery::default())
                .map_err(|_| "COORDINATOR_EFFECT");
            rehearsal_effects(&before, &database_image(&mut c.store)?, &mut result);
            if pass.is_err() {
                rehearsal_counts(&c, &mut result)?;
            }
            pass?;
            let exact =
                c.ws.execute(&["export".into(), "--sync".into(), "--json".into()])
                    .map_err(|_| "EXPORT_FAKE")?;
            if exact.as_bytes() != export_bytes {
                return Err("EXPORT_BINDING".into());
            }
            let standard_before = database_image(&mut c.store)?;
            let standard = rehearsal_standard(&mut c, records).map_err(|_| "STANDARD_EFFECT");
            if standard.is_err() {
                rehearsal_effects(
                    &standard_before,
                    &database_image(&mut c.store)?,
                    &mut result,
                );
                rehearsal_counts(&c, &mut result)?;
            }
            standard?;
            result["phases"]["standard_intake_completed"] = true.into();
            let baseline = database_image(&mut c.store)?;
            let pass = rehearsal_pass(&mut c, &mut RehearsalDelivery::default())
                .map_err(|_| "COORDINATOR_EFFECT");
            rehearsal_effects(&baseline, &database_image(&mut c.store)?, &mut result);
            rehearsal_counts(&c, &mut result)?;
            pass?;
            if units.mutations.load(Ordering::Relaxed) != 0
                || ws.mutations.load(Ordering::Relaxed) != 0
            {
                return Err("FAKE_MUTATION".into());
            }
            drop(c);
            let (mut c, _restart_handle) = Coordinator::create(
                V2Store::open(&dir.join("zach-v2.sqlite3")).map_err(|_| "DATABASE_REOPEN")?,
                dir.clone(),
            );
            c.controller = units.clone();
            c.ws = ws.clone();
            c.submission_probe = Some(BTreeMap::new());
            let startup = rehearsal_startup(&mut c).map_err(|_| "RESTART_REFUSED");
            rehearsal_effects(&baseline, &database_image(&mut c.store)?, &mut result);
            startup?;
            if baseline != database_image(&mut c.store)? {
                return Err("RESTART_EFFECT".into());
            }
            let pass = rehearsal_pass(&mut c, &mut RehearsalDelivery::default())
                .map_err(|_| "COORDINATOR_EFFECT");
            rehearsal_effects(&baseline, &database_image(&mut c.store)?, &mut result);
            rehearsal_counts(&c, &mut result)?;
            pass?;
            if !c.jobs.is_empty()
                || units.mutations.load(Ordering::Relaxed) != 0
                || ws.mutations.load(Ordering::Relaxed) != 0
            {
                return Err("NOT_QUIESCENT".into());
            }
            for key in [
                "restart_completed",
                "terminal_reconciliation_completed",
                "lifecycle_completed",
                "decisions_completed",
                "gates_completed",
                "dispatch_completed",
                "merge_completed",
                "delivery_completed",
                "quiescent",
            ] {
                result["phases"][key] = true.into();
            }
            result["checks"]["raw_inventory_and_history_compared"] = true.into();
            result["checks"]["only_reviewed_differences"] = true.into();
            Ok(())
        })();
        if let Some((units, ws)) = driver_counters {
            let unit_mutations = units.mutations.load(Ordering::Relaxed);
            let publications = ws.mutations.load(Ordering::Relaxed);
            for (key, n) in [
                ("other", unit_mutations),
                ("publication", publications),
                ("lifecycle_mutation", publications),
            ] {
                result["forbidden_intents"][key] = serde_json::json!(
                    result["forbidden_intents"][key].as_u64().unwrap_or(0) + n as u64
                );
            }
            if unit_mutations != 0 || publications != 0 {
                outcome = Err("FAKE_MUTATION".into());
            }
        }
        let recheck = (|| -> Result<(), String> {
            rehearsal_entries(&dir, uid, true)?;
            let m = std::fs::symlink_metadata(&dir).map_err(|_| "IDENTITY_CHANGED")?;
            if (m.dev(), m.ino()) != dir_identity || m.uid() != uid || m.mode() & 0o7777 != 0o700 {
                return Err("IDENTITY_CHANGED".into());
            }
            for (name, id, hash) in [
                ("zach-v2.sqlite3", db_id, None),
                (
                    "canonical-export.json",
                    export_id,
                    Some(rehearsal_sha256(&export_bytes)),
                ),
                (
                    "copy-only.json",
                    marker_id,
                    Some(rehearsal_sha256(&marker_bytes)),
                ),
            ] {
                let (file, current) = rehearsal_file(&dir.join(name), uid)?;
                if id != current {
                    return Err("IDENTITY_CHANGED".into());
                }
                if let Some(hash) = hash {
                    if rehearsal_sha256(&rehearsal_bytes(file, 16 * 1024 * 1024)?) != hash {
                        return Err("IDENTITY_CHANGED".into());
                    }
                }
            }
            Ok(())
        })();
        if recheck.is_ok() {
            result["checks"]["input_identity_rechecked"] = true.into();
        }
        let mut outcome = outcome.and(recheck);
        if outcome.is_ok() {
            let zero = |section: &str| {
                result[section]
                    .as_object()
                    .is_some_and(|o| o.values().all(|n| n.as_u64() == Some(0)))
            };
            let all_true = |section: &str| {
                result[section]
                    .as_object()
                    .is_some_and(|o| o.values().all(|n| n.as_bool() == Some(true)))
            };
            let poll = &result["delivery_poll"];
            if !zero("forbidden_intents")
                || !zero("effects")
                || !all_true("phases")
                || !all_true("positive_controls")
                || poll["attempted"] != poll["executed"]
                || poll["executed"] != poll["completed"]
                || poll["fake_mutation_attempts"] != 0
            {
                outcome = Err("RESULT_INVARIANT".into());
            }
        }
        match &outcome {
            Ok(()) => {
                result["status"] = "PASS".into();
                result["failure_class"] = "NONE".into();
            }
            Err(class) => result["failure_class"] = class.clone().into(),
        }
        let output = dir.join("result.json");
        let temporary = dir.join(".result.tmp");
        if output.exists() || temporary.exists() {
            return Err("OUTPUT_EXISTS".into());
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|_| "OUTPUT_WRITE")?;
        file.write_all(&serde_json::to_vec(&result).map_err(|_| "RESULT_SCHEMA")?)
            .map_err(|_| "OUTPUT_WRITE")?;
        file.sync_all().map_err(|_| "OUTPUT_WRITE")?;
        use std::os::unix::ffi::OsStrExt;
        let from =
            std::ffi::CString::new(temporary.as_os_str().as_bytes()).map_err(|_| "OUTPUT_WRITE")?;
        let to =
            std::ffi::CString::new(output.as_os_str().as_bytes()).map_err(|_| "OUTPUT_WRITE")?;
        if unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err("OUTPUT_WRITE".into());
        }
        rehearsal_file(&output, uid)?;
        outcome
    }

    #[test]
    fn rehearsal_input_open_rejects_links_and_nonprivate_modes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDirectory::new();
        let file = dir.0.join("synthetic-input");
        runner::write_secure_file(&file, b"synthetic").unwrap();
        let uid = unsafe { libc::geteuid() };
        assert!(rehearsal_file(&file, uid).is_ok());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(rehearsal_file(&file, uid).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let hard = dir.0.join("hard");
        std::fs::hard_link(&file, &hard).unwrap();
        assert!(rehearsal_file(&file, uid).is_err());
        std::fs::remove_file(hard).unwrap();
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(rehearsal_file(&link, uid).is_err());
    }

    #[test]
    fn offline_empty_terminal_is_visible_in_actual_snapshot_without_event() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let payload = serde_json::json!({"schema_version":2,"tasks":[{"id":"empty-snapshot","repository":"synthetic","status":"In Progress","autonomous_consent":false}]});
        let old = intake::decode_export_records(&payload.to_string())
            .unwrap()
            .remove(0);
        c.save(&old).unwrap();
        let mut incoming = old.clone();
        incoming.status = "Done".into();
        c.store
            .sync_task_with_mode(
                &incoming,
                crate::v2::store::SyncMode::ReconcileFinishedLegacy,
            )
            .unwrap();
        assert!(c.store.list_events_since(None, 0, 100).unwrap().is_empty());
        let messages = c
            .socket_command(ClientCommand::Subscribe {
                group: None,
                since_seq: None,
                once: None,
            })
            .unwrap();
        assert!(
            matches!(&messages[0],ServerMessage::Snapshot{tasks,..} if tasks.len()==1 && tasks[0].status=="Done")
        );
    }

    #[test]
    fn rehearsal_sha_and_strict_marker_contract() {
        assert_eq!(
            rehearsal_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            rehearsal_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let marker = serde_json::json!({"schema_version":1,"purpose":"zach039-exclusive-copy","run_id":"synthetic-run","database_sha256":"a".repeat(64),"export_sha256":"b".repeat(64),"native_candidate_sha256":"c".repeat(64),"infra_candidate_sha256":"d".repeat(64)});
        assert!(serde_json::from_value::<RehearsalMarker>(marker.clone()).is_ok());
        let mut extra = marker.clone();
        extra["unexpected"] = true.into();
        assert!(serde_json::from_value::<RehearsalMarker>(extra).is_err());
        let raw = marker.to_string();
        assert!(
            serde_json::from_str::<RehearsalMarker>(&raw.replacen(
                '{',
                "{\"schema_version\":1,",
                1
            ))
            .is_err()
        );
        assert!(!digest_shape(&"A".repeat(64)));
    }

    #[test]
    fn retries_are_durable_bounded_by_class_and_generation_with_backoff() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        for class in ["infra", "semantic"] {
            let t = task(class);
            c.save(&t).unwrap();
            for failure in 1..=3 {
                c.fail_task(class, "failed", Some(class)).unwrap();
                let saved = c.task(class).unwrap();
                assert_eq!(saved.retry_count, failure);
                assert!(saved.active_attempt_id.is_none());
                if failure <= 2 {
                    assert_eq!(saved.status, "Ready");
                    assert!(
                        saved.next_retry_epoch >= now_epoch() + if failure == 1 { 14 } else { 29 }
                    );
                } else {
                    assert_eq!(saved.status, "Blocked");
                }
            }
            let decision = c
                .store
                .list_decisions(true, None)
                .unwrap()
                .into_iter()
                .find(|d| d.task_id == class)
                .unwrap();
            let resolved = c
                .store
                .resolve_decision(&decision.decision_id, "Retry stage", "alice", None)
                .unwrap();
            let DecisionResolution::Resolved(decision) = resolved else {
                panic!("not resolved")
            };
            c.apply_decision(&decision).unwrap();
            let reset = c.task(class).unwrap();
            assert_eq!(reset.memory.retry_generation, 1);
            assert!(reset.memory.retry_reset_epoch > 0);
            assert_eq!(reset.next_retry_epoch, 0);
            c.fail_task(class, "failed after manual reset", Some(class))
                .unwrap();
            assert_eq!(c.task(class).unwrap().status, "Ready");
        }
        for weight in ["XS", "L"] {
            let mut t = task(weight);
            t.weight = weight.into();
            c.save(&t).unwrap();
            c.fail_task(weight, "scope_violation", Some("policy"))
                .unwrap();
            assert_eq!(c.task(weight).unwrap().status, "Blocked");
        }
        assert_eq!(pipeline::retry_backoff(1), 15);
        assert_eq!(pipeline::retry_backoff(2), 30);
        assert_eq!(pipeline::retry_backoff(20), 300);
    }

    #[test]
    fn decisions_validate_choice_and_rejection_never_sets_ready() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let t = task("decision");
        c.save(&t).unwrap();
        c.store
            .open_decision(
                "d",
                "decision",
                "test",
                "retries_exhausted",
                "retry?",
                &["Retry stage".into(), "Abort task".into()],
                Some(0),
                "failed",
                None,
            )
            .unwrap();
        assert!(
            c.store
                .resolve_decision("d", "Approve", "alice", None)
                .is_err()
        );
        let DecisionResolution::Resolved(decision) = c
            .store
            .resolve_decision("d", "Abort task", "alice", None)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(c.task("decision").unwrap().status, "Blocked");
        c.apply_decision(&decision).unwrap();
        assert_eq!(c.task("decision").unwrap().status, "Blocked");
        assert!(matches!(
            c.store
                .resolve_decision("d", "Retry stage", "bob", None)
                .unwrap(),
            DecisionResolution::AlreadyResolved(_)
        ));
        c.apply_decision(&decision).unwrap();
        assert_eq!(
            c.task("decision").unwrap().memory.applied_decisions.len(),
            1
        );
    }

    #[test]
    fn human_approval_publishes_real_actor_and_sha_before_advancing() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let mut t = task("human");
        t.weight = "L".into();
        t.required_stages = intake::default_required_stages("L");
        t.stages_completed = vec!["plan".into(), "plan-review".into()];
        c.save(&t).unwrap();
        c.evaluate_gates().unwrap();
        let d = c.store.list_decisions(true, None).unwrap().remove(0);
        let DecisionResolution::Resolved(d) = c
            .store
            .resolve_decision(
                &d.decision_id,
                "Approve",
                "alice",
                Some("Reviewed plan; approved"),
            )
            .unwrap()
        else {
            panic!()
        };
        c.apply_decision(&d).unwrap();
        assert_eq!(c.task("human").unwrap().status, "Blocked");
        let ops = c.store.lifecycle_ops().unwrap();
        let op = &ops[0];
        assert!(op.args.windows(2).any(|a| a == ["--actor", "alice"]));
        assert!(op.args.windows(2).any(|a| a == ["--sha", "base"]));
        c.lifecycle_ack(&op.operation_id, "").unwrap();
        let saved = c.task("human").unwrap();
        assert_eq!(saved.status, "Ready");
        assert!(
            saved
                .stages_completed
                .contains(&"human-plan-approval".into())
        );
        c.lifecycle_ack(&op.operation_id, "").unwrap();
        assert_eq!(c.task("human").unwrap().memory.applied_decisions.len(), 1);
    }

    #[test]
    fn valid_review_rework_uses_separate_budget_and_publication_checkpoint_recovers() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let mut t = task("rework");
        t.current_stage = Some("pr-review".into());
        t.stages_completed = vec!["impl".into()];
        let mut a = seed_attempt(&mut c, t, "review-1");
        a.phase = "POSTPROCESSING".into();
        a.status = "PASSED".into();
        c.store.record_stage_attempt(&a).unwrap();
        let mut t = c.task("rework").unwrap();
        t.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
            attempt_id: a.attempt_id.clone(),
            operation: "PUBLISH_CHANGES_REQUESTED".into(),
        });
        c.save(&t).unwrap();
        c.resume_pipeline_steps().unwrap();
        let ops = c.store.lifecycle_ops().unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].kind, "pr-review");
        assert!(c.jobs.is_empty());
        c.lifecycle_ack(&ops[0].operation_id, "").unwrap();
        let saved = c.task("rework").unwrap();
        assert_eq!(saved.memory.review_rework_count, 1);
        assert_eq!(saved.retry_count, 0);
        assert_eq!(saved.next_retry_epoch, 0);
        assert_eq!(saved.current_stage.as_deref(), Some("impl"));
        assert!(!saved.stages_completed.contains(&"impl".into()));
        let mut saved = saved;
        for _ in 0..2 {
            c.review_rework(&mut saved, "pr-review").unwrap();
            c.save(&saved).unwrap();
        }
        assert_eq!(saved.status, "Blocked");
        assert_eq!(saved.retry_count, 0);
    }

    #[test]
    fn close_failure_retains_receipt_and_only_close_ack_marks_done() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let mut t = task("close");
        t.status = "Queued for Merge".into();
        t.memory.merge_checkpoint = Some(MergeCheckpoint {
            phase: "CLOSE_PENDING".into(),
            target_sha: "head".into(),
            pr_number: 9,
            merge_sha: Some("merged".into()),
            post_merge_verified: true,
            phase_started_epoch: now_epoch(),
        });
        c.save(&t).unwrap();
        c.store
            .acquire_path_locks("close", &["*".into()], "close")
            .unwrap();
        c.store
            .enqueue_merge_queue("close", "close", 9, "head")
            .unwrap();
        let op = op(&t, "close-op", "close");
        c.store.enqueue_lifecycle(&op).unwrap();
        for _ in 0..3 {
            c.store
                .update_lifecycle("close-op", "IN_FLIGHT", None, 0)
                .unwrap();
            c.lifecycle_failed("close-op", "remote close failed")
                .unwrap();
        }
        let failed = c.task("close").unwrap();
        assert_eq!(failed.status, "Blocked");
        assert_eq!(failed.memory.merge_checkpoint, t.memory.merge_checkpoint);
        assert_eq!(c.store.list_path_locks(None).unwrap().len(), 1);
        let decision = c.store.list_decisions(true, None).unwrap().remove(0);
        assert!(decision.options.contains(&"Retry close".into()));
        assert!(!decision.options.contains(&"Retry merge".into()));
        c.lifecycle_ack("close-op", "").unwrap();
        assert_eq!(c.task("close").unwrap().status, "Done");
        assert!(c.store.list_merge_queue(None).unwrap().is_empty());
        assert!(c.store.list_path_locks(None).unwrap().is_empty());
    }

    #[test]
    fn reattach_and_dual_signal_liveness_never_confuse_missing_cpu_with_stall() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let t = task("live");
        let a = seed_attempt(&mut c, t.clone(), "live-attempt");
        let m = manifest(&dir.0, &t, &a.attempt_id);
        c.observed(&a.attempt_id, running(), None, Ok(m.clone()), None)
            .unwrap();
        let attached = c.store.get_stage_attempt(&a.attempt_id).unwrap().unwrap();
        assert_eq!(attached.phase, "RUNNING");
        assert!(attached.last_liveness_epoch >= now_epoch() - 1);
        assert_eq!(attached.invocation_id.as_deref(), Some("invocation"));
        for (bytes, cpu, expected) in [
            (1, Some(100), "RUNNING"),
            (0, Some(101), "RUNNING"),
            (0, None, "RUNNING"),
            (0, Some(100), "HARVESTED"),
        ] {
            let mut old = a.clone();
            old.invocation_id = Some("invocation".into());
            c.store.record_stage_attempt(&old).unwrap();
            let mut observation = running();
            observation.output_bytes = bytes;
            observation.cpu_usage_usec = cpu;
            let mut m = m.clone();
            m.spec.stall_timeout_secs = 10;
            c.observed(&a.attempt_id, observation, None, Ok(m), None)
                .unwrap();
            let saved = c.store.get_stage_attempt(&a.attempt_id).unwrap().unwrap();
            assert_eq!(saved.phase, expected);
            if expected == "HARVESTED" {
                assert_eq!(saved.status, "STALLED");
                assert_eq!(saved.failure_class.as_deref(), Some("infra"));
            }
        }
    }

    #[test]
    fn manager_errors_do_not_mark_units_lost_and_worker_panics_become_task_events() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let a = seed_attempt(&mut c, task("manager"), "observed");
        c.handle_event(CoordinatorEvent::Completed {
            key: "observe:observed".into(),
            task_id: Some("manager".into()),
            result: Box::new(Err("manager unavailable".into())),
        })
        .unwrap();
        assert_eq!(
            c.store
                .get_stage_attempt(&a.attempt_id)
                .unwrap()
                .unwrap()
                .status,
            "RUNNING"
        );
        let t = task("panic");
        c.save(&t).unwrap();
        assert!(c.submit(
            "prepare:panic".into(),
            Some("panic".into()),
            0,
            Box::new(|| panic!("injected worker panic"))
        ));
        let event = c.rx.recv_timeout(Duration::from_secs(2)).unwrap();
        c.handle_event(event).unwrap();
        assert_eq!(c.task("panic").unwrap().status, "Ready");
        assert_eq!(c.task("panic").unwrap().retry_count, 1);
    }

    #[test]
    fn singleton_lock_is_exclusive_and_close_on_exec() {
        let dir = TestDirectory::new();
        let lock = DaemonLock::acquire(&dir.0).unwrap();
        assert!(DaemonLock::acquire(&dir.0).is_err());
        assert_ne!(
            unsafe { libc::fcntl(lock._file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        drop(lock);
        assert!(DaemonLock::acquire(&dir.0).is_ok());
    }
    #[test]
    fn slow_checks_governance_and_merge_jobs_do_not_block_socket_status_or_decide() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixStream;
        let dir = TestDirectory::new();
        let (mut c, handle) =
            Coordinator::create(V2Store::open_in_memory().unwrap(), dir.0.clone());
        c.preflight = true;
        c.reconciled = true;
        c.synced = true;
        c.last_export = Instant::now();
        let t = task("responsive");
        c.save(&t).unwrap();
        c.store
            .open_decision(
                "responsive-decision",
                &t.task_id,
                &t.task_group,
                "test",
                "choose",
                &["Abort task".into()],
                Some(0),
                "socket liveness",
                None,
            )
            .unwrap();
        let mut releases = Vec::new();
        for (key, pool) in [("check:hold", 0), ("ws:hold", 2), ("merge:hold", 0)] {
            let (tx, rx) = mpsc::channel();
            releases.push(tx);
            c.submit(
                key.into(),
                None,
                pool,
                Box::new(move || {
                    rx.recv().unwrap();
                    Ok(WorkerResult::Preflight)
                }),
            );
        }
        let coordinator_thread = std::thread::spawn(move || c.run());
        let socket_path = PathBuf::from(format!("target/z25-socket-{}.sock", std::process::id()));
        let mut server = crate::v2::socket::DaemonServer::bind(&socket_path, 0).unwrap();
        let shutdown = server.shutdown.clone();
        let socket_thread = std::thread::spawn(move || server.run_coordinated(handle, false));
        let mut client = UnixStream::connect(&socket_path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let start = Instant::now();
        crate::v2::socket::write_ndjson(&mut client, &ClientCommand::Status).unwrap();
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("STATUS"));
        assert!(start.elapsed() < Duration::from_millis(500));
        let start = Instant::now();
        crate::v2::socket::write_ndjson(
            reader.get_mut(),
            &ClientCommand::Decide {
                decision_id: "responsive-decision".into(),
                choice: "Abort task".into(),
                by: Some("alice".into()),
                note: None,
            },
        )
        .unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("RESOLVED"));
        assert!(start.elapsed() < Duration::from_millis(500));
        for tx in releases {
            tx.send(()).unwrap();
        }
        shutdown.store(true, Ordering::Relaxed);
        socket_thread.join().unwrap().unwrap();
        coordinator_thread.join().unwrap().unwrap();
    }

    #[test]
    fn startup_repairs_legacy_pre_attempt_window_and_reacquires_repository_ownership() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let mut t = task("interrupted");
        t.status = "Planning".into();
        t.current_stage = Some("plan".into());
        c.save(&t).unwrap();
        c.worker_result(WorkerResult::Reconciled).unwrap();
        let saved = c.task(&t.task_id).unwrap();
        assert_eq!(saved.status, "Ready");
        assert!(saved.next_retry_epoch > now_epoch());
        let attempts = c.store.list_stage_attempts(&t.task_id).unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].failure_class.as_deref(), Some("infra"));
        assert_eq!(attempts[0].phase, "COMPLETE");
        assert!(c.store.list_path_locks(None).unwrap().is_empty());
    }

    #[test]
    fn pending_parity_ack_updates_review_sha_and_requires_new_l_human_gate() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let mut t = task("parity");
        t.weight = "L".into();
        t.required_stages = intake::default_required_stages("L");
        t.stages_completed = t.required_stages.clone();
        t.status = "Queued for Merge".into();
        t.memory.merge_checkpoint = Some(MergeCheckpoint {
            phase: "DIFF".into(),
            target_sha: "new-head".into(),
            pr_number: 9,
            ..MergeCheckpoint::default()
        });
        c.save(&t).unwrap();
        c.store
            .enqueue_merge_queue(&t.repository, &t.task_id, 9, "head")
            .unwrap();
        let op = op(&t, "parity-op", "merge-parity");
        c.store.enqueue_lifecycle(&op).unwrap();
        c.lifecycle_ack("parity-op", "").unwrap();
        let saved = c.task(&t.task_id).unwrap();
        assert_eq!(saved.reviewed_sha.as_deref(), Some("new-head"));
        assert!(
            !saved
                .stages_completed
                .contains(&"human-merge-approval".into())
        );
        assert_eq!(
            saved.memory.merge_checkpoint.as_ref().unwrap().phase,
            "PUSH"
        );
        assert_eq!(
            c.store.list_merge_queue(None).unwrap()[0].reviewed_sha,
            "new-head"
        );
        c.evaluate_gates().unwrap();
        let decisions = c.store.list_decisions(true, None).unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].sha.as_deref(), Some("new-head"));
        assert_eq!(c.task(&t.task_id).unwrap().status, "Blocked");
    }

    #[test]
    fn migrations_reopen_without_discarding_supervision_or_nullable_tokens() {
        let dir = TestDirectory::new();
        let db = dir.0.join("state.sqlite3");
        let t = task("migration");
        let mut a = attempt(&t, "migration-attempt");
        a.phase = "HARVESTED".into();
        a.last_output_bytes = 45;
        a.retry_generation = 7;
        a.exit_code = Some(0);
        a.exit_code_kind = Some("1".into());
        a.control_group = Some("/kept".into());
        {
            let mut store = V2Store::open(&db).unwrap();
            let mut t = t.clone();
            t.next_retry_epoch = 500;
            t.lease_owner = Some("old-instance".into());
            t.memory.retry_generation = 7;
            t.memory.retry_reset_epoch = 123;
            store.upsert_task(&t).unwrap();
            store.record_stage_attempt(&a).unwrap();
        }
        for _ in 0..3 {
            let store = V2Store::open(&db).unwrap();
            assert_eq!(store.get_stage_attempt(&a.attempt_id).unwrap().unwrap(), a);
            let saved = store.get_task(&t.task_id).unwrap().unwrap();
            assert_eq!(saved.next_retry_epoch, 500);
            assert_eq!(saved.memory.retry_generation, 7);
            assert_eq!(saved.lease_owner.as_deref(), Some("old-instance"));
            assert_eq!(store.meta("schema_version").unwrap().as_deref(), Some("4"));
        }
    }
    #[test]
    fn task_attempt_and_start_intent_transactions_roll_back_as_a_unit() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let mut t = task("atomic-start");
        t.executor = None;
        t.memory.governance_started = false;
        c.save(&t).unwrap();
        let op = op(&t, "start-atomic", "start");
        let mut next = t.clone();
        next.executor = Some("zach".into());
        c.store.connection_mut().execute_batch("CREATE TRIGGER reject_intent BEFORE INSERT ON lifecycle_ops BEGIN SELECT RAISE(ABORT,'injected intent failure'); END;").unwrap();
        assert!(c.store.checkpoint_with_lifecycle(&next, &op).is_err());
        assert!(c.task(&t.task_id).unwrap().executor.is_none());
        assert!(c.store.lifecycle_ops().unwrap().is_empty());
        c.store
            .connection_mut()
            .execute_batch("DROP TRIGGER reject_intent;")
            .unwrap();
        c.store.checkpoint_with_lifecycle(&next, &op).unwrap();
        assert_eq!(
            c.task(&t.task_id).unwrap().executor.as_deref(),
            Some("zach")
        );
        let a = seed_attempt(&mut c, task("atomic-attempt"), "atomic-attempt");
        let mut next = c.task("atomic-attempt").unwrap();
        next.status = "Ready".into();
        next.active_attempt_id = None;
        let mut completed = a.clone();
        completed.phase = "COMPLETE".into();
        c.store.connection_mut().execute_batch("CREATE TRIGGER reject_attempt BEFORE UPDATE ON stage_attempts BEGIN SELECT RAISE(ABORT,'injected attempt failure'); END;").unwrap();
        assert!(
            c.store
                .transition_attempt(&next, &completed, true, None)
                .is_err()
        );
        assert_eq!(
            c.task("atomic-attempt")
                .unwrap()
                .active_attempt_id
                .as_deref(),
            Some("atomic-attempt")
        );
        assert_eq!(
            c.store
                .get_stage_attempt("atomic-attempt")
                .unwrap()
                .unwrap()
                .phase,
            "RUNNING"
        );
    }

    #[test]
    fn halted_workers_stop_and_late_publication_cannot_make_them_ready() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let t = task("halt");
        let a = seed_attempt(&mut c, t.clone(), "halt-attempt");
        let mut current = c.task("halt").unwrap();
        current.memory.halt_requested = true;
        current.status = "Blocked".into();
        c.save(&current).unwrap();
        c.observed(
            &a.attempt_id,
            running(),
            None,
            Ok(manifest(&dir.0, &t, &a.attempt_id)),
            None,
        )
        .unwrap();
        assert_eq!(
            c.store
                .get_stage_attempt(&a.attempt_id)
                .unwrap()
                .unwrap()
                .phase,
            "HARVESTED"
        );
        c.worker_result(WorkerResult::Stopped(a.attempt_id.clone()))
            .unwrap();
        assert_eq!(c.task("halt").unwrap().status, "Blocked");
        assert_eq!(c.task("halt").unwrap().retry_count, 0);
        let op = op(&t, "late-impl", "impl");
        c.store.enqueue_lifecycle(&op).unwrap();
        c.lifecycle_ack("late-impl", "").unwrap();
        assert_eq!(c.task("halt").unwrap().status, "Blocked");
        assert!(
            !c.task("halt")
                .unwrap()
                .stages_completed
                .contains(&"impl".into())
        );
    }

    #[test]
    fn late_close_failure_does_not_reopen_acknowledged_done_task() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let mut t = task("late-close");
        t.status = "Queued for Merge".into();
        t.memory.merge_checkpoint = Some(MergeCheckpoint {
            phase: "CLOSE_PENDING".into(),
            pr_number: 9,
            merge_sha: Some("merged".into()),
            post_merge_verified: true,
            ..Default::default()
        });
        c.save(&t).unwrap();
        c.store
            .enqueue_lifecycle(&op(&t, "late-close-op", "close"))
            .unwrap();
        c.lifecycle_ack("late-close-op", "").unwrap();
        c.lifecycle_failed("late-close-op", "late worker error")
            .unwrap();
        assert_eq!(c.task("late-close").unwrap().status, "Done");
        assert_eq!(c.store.lifecycle_ops().unwrap()[0].state, "ACKNOWLEDGED");
        assert!(c.store.list_decisions(true, None).unwrap().is_empty());
    }

    #[test]
    fn merge_lane_release_is_durable_and_requeues_cannot_bypass_another_owner() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let mut t = task("lane");
        t.required_stages = vec!["impl".into()];
        t.stages_completed = t.required_stages.clone();
        t.memory.merge_checkpoint = Some(MergeCheckpoint {
            phase: "LANE_BLOCKED".into(),
            pr_number: 9,
            merge_sha: Some("receipt".into()),
            ..Default::default()
        });
        t.status = "Blocked".into();
        c.save(&t).unwrap();
        c.store
            .acquire_path_locks("lane", &["*".into()], "lane")
            .unwrap();
        let d = c
            .store
            .open_decision(
                "lane-decision",
                "lane",
                "test",
                "post_merge_failure",
                "unblock?",
                &["Unblock lane".into()],
                Some(0),
                "manual",
                None,
            )
            .unwrap();
        let DecisionResolution::Resolved(d) = c
            .store
            .resolve_decision(&d.decision_id, "Unblock lane", "alice", None)
            .unwrap()
        else {
            panic!()
        };
        c.apply_decision(&d).unwrap();
        c.worker_result(WorkerResult::Reconciled).unwrap();
        assert!(c.store.list_path_locks(None).unwrap().is_empty());
        assert!(c.task("lane").unwrap().memory.merge_lane_released);
        let mut t = task("waiter");
        t.repository = "occupied".into();
        t.stages_completed = t.required_stages.clone();
        c.save(&t).unwrap();
        c.store
            .acquire_path_locks("occupied", &["*".into()], "other")
            .unwrap();
        c.evaluate_gates().unwrap();
        assert!(
            c.store
                .get_merge_queue_entry("occupied", "waiter")
                .unwrap()
                .is_none()
        );
        c.store
            .enqueue_merge_queue("occupied", "waiter", 9, "head")
            .unwrap();
        t.status = "Queued for Merge".into();
        c.save(&t).unwrap();
        c.drive_merges().unwrap();
        assert!(!c.jobs.iter().any(|key| key.starts_with("merge:")));
    }

    #[test]
    fn escalated_impl_is_suspended_until_prerequisites_and_never_relaunched() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let mut t = task("escalated");
        t.lease_owner = Some(c.instance.clone());
        let mut a = seed_attempt(&mut c, t, "saved-impl");
        a.phase = "POSTPROCESSING".into();
        a.status = "PASSED".into();
        c.store.record_stage_attempt(&a).unwrap();
        let mut t = c.task("escalated").unwrap();
        t.weight = "L".into();
        t.context_pack.weight = "L".into();
        t.required_stages = intake::default_required_stages("L");
        c.worker_result(WorkerResult::Pipeline {
            attempt_id: a.attempt_id.clone(),
            step: PipelineStepResult {
                task: t,
                next_operation: "PLAN_PREREQUISITES".into(),
                publication: None,
            },
        })
        .unwrap();
        let saved = c.task("escalated").unwrap();
        assert_eq!(saved.current_stage.as_deref(), Some("plan"));
        assert_eq!(
            saved.memory.suspended_impl_attempt_id.as_deref(),
            Some("saved-impl")
        );
        assert!(saved.active_attempt_id.is_none());
        c.worker_result(WorkerResult::Reconciled).unwrap();
        c.dispatch().unwrap();
        assert_eq!(
            c.task("escalated").unwrap().current_stage.as_deref(),
            Some("plan")
        );
        assert!(c.store.get_stage_attempt("saved-impl").unwrap().is_some());
        let mut t = c.task("escalated").unwrap();
        t.status = "Ready".into();
        t.memory.pipeline_checkpoint = None;
        t.stages_completed = vec![
            "plan".into(),
            "plan-review".into(),
            "human-plan-approval".into(),
        ];
        c.save(&t).unwrap();
        c.dispatch().unwrap();
        let resumed = c.task("escalated").unwrap();
        assert_eq!(resumed.active_attempt_id.as_deref(), Some("saved-impl"));
        assert_eq!(
            resumed
                .memory
                .pipeline_checkpoint
                .as_ref()
                .unwrap()
                .operation,
            "VALIDATE"
        );
        assert_eq!(c.store.list_stage_attempts("escalated").unwrap().len(), 1);
    }

    #[test]
    fn authoritative_plan_receipt_escalates_before_review_or_impl_dispatch() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let mut t = task("floor");
        t.weight = "M".into();
        t.current_stage = Some("plan".into());
        t.required_stages = intake::default_required_stages("M");
        let mut a = seed_attempt(&mut c, t, "floor-plan");
        a.phase = "POSTPROCESSING".into();
        a.status = "PASSED".into();
        c.store.record_stage_attempt(&a).unwrap();
        let mut t = c.task("floor").unwrap();
        t.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
            attempt_id: a.attempt_id.clone(),
            operation: "PUBLISH_APPROVED".into(),
        });
        c.save(&t).unwrap();
        let op = intake::stage_operation(
            &t,
            "floor-op",
            "plan",
            &dir.0.join("plan.md"),
            None,
            Some("base"),
            "zach",
        );
        c.store.enqueue_lifecycle(&op).unwrap();
        c.lifecycle_ack(
            "floor-op",
            r#"{"task_id":"floor","stage":"plan","sha":"base","weight":"L"}"#,
        )
        .unwrap();
        let saved = c.task("floor").unwrap();
        assert_eq!(saved.weight, "L");
        assert_eq!(saved.context_pack.weight, "L");
        assert!(
            saved
                .required_stages
                .contains(&"human-plan-approval".into())
        );
        assert_eq!(
            scheduler::determine_next_stage(&saved).as_deref(),
            Some("plan-review")
        );
    }

    #[test]
    fn rework_grants_have_new_decisions_without_resetting_execution_retry_generation() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let mut t = task("grants");
        c.save(&t).unwrap();
        for expected_generation in 0..2 {
            t = c.task("grants").unwrap();
            t.memory.review_rework_count = 2;
            c.review_rework(&mut t, "pr-review").unwrap();
            c.save(&t).unwrap();
            let d = c.store.list_decisions(true, None).unwrap().remove(0);
            assert_eq!(t.memory.review_rework_generation, expected_generation);
            assert_eq!(t.memory.review_rework_count, 2);
            let DecisionResolution::Resolved(d) = c
                .store
                .resolve_decision(&d.decision_id, "Authorize additional rework", "alice", None)
                .unwrap()
            else {
                panic!()
            };
            c.apply_decision(&d).unwrap();
            assert_eq!(c.task("grants").unwrap().memory.retry_generation, 0);
        }
        assert_eq!(c.store.list_decisions(false, None).unwrap().len(), 2);
    }

    #[test]
    fn production_socket_replays_more_than_five_thousand_events_without_gaps() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixStream;
        let dir = TestDirectory::new();
        let (mut c, handle) =
            Coordinator::create(V2Store::open_in_memory().unwrap(), dir.0.clone());
        c.preflight = true;
        c.reconciled = true;
        c.synced = true;
        c.last_export = Instant::now();
        c.store.connection_mut().execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<5105) INSERT INTO task_events(task_id,task_group,ts_epoch,event_type,payload_json) SELECT 'events','test',1,'REPLAY_TEST','{}' FROM n;").unwrap();
        let coordinator_thread = std::thread::spawn(move || c.run());
        let path = PathBuf::from(format!("target/z25-replay-{}.sock", std::process::id()));
        let mut server = crate::v2::socket::DaemonServer::bind(&path, 0).unwrap();
        let shutdown = server.shutdown.clone();
        let socket_thread = std::thread::spawn(move || server.run_coordinated(handle, false));
        let mut client = UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        crate::v2::socket::write_ndjson(
            &mut client,
            &ClientCommand::Subscribe {
                group: Some("test".into()),
                since_seq: Some(0),
                once: Some(true),
            },
        )
        .unwrap();
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("SNAPSHOT"));
        let mut count = 0;
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            let value: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(value["type"], "EVENT");
            count += 1;
            assert_eq!(value["event"]["seq_id"], count);
        }
        assert_eq!(count, 5105);
        shutdown.store(true, Ordering::Relaxed);
        socket_thread.join().unwrap().unwrap();
        coordinator_thread.join().unwrap().unwrap();
    }
    #[derive(Default)]
    struct RecordingWsTaskClient {
        calls: Mutex<Vec<Vec<String>>>,
    }
    impl WsTaskClient for RecordingWsTaskClient {
        fn execute(&self, args: &[String]) -> Result<String, String> {
            self.calls.lock().unwrap().push(args.to_vec());
            let id = args.get(1).map(String::as_str).unwrap_or("");
            let sha = args
                .windows(2)
                .find(|pair| pair[0] == "--sha")
                .map(|pair| pair[1].as_str())
                .unwrap_or("base");
            Ok(serde_json::json!({"task_id":id,"stage":args.get(2),"sha":sha,"weight":"M","branch":"task/ordered","worktree":"/governed/ordered"}).to_string())
        }
    }
    #[test]
    fn ws_task_adapter_replays_start_before_plan_and_acknowledges_each_once() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let ws = Arc::new(RecordingWsTaskClient::default());
        c.ws = ws.clone();
        let mut t = task("ordered");
        t.current_stage = Some("plan".into());
        t.weight = "M".into();
        t.required_stages = intake::default_required_stages("M");
        t.memory.governance_started = false;
        let mut a = seed_attempt(&mut c, t, "ordered-plan");
        a.phase = "POSTPROCESSING".into();
        a.status = "PASSED".into();
        c.store.record_stage_attempt(&a).unwrap();
        let mut t = c.task("ordered").unwrap();
        t.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
            attempt_id: a.attempt_id,
            operation: "PUBLISH_APPROVED".into(),
        });
        c.save(&t).unwrap();
        let mut start = op(&t, "ordered-start", "start");
        start.args = vec![
            "start".into(),
            "ordered".into(),
            "--executor".into(),
            "zach".into(),
        ];
        c.store.enqueue_lifecycle(&start).unwrap();
        let mut plan = intake::publish_plan_stage(&t, "ordered-plan-op", &dir.0.join("plan.md"));
        plan.depends_on = Some(start.operation_id.clone());
        c.store.enqueue_lifecycle(&plan).unwrap();
        for _ in 0..2 {
            c.replay_lifecycle().unwrap();
            let event = c.rx.recv_timeout(Duration::from_secs(2)).unwrap();
            c.handle_event(event).unwrap();
        }
        c.replay_lifecycle().unwrap();
        let calls = ws.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][0], "start");
        assert_eq!(&calls[1][..3], ["stage", "ordered", "plan"]);
        assert_eq!(
            c.task("ordered").unwrap().branch.as_deref(),
            Some("task/ordered")
        );
        assert!(
            c.store
                .lifecycle_ops()
                .unwrap()
                .iter()
                .all(|o| o.state == "ACKNOWLEDGED")
        );
        assert!(c.jobs.is_empty());
    }

    struct MockUnitController {
        observed: UnitObservation,
        calls: Mutex<Vec<String>>,
    }
    impl UnitController for MockUnitController {
        fn inspect(&self, unit: &str) -> Result<UnitObservation, String> {
            self.calls.lock().unwrap().push(format!("inspect:{unit}"));
            Ok(self.observed.clone())
        }
        fn launch(&self, _: &AttemptManifest) -> Result<(), String> {
            panic!("reconciliation must never launch")
        }
        fn stop(&self, unit: &str) -> Result<(), String> {
            self.calls.lock().unwrap().push(format!("stop:{unit}"));
            Ok(())
        }
        fn reset_failed(&self, unit: &str) -> Result<(), String> {
            self.calls.lock().unwrap().push(format!("reset:{unit}"));
            Ok(())
        }
        fn list_units(&self) -> Result<Vec<String>, String> {
            Ok(vec!["zach-stage-unrecognized.service".into()])
        }
    }
    #[test]
    fn startup_adopts_exact_live_identity_omitted_from_enumeration_without_relaunch() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let mut t = task("startup");
        t.status = "In Progress".into();
        let a = attempt(&t, "startup-attempt");
        c.save(&t).unwrap();
        c.store.record_stage_attempt(&a).unwrap();
        let controller = MockUnitController {
            observed: running(),
            calls: Mutex::new(Vec::new()),
        };
        let result =
            reconcile_attempt_snapshots(&controller, &dir.0, vec![(t, vec![a.clone()])]).unwrap();
        c.worker_result(result).unwrap();
        let saved = c.task("startup").unwrap();
        assert_eq!(
            saved.active_attempt_id.as_deref(),
            Some(a.attempt_id.as_str())
        );
        assert_eq!(
            c.store
                .get_stage_attempt(&a.attempt_id)
                .unwrap()
                .unwrap()
                .sha_before,
            a.sha_before
        );
        let calls = controller.calls.lock().unwrap();
        assert!(calls.contains(&format!("inspect:{}", a.systemd_unit.unwrap())));
        assert!(calls.contains(&"stop:zach-stage-unrecognized.service".into()));
    }
    #[test]
    fn late_publication_failure_never_reopens_external_terminal_or_aborted_task() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        for status in ["Done", "Cancelled", "Blocked"] {
            let mut task = task(status);
            task.status = status.into();
            task.memory.halt_requested = status == "Blocked";
            c.save(&task).unwrap();
            let operation = op(&task, &format!("terminal-{status}"), "impl");
            c.store.enqueue_lifecycle(&operation).unwrap();
            for _ in 0..3 {
                c.store
                    .update_lifecycle(&operation.operation_id, "IN_FLIGHT", None, 0)
                    .unwrap();
            }
            c.lifecycle_failed(&operation.operation_id, "late provider/publication error")
                .unwrap();
            assert_eq!(c.task(status).unwrap().status, status);
            assert!(c.store.list_decisions(true, None).unwrap().is_empty());
        }
    }
    #[test]
    fn loaded_dead_unit_with_known_exit_metadata_is_harvested_instead_of_lost() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let task = task("dead-exit");
        let a = seed_attempt(&mut c, task.clone(), "dead-attempt");
        runner::write_secure_file(
            &dir.0.join("stdout.jsonl"),
            include_bytes!("../../tests/fixtures/codex_exec_usage.jsonl"),
        )
        .unwrap();
        runner::write_secure_file(&dir.0.join("stderr.log"), b"").unwrap();
        let mut observation = running();
        observation.active_state = "inactive".into();
        observation.sub_state = "dead".into();
        observation.exit_code_kind = "1".into();
        observation.exit_code = Some(0);
        c.observed(
            &a.attempt_id,
            observation,
            None,
            Ok(manifest(&dir.0, &task, &a.attempt_id)),
            None,
        )
        .unwrap();
        assert_eq!(
            c.store
                .get_stage_attempt(&a.attempt_id)
                .unwrap()
                .unwrap()
                .phase,
            "EXIT_OBSERVED"
        );
        let event = c.rx.recv_timeout(Duration::from_secs(2)).unwrap();
        c.handle_event(event).unwrap();
        let saved = c.store.get_stage_attempt(&a.attempt_id).unwrap().unwrap();
        assert_eq!(saved.status, "PASSED");
        assert_eq!(saved.phase, "HARVESTED");
        assert_eq!(saved.sha_before, a.sha_before);
    }
    fn delivery_rows(t: &TaskRecord) -> Vec<crate::v2::store::PostMergeDelivery> {
        let contract = delivery::DeliveryContract {
            schema_version: 1,
            post_merge_workflows: vec![],
            promotions: vec![delivery::tests::promotion()],
        };
        delivery::seed_deliveries(t, &"a".repeat(40), &contract, &[])
    }

    #[test]
    fn delivery_worker_persists_dispatch_intent_and_leaves_coordinator_responsive() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let mut t = task("delivery-worker");
        t.status = "Delivery Pending".into();
        t.github_repo = Some("acme/sample-app".into());
        t.current_stage = None;
        let mut rows = delivery_rows(&t);
        rows[0].state = "plan_dispatch".into();
        rows[0].build_run_id = Some("123".into());
        rows[0].artifact_digest = Some("d".repeat(64));
        rows[0].expected_current = Some("none".into());
        c.store.save_deliveries_and_task(&t, &rows).unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let mut driver = delivery::tests::MockDriver::default();
        driver.dispatch_barrier = Some((entered_tx, resume_rx));
        c.submit_delivery_poll(driver);
        // The worker's store calls are serviced by this owner, with no network
        // operation ever executing inside an access closure.
        let deadline = Instant::now() + Duration::from_secs(5);
        while entered_rx.try_recv().is_err() {
            assert!(Instant::now() < deadline);
            if let Ok(event) = c.rx.recv_timeout(Duration::from_millis(10)) {
                c.handle_event(event).unwrap();
            }
        }
        assert_eq!(
            c.store.list_deliveries(Some(&t.task_id)).unwrap()[0].state,
            "plan_dispatching"
        );
        let started = Instant::now();
        c.store.record_heartbeat(now_epoch()).unwrap();
        assert!(matches!(
            c.socket_command(ClientCommand::Status).unwrap()[0],
            ServerMessage::Status { .. }
        ));
        assert!(started.elapsed() < Duration::from_millis(100));
        // The already-running poll is deduplicated even while network I/O waits.
        c.submit_delivery_poll(delivery::tests::MockDriver::default());
        assert_eq!(
            c.jobs
                .iter()
                .filter(|k| *k == "post-merge-deliveries")
                .count(),
            1
        );
        resume_tx.send(()).unwrap();
        while c.jobs.contains("post-merge-deliveries") {
            let event = c.rx.recv_timeout(Duration::from_secs(2)).unwrap();
            c.handle_event(event).unwrap();
        }
        assert_eq!(
            c.store.list_deliveries(Some(&t.task_id)).unwrap()[0].state,
            "plan_waiting"
        );
    }

    #[test]
    fn delivery_handoff_approval_and_verified_close_preserve_both_lifecycles() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let db = dir.0.join("close.sqlite");
        c.store = V2Store::open(&db).unwrap();
        let ws = Arc::new(RecordingWsTaskClient::default());
        c.ws = ws.clone();
        let mut t = task("delivery-close");
        t.status = "Queued for Merge".into();
        t.github_repo = Some("acme/sample-app".into());
        c.save(&t).unwrap();
        c.store
            .acquire_path_locks(&t.repository, &["*".into()], &t.task_id)
            .unwrap();
        c.store
            .enqueue_merge_queue(&t.repository, &t.task_id, 9, "head")
            .unwrap();
        let cp = MergeCheckpoint {
            phase: "DELIVERY_PENDING".into(),
            pr_number: 9,
            target_sha: "head".into(),
            merge_sha: Some("a".repeat(40)),
            post_merge_verified: true,
            ..Default::default()
        };
        c.merge_result(
            &t.task_id,
            MergePhaseResult::DeliveryHandoff {
                checkpoint: cp,
                deliveries: delivery_rows(&t),
            },
        )
        .unwrap();
        assert!(c.store.list_path_locks(None).unwrap().is_empty());
        assert!(c.store.list_merge_queue(None).unwrap().is_empty());
        assert!(c.store.lifecycle_ops().unwrap().is_empty());
        let mut row = c.store.list_deliveries(Some(&t.task_id)).unwrap().remove(0);
        row.state = "waiting".into();
        row.decision_id = Some("approve-delivery".into());
        c.store.upsert_delivery(&row).unwrap();
        c.store
            .open_decision(
                "approve-delivery",
                &t.task_id,
                &t.task_group,
                "prod_promotion_approval",
                "approve?",
                &["Approve".into(), "Reject".into()],
                Some(0),
                "promotion",
                Some(&"a".repeat(40)),
            )
            .unwrap();
        let DecisionResolution::Resolved(d) = c
            .store
            .resolve_decision("approve-delivery", "Approve", "alice", None)
            .unwrap()
        else {
            panic!()
        };
        c.apply_decision(&d).unwrap();
        assert_eq!(c.task(&t.task_id).unwrap().status, "Delivery Pending");
        assert_eq!(
            c.store.list_deliveries(Some(&t.task_id)).unwrap()[0].state,
            "approved"
        );
        // Even a replayed close intent cannot run before delivery verification.
        let close = merge_queue::close_operation(&t, 9);
        c.store.enqueue_lifecycle(&close).unwrap();
        c.replay_lifecycle().unwrap();
        assert!(ws.calls.lock().unwrap().is_empty());
        let mut verified = c.task(&t.task_id).unwrap();
        verified.memory.merge_checkpoint.as_mut().unwrap().phase = "CLOSE_PENDING".into();
        row.state = "verified".into();
        c.store.upsert_delivery(&row).unwrap();
        c.store
            .save_delivery_status(&verified, Some(std::slice::from_ref(&row)))
            .unwrap();
        c.store
            .save_delivery_status(&verified, Some(&[row]))
            .unwrap();
        c.reconcile_terminal_tasks().unwrap();
        assert_eq!(c.store.lifecycle_ops().unwrap()[0].state, "PENDING");
        c.lifecycle_failed(&close.operation_id, "Governance temporarily unavailable")
            .unwrap();
        assert_eq!(c.task(&t.task_id).unwrap().status, "Delivery Pending");
        // Reopen the real SQLite file after the failed close, retaining its receipt.
        drop(c);
        let (mut c, _) = Coordinator::create(V2Store::open(&db).unwrap(), dir.0.clone());
        c.ws = ws.clone();
        c.reconcile_terminal_tasks().unwrap();
        assert_eq!(c.task(&t.task_id).unwrap().status, "Delivery Pending");
        let mut successor = task("next-task");
        successor.repository = t.repository.clone();
        c.save(&successor).unwrap();
        assert!(
            c.store
                .acquire_path_locks(&t.repository, &["*".into()], &successor.task_id)
                .unwrap()
        );
        let decision = c.store.list_decisions(true, None).unwrap().remove(0);
        let DecisionResolution::Resolved(decision) = c
            .store
            .resolve_decision(&decision.decision_id, "Retry close", "alice", None)
            .unwrap()
        else {
            panic!()
        };
        c.apply_decision(&decision).unwrap();
        assert_eq!(c.task(&t.task_id).unwrap().status, "Delivery Pending");
        c.replay_lifecycle().unwrap();
        let event = c.rx.recv_timeout(Duration::from_secs(2)).unwrap();
        c.handle_event(event).unwrap();
        c.lifecycle_ack(&close.operation_id, "").unwrap(); // duplicate receipt
        assert_eq!(c.task(&t.task_id).unwrap().status, "Done");
        assert_eq!(
            c.store.list_path_locks(None).unwrap()[0].task_id,
            successor.task_id
        );
        assert_eq!(
            ws.calls.lock().unwrap().as_slice(),
            &[vec!["close", "delivery-close", "--pr", "9"]]
        );
        assert_eq!(c.store.lifecycle_ops().unwrap()[0].state, "ACKNOWLEDGED");
        let events = c.store.list_events_since(None, 0, 100).unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|e| e.event_type == "POST_MERGE_DELIVERY_VERIFIED")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| e.event_type == "MERGE_COMPLETED")
                .count(),
            1
        );
        assert!(
            events
                .iter()
                .position(|e| e.event_type == "POST_MERGE_DELIVERY_VERIFIED")
                .unwrap()
                < events
                    .iter()
                    .position(|e| e.event_type == "MERGE_COMPLETED")
                    .unwrap()
        );
    }
    #[test]
    fn delivery_dispatch_rechecks_consent_after_network_probe() {
        for halt in [false, true] {
            let dir = TestDirectory::new();
            let mut c = coordinator(&dir.0);
            let mut t = task("revoked-delivery");
            t.github_repo = Some("acme/sample-app".into());
            t.status = "Delivery Pending".into();
            let mut rows = delivery_rows(&t);
            rows[0].state = "approved".into();
            rows[0].build_run_id = Some("123".into());
            rows[0].artifact_digest = Some("d".repeat(64));
            rows[0].expected_current = Some("none".into());
            rows[0].rule_json["current_source_probe"] =
                serde_json::json!("https://example.invalid/current");
            c.store.save_deliveries_and_task(&t, &rows).unwrap();
            let (entered_tx, entered_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let (dispatch_tx, dispatch_rx) = mpsc::channel();
            let (_dispatch_resume_tx, dispatch_resume_rx) = mpsc::channel();
            let mut driver = delivery::tests::MockDriver::default();
            driver.probe_barrier = Some((entered_tx, resume_rx));
            driver.dispatch_barrier = Some((dispatch_tx, dispatch_resume_rx));
            c.submit_delivery_poll(driver);
            let deadline = Instant::now() + Duration::from_secs(5);
            while entered_rx.try_recv().is_err() {
                assert!(Instant::now() < deadline);
                if let Ok(event) = c.rx.recv_timeout(Duration::from_millis(10)) {
                    c.handle_event(event).unwrap();
                }
            }
            let mut revoked = c.task(&t.task_id).unwrap();
            if halt {
                revoked.memory.halt_requested = true;
            } else {
                revoked.autonomous_consent = false;
            }
            c.save(&revoked).unwrap();
            resume_tx.send(()).unwrap();
            while c.jobs.contains("post-merge-deliveries") {
                let event = c.rx.recv_timeout(Duration::from_secs(2)).unwrap();
                c.handle_event(event).unwrap();
            }
            assert!(
                dispatch_rx.try_recv().is_err(),
                "revoked promotion must not dispatch"
            );
            assert_eq!(
                c.store.list_deliveries(Some(&t.task_id)).unwrap()[0].state,
                "approved"
            );
            assert_eq!(c.task(&t.task_id).unwrap().memory.halt_requested, halt);
            assert_eq!(c.task(&t.task_id).unwrap().autonomous_consent, halt);
        }
    }

    #[test]
    fn legacy_delivery_close_recovers_only_from_matching_receipt_without_reacquiring_lane() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let mut t = task("legacy-delivery");
        t.status = "Done".into();
        t.memory.merge_checkpoint = Some(MergeCheckpoint {
            phase: "CLOSE_PENDING".into(),
            target_sha: "head".into(),
            pr_number: 9,
            merge_sha: Some("a".repeat(40)),
            post_merge_verified: true,
            ..Default::default()
        });
        let mut rows = delivery_rows(&t);
        rows[0].state = "verified".into();
        c.store.save_deliveries_and_task(&t, &rows).unwrap();
        c.store.save_delivery_status(&t, Some(&rows)).unwrap();
        c.reconcile_terminal_tasks().unwrap();
        let saved = c.task(&t.task_id).unwrap();
        assert_eq!(saved.status, "Delivery Pending");
        assert_eq!(saved.memory.merge_checkpoint, t.memory.merge_checkpoint);
        c.last_delivery_poll = Instant::now();
        c.jobs.insert(format!("delivery-close:{}", t.task_id));
        c.poll_deliveries().unwrap();
        assert!(c.store.list_path_locks(None).unwrap().is_empty());
        c.handle_event(CoordinatorEvent::Completed {
            key: format!("delivery-close:{}", t.task_id),
            task_id: Some(t.task_id.clone()),
            result: Box::new(Err(
                "close readback does not match saved merge receipt".into()
            )),
        })
        .unwrap();
        let decision = c.store.list_decisions(true, None).unwrap().remove(0);
        c.poll_deliveries().unwrap();
        assert!(!c.jobs.contains(&format!("delivery-close:{}", t.task_id)));
        let DecisionResolution::Resolved(decision) = c
            .store
            .resolve_decision(&decision.decision_id, "Retry close", "alice", None)
            .unwrap()
        else {
            panic!()
        };
        c.apply_decision(&decision).unwrap();
        assert_eq!(c.task(&t.task_id).unwrap().status, "Delivery Pending");
        assert_eq!(c.task(&t.task_id).unwrap().memory.merge_retry_generation, 1);
        let mut driver = merge_queue::tests::MockMergeDriver {
            pr_merge_state: Some(merge_queue::PrMergeState::Merged(Some("a".repeat(40)))),
            ..Default::default()
        };
        let result =
            merge_queue::run_merge_phase(&dir.0, &saved, &mut driver, &c.semaphore).unwrap();
        c.merge_result(&t.task_id, result).unwrap();
        assert_eq!(c.store.lifecycle_ops().unwrap()[0].kind, "close");
        let mut stale = saved.clone();
        stale.status = "Ready".into();
        stale.memory = TaskMemory::default();
        assert_eq!(
            c.store.sync_task(&stale).unwrap().status,
            "Delivery Pending"
        );
        let mut terminal = stale;
        terminal.status = "Done".into();
        terminal.memory.governance_started = true;
        let terminal = c.store.sync_task(&terminal).unwrap();
        assert_eq!(
            terminal.memory.merge_checkpoint,
            saved.memory.merge_checkpoint
        );
        assert!(terminal.memory.governance_terminal_observed);
        assert!(
            c.store
                .recover_unclosed_delivery(&t.task_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn terminal_governance_readback_acknowledges_saved_delivery_close_once() {
        let dir = TestDirectory::new();
        let mut c = coordinator(&dir.0);
        let mut t = task("remote-closed-delivery");
        t.status = "Delivery Pending".into();
        t.memory.merge_checkpoint = Some(MergeCheckpoint {
            phase: "CLOSE_PENDING".into(),
            target_sha: "head".into(),
            pr_number: 9,
            merge_sha: Some("a".repeat(40)),
            post_merge_verified: true,
            ..Default::default()
        });
        let mut rows = delivery_rows(&t);
        rows[0].state = "verified".into();
        c.store.save_deliveries_and_task(&t, &rows).unwrap();
        c.store.save_delivery_status(&t, Some(&rows)).unwrap();
        let close = merge_queue::close_operation(&t, 9);
        c.store.enqueue_lifecycle(&close).unwrap();
        c.store
            .update_lifecycle(&close.operation_id, "IN_FLIGHT", None, 0)
            .unwrap();
        // Remote close succeeded; the daemon lost its ACK before restart/export.
        t.status = "Done".into();
        c.worker_result(WorkerResult::Export(vec![t.clone()]))
            .unwrap();
        c.reconcile_terminal_tasks().unwrap();
        c.reconcile_terminal_tasks().unwrap();
        c.replay_lifecycle().unwrap();
        assert_eq!(c.task(&t.task_id).unwrap().status, "Done");
        assert_eq!(c.store.lifecycle_ops().unwrap()[0].state, "ACKNOWLEDGED");
        assert!(
            !c.jobs
                .iter()
                .any(|job| job.starts_with("ws:") || job.starts_with("merge:"))
        );
        assert_eq!(
            c.store
                .list_events_since(None, 0, 100)
                .unwrap()
                .iter()
                .filter(|e| e.event_type == "MERGE_COMPLETED")
                .count(),
            1
        );
    }

    #[test]
    fn legacy_delivery_recovery_preserves_external_terminal_and_unproven_records() {
        for case in [
            "external-done",
            "cancelled",
            "acknowledged",
            "missing-checkpoint",
            "wrong-sha",
            "other-executor",
            "revoked",
            "halted",
        ] {
            let dir = TestDirectory::new();
            let mut c = coordinator(&dir.0);
            let mut t = task(case);
            t.status = "Done".into();
            t.memory.merge_checkpoint = Some(MergeCheckpoint {
                phase: "CLOSE_PENDING".into(),
                target_sha: "head".into(),
                pr_number: 9,
                merge_sha: Some("a".repeat(40)),
                post_merge_verified: true,
                ..Default::default()
            });
            if case == "missing-checkpoint" {
                t.memory.merge_checkpoint = None;
            }
            if case == "other-executor" {
                t.executor = Some("session".into());
            }
            if case == "revoked" {
                t.autonomous_consent = false;
            }
            if case == "halted" {
                t.memory.halt_requested = true;
            }
            let mut rows = delivery_rows(&t);
            rows[0].state = "verified".into();
            if case == "wrong-sha" {
                rows[0].merge_sha = "b".repeat(40);
            }
            c.store.save_deliveries_and_task(&t, &rows).unwrap();
            c.store.save_delivery_status(&t, Some(&rows)).unwrap();
            if matches!(case, "external-done" | "cancelled") {
                if case == "cancelled" {
                    t.status = "Cancelled".into();
                }
                c.store.sync_task(&t).unwrap();
            }
            if case == "acknowledged" {
                let op = merge_queue::close_operation(&t, 9);
                c.store.enqueue_lifecycle(&op).unwrap();
                c.lifecycle_ack(&op.operation_id, "").unwrap();
            }
            c.reconcile_terminal_tasks().unwrap();
            c.last_delivery_poll = Instant::now();
            c.poll_deliveries().unwrap();
            assert_eq!(c.task(&t.task_id).unwrap().status, t.status, "{case}");
            assert!(
                c.store
                    .lifecycle_ops()
                    .unwrap()
                    .iter()
                    .all(|op| op.state == "ACKNOWLEDGED"),
                "{case}"
            );
        }
    }
    #[test]
    fn coordinator_get_decision_is_read_only_including_resolved_and_kind_invariant() {
        let dir = TestDirectory::new();
        let (mut c, _) = Coordinator::create(V2Store::open_in_memory().unwrap(), dir.0.clone());
        let t = task("lookup");
        c.save(&t).unwrap();
        let initial = c
            .store
            .open_decision(
                "arbitrary-id",
                &t.task_id,
                &t.task_group,
                "human-merge-approval",
                "choose",
                &["approve".into(), "reject".into()],
                Some(0),
                "synthetic",
                None,
            )
            .unwrap();
        // Reopening an existing ID cannot replace the authoritative kind.
        let reopened = c
            .store
            .open_decision(
                "arbitrary-id",
                &t.task_id,
                &t.task_group,
                "plan_approval",
                "different",
                &["other".into()],
                None,
                "different",
                None,
            )
            .unwrap();
        assert_eq!(initial, reopened);
        for resolved in [false, true] {
            if resolved {
                c.store
                    .resolve_decision("arbitrary-id", "reject", "tester", None)
                    .unwrap();
            }
            let before = c.store.status_summary().unwrap();
            for id in ["arbitrary-id", "missing"] {
                let expected = c.store.get_decision(id).unwrap();
                assert_eq!(
                    c.socket_command(ClientCommand::GetDecision {
                        decision_id: id.into()
                    })
                    .unwrap(),
                    vec![ServerMessage::Decision { decision: expected }]
                );
            }
            assert_eq!(before, c.store.status_summary().unwrap());
            if !resolved {
                // Another owner resolves after lookup, before the eventual Decide.
                c.store
                    .resolve_decision("arbitrary-id", "reject", "other-owner", None)
                    .unwrap();
                let winner = c.store.get_decision("arbitrary-id").unwrap();
                assert_eq!(
                    c.socket_command(ClientCommand::Decide {
                        decision_id: "arbitrary-id".into(),
                        choice: "approve".into(),
                        by: Some("web-client".into()),
                        note: None
                    })
                    .unwrap(),
                    vec![ServerMessage::DecisionResult {
                        outcome: "ALREADY_RESOLVED".into(),
                        decision: winner
                    }]
                );
            }
        }
    }
}
