use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use zach::ledger;
use zach::v2::intake::{ingest_export_json, sync_from_ws_task};
use zach::v2::pipeline::plan_task_execution;
use zach::v2::socket::{ClientCommand, DaemonServer, write_ndjson};
use zach::v2::store::{DecisionResolution, V2Store};
use zach::v2::web_gateway::{GatewayConfig, GatewayHandle, WebGateway};
use zach::v2::{
    DEFAULT_WEB_PORT, default_db_path, default_socket_path, default_state_dir, default_ws_task_bin,
};
use zach::{AuditRequest, GithubConfig, audit_task_integration};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8090";

#[derive(Debug, PartialEq, Eq)]
struct BootstrapConfig {
    bind_addr: String,
}

impl BootstrapConfig {
    fn from_env() -> Self {
        Self {
            bind_addr: env::var("ZACH_BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_owned()),
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("--health");
    let config = BootstrapConfig::from_env();

    match command {
        "--health" => println!("zach: healthy"),
        "--config" => println!("bind_addr={}", config.bind_addr),
        operation if ledger::PUBLIC_WEBHOOK_OPERATIONS.contains(&operation) => {
            run_ledger_validator(&config)
        }
        "governance.audit-task-integration" => run_audit(&args[2..]),
        "doctor" => run_doctor(&args[2..]),
        "__sandbox-bridge" => match zach::v2::isolation::sandbox_bridge(&args[2..]) {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                eprintln!("sandbox bridge: {error}");
                std::process::exit(1);
            }
        },
        "status" => run_v2_status(&args[2..]),
        "queue" => run_v2_queue(&args[2..]),
        "decisions" => run_v2_decisions(&args[2..]),
        "decide" => run_v2_decide(&args[2..]),
        "sync" => run_v2_sync(&args[2..]),
        "config" => run_v2_config(&args[2..]),
        "run" => run_v2_run(&args[2..]),
        "daemon" | "zachd" => run_v2_daemon(&args[2..]),
        "attach" => run_v2_attach(&args[2..]),
        "events" => run_v2_events(&args[2..]),
        "web" => run_v2_web(&args[2..]),
        "--help" | "-h" => print_usage(),
        unknown => {
            eprintln!("unknown option: {unknown}");
            print_usage();
            std::process::exit(2);
        }
    }
}

fn run_doctor(args: &[String]) {
    let worktree = flag_value(args, "--worktree").map(PathBuf::from);
    let report = zach::v2::isolation::doctor(worktree.as_deref());
    if has_flag(args, "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        for probe in &report.probes {
            println!(
                "{} {}: {}",
                if probe.ok { "PASS" } else { "FAIL" },
                probe.name,
                probe.detail
            );
        }
    }
    if !report.ok {
        std::process::exit(1);
    }
}

fn open_store(args: &[String]) -> V2Store {
    let db_path = flag_value(args, "--db")
        .map(PathBuf::from)
        .unwrap_or_else(default_db_path);
    V2Store::open(&db_path).unwrap_or_else(|error| {
        eprintln!("failed to open v2 store at {}: {error}", db_path.display());
        std::process::exit(1);
    })
}

fn run_v2_status(args: &[String]) {
    let mut store = open_store(args);
    if has_flag(args, "--sync") {
        let ws_task = default_ws_task_bin();
        if let Err(error) = sync_from_ws_task(&mut store, &ws_task) {
            eprintln!("warning: ws-task sync failed: {error}");
        }
    }
    let summary = store.status_summary().unwrap_or_else(|error| {
        eprintln!("status query failed: {error}");
        std::process::exit(1);
    });
    if has_flag(args, "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_owned())
        );
    } else {
        println!(
            "Zach v{} · max_parallel={} · tasks={} · ready_eligible={} · in_progress={} · open_decisions={} · locks={} · merge_queue={} · max_seq={}",
            summary.schema_version,
            summary.max_parallel_tasks,
            summary.total_tasks,
            summary.ready_eligible_count,
            summary.in_progress_count,
            summary.open_decisions_count,
            summary.active_locks_count,
            summary.merge_queue_count,
            summary.max_seq_id
        );
    }
}

fn run_v2_queue(args: &[String]) {
    let mut store = open_store(args);
    if has_flag(args, "--sync") {
        let ws_task = default_ws_task_bin();
        if let Err(error) = sync_from_ws_task(&mut store, &ws_task) {
            eprintln!("warning: ws-task sync failed: {error}");
        }
    }
    if has_flag(args, "--merge-queue") {
        let entries = store.list_merge_queue(None).unwrap_or_else(|error| {
            eprintln!("merge queue query failed: {error}");
            std::process::exit(1);
        });
        if has_flag(args, "--json") {
            println!(
                "{}",
                serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_owned())
            );
        } else if entries.is_empty() {
            println!("Merge queue is empty.");
        } else {
            for entry in &entries {
                let sha_short = if entry.reviewed_sha.len() > 8 {
                    &entry.reviewed_sha[..8]
                } else {
                    &entry.reviewed_sha
                };
                println!(
                    "{:<16} {:<10} PR #{:<5} sha={:<8} state={}",
                    entry.repo, entry.task_id, entry.pr_number, sha_short, entry.state
                );
            }
        }
        return;
    }
    let group = flag_value(args, "--group");
    let queue = store
        .list_ready_queue(group.as_deref())
        .unwrap_or_else(|error| {
            eprintln!("queue query failed: {error}");
            std::process::exit(1);
        });
    if has_flag(args, "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&queue).unwrap_or_else(|_| "[]".to_owned())
        );
    } else if queue.is_empty() {
        println!("Ready queue is empty.");
    } else {
        for task in &queue {
            println!(
                "{:<10} [{:<2}] repo={:<16} group={:<6} stages={} · {}",
                task.task_id,
                task.weight,
                task.repository,
                task.task_group,
                task.required_stages.join("->"),
                task.title
            );
        }
    }
}

fn run_v2_decisions(args: &[String]) {
    let store = open_store(args);
    let open_only = !has_flag(args, "--all");
    let group = flag_value(args, "--group");
    let decisions = store
        .list_decisions(open_only, group.as_deref())
        .unwrap_or_else(|error| {
            eprintln!("decisions query failed: {error}");
            std::process::exit(1);
        });
    if has_flag(args, "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&decisions).unwrap_or_else(|_| "[]".to_owned())
        );
    } else if decisions.is_empty() {
        println!("No matching decisions.");
    } else {
        for dec in &decisions {
            println!(
                "{} [{}] task={} kind={} question={:?} options={:?}",
                dec.decision_id, dec.status, dec.task_id, dec.kind, dec.question, dec.options
            );
        }
    }
}

fn run_v2_decide(args: &[String]) {
    let decision_id = args
        .first()
        .filter(|v| !v.starts_with("--"))
        .cloned()
        .or_else(|| flag_value(args, "--id"))
        .unwrap_or_else(|| usage_error("missing <DECISION_ID>"));
    let choice =
        flag_value(args, "--choice").unwrap_or_else(|| usage_error("missing --choice <CHOICE>"));
    let by = flag_value(args, "--by")
        .or_else(|| env::var("USER").ok())
        .unwrap_or_else(|| "operator".to_owned());
    let note = flag_value(args, "--note");

    let mut store = open_store(args);
    match store.resolve_decision(&decision_id, &choice, &by, note.as_deref()) {
        Ok(DecisionResolution::Resolved(rec)) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "outcome": "RESOLVED",
                    "decision": rec,
                }))
                .unwrap_or_default()
            );
        }
        Ok(DecisionResolution::AlreadyResolved(rec)) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "outcome": "ALREADY_RESOLVED",
                    "decision": rec,
                }))
                .unwrap_or_default()
            );
        }
        Ok(DecisionResolution::NotFound) => {
            eprintln!("decision not found: {decision_id}");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("decide failed: {error}");
            std::process::exit(1);
        }
    }
}

const OFFLINE_EXPORT_MAX_AGE_SECS: u64 = 300;

fn offline_sync_options(args: &[String]) -> Result<(PathBuf, PathBuf), String> {
    let mut export = None;
    let mut db = None;
    let mut opt_in = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--reconcile-finished-legacy" if !opt_in => opt_in = true,
            "--export-file" | "--db" => {
                let target = if args[i] == "--db" {
                    &mut db
                } else {
                    &mut export
                };
                if target.is_some() {
                    return Err("duplicate offline sync option".into());
                }
                i += 1;
                let value = args
                    .get(i)
                    .filter(|v| !v.starts_with("--"))
                    .ok_or("offline sync option requires a value")?;
                *target = Some(PathBuf::from(value));
            }
            _ => {
                return Err(
                    "offline sync accepts only --reconcile-finished-legacy, --export-file and --db"
                        .into(),
                );
            }
        }
        i += 1;
    }
    if !opt_in {
        return Err("offline reconciliation requires explicit opt-in".into());
    }
    Ok((
        export.ok_or("offline reconciliation requires a fresh local --export-file")?,
        db.unwrap_or_else(default_db_path),
    ))
}

fn read_private_export(path: &std::path::Path) -> Result<(String, std::time::SystemTime), String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    zach::v2::isolation::reject_symlink_components(path)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
        || meta.len() > 16 * 1024 * 1024
    {
        return Err(
            "export must be a private owned regular file without links (at most 16 MiB)".into(),
        );
    }
    let age = std::time::SystemTime::now()
        .duration_since(meta.modified().map_err(|e| e.to_string())?)
        .map_err(|_| "export timestamp is in the future")?;
    if age > std::time::Duration::from_secs(OFFLINE_EXPORT_MAX_AGE_SECS) {
        return Err("export is older than five minutes".into());
    }
    let mut payload = String::new();
    (&file)
        .take(16 * 1024 * 1024 + 1)
        .read_to_string(&mut payload)
        .map_err(|e| e.to_string())?;
    if payload.len() > 16 * 1024 * 1024 {
        return Err("export grew beyond size limit".into());
    }
    let modified = meta.modified().map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    if after.modified().map_err(|e| e.to_string())? != modified
        || after.len() != meta.len()
        || payload.len() as u64 != meta.len()
    {
        return Err("export changed while being read".into());
    }
    // Hold the opened content, never reopen a validated pathname for intake.
    zach::v2::intake::decode_export_records(&payload).map_err(|e| e.to_string())?;
    Ok((payload, modified))
}

fn reject_zach_processes(proc_dir: &std::path::Path, own_pid: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    for entry in fs::read_dir(proc_dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid == own_pid {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("process identity inspection failed: {e}")),
        };
        if meta.uid() != unsafe { libc::geteuid() } {
            continue;
        }
        let read_identity = |name| match fs::read_to_string(entry.path().join(name)) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if entry.path().exists() {
                    Err("incomplete process identity inspection".into())
                } else {
                    Ok(None)
                }
            }
            Err(e) => Err(format!("process inspection failed: {e}")),
        };
        let Some(comm) = read_identity("comm")? else {
            continue;
        };
        let Some(cgroup) = read_identity("cgroup")? else {
            continue;
        };
        if comm.trim().is_empty() || cgroup.trim().is_empty() {
            return Err("empty process identity".into());
        }
        if comm.trim().starts_with("zach")
            || cgroup.contains("zach-workers.slice/")
            || cgroup.contains("/zach-stage-")
            || cgroup.contains("/zach-w-")
        {
            return Err("another Zach or worker process exists".into());
        }
    }
    Ok(())
}

fn offline_absence_check(
    controller: &dyn zach::v2::runner::UnitController,
    units: &[String],
    sockets: &[PathBuf],
) -> Result<(), String> {
    use zach::v2::runner::UnitState;
    for socket in sockets {
        match fs::symlink_metadata(socket) {
            Ok(_) => return Err("Zach socket path still exists".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(format!("socket inspection failed: {e}")),
        }
    }
    if !controller.list_units()?.is_empty() {
        return Err("worker units still exist".into());
    }
    for unit in units {
        if controller.inspect(unit)?.state()? != UnitState::Missing {
            return Err("a persisted worker unit still exists".into());
        }
    }
    Ok(())
}

fn reconcile_finished_legacy(args: &[String]) -> Result<zach::v2::intake::IntakeSummary, String> {
    reconcile_finished_legacy_in(
        args,
        &default_state_dir(),
        default_socket_path(),
        check_offline_host,
        |_| Ok(()),
    )
}

fn check_offline_host(units: &[String], sockets: &[PathBuf]) -> Result<(), String> {
    use zach::v2::runner::SystemUnitController;
    // Check old and current worker naming, in addition to exact persisted identities.
    let broad_units = std::process::Command::new("systemctl")
        .args([
            "--user",
            "list-units",
            "--all",
            "zach-*",
            "--no-legend",
            "--plain",
            "--no-pager",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !broad_units.status.success() {
        return Err("cannot enumerate all Zach units".into());
    }
    for line in String::from_utf8(broad_units.stdout)
        .map_err(|e| e.to_string())?
        .lines()
    {
        let unit = line
            .split_whitespace()
            .find(|p| p.starts_with("zach-"))
            .ok_or("ambiguous systemctl unit listing")?;
        if !matches!(unit, "zach-workers.slice") {
            return Err("a Zach service/worker unit still exists".into());
        }
    }
    offline_absence_check(&SystemUnitController, units, sockets)?;
    reject_zach_processes(std::path::Path::new("/proc"), std::process::id())?;
    offline_absence_check(&SystemUnitController, units, sockets)?;
    Ok(())
}

fn reconcile_finished_legacy_in(
    args: &[String],
    state: &std::path::Path,
    configured_socket: PathBuf,
    preflight: impl FnOnce(&[String], &[PathBuf]) -> Result<(), String>,
    after_sync: impl FnOnce(&V2Store) -> Result<(), String>,
) -> Result<zach::v2::intake::IntakeSummary, String> {
    let (export, db) = offline_sync_options(args)?;
    let (payload, export_modified) = read_private_export(&export)?;
    let records = zach::v2::intake::decode_export_records(&payload).map_err(|e| e.to_string())?;
    zach::v2::isolation::reject_symlink_components(state)?;
    zach::v2::isolation::reject_symlink_components(&db)?;
    let state = fs::canonicalize(state).map_err(|e| e.to_string())?;
    let db = fs::canonicalize(db).map_err(|e| e.to_string())?;
    if db != state.join("zach-v2.sqlite3") {
        return Err(
            "offline reconciliation requires the canonical state directory's zach-v2.sqlite3"
                .into(),
        );
    }
    let _lock = zach::v2::coordinator::DaemonLock::acquire(&state)?;
    let conn =
        rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| e.to_string())?;
    let units = conn
        .prepare("SELECT DISTINCT systemd_unit FROM stage_attempts WHERE systemd_unit IS NOT NULL")
        .map_err(|e| e.to_string())?
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    if units.iter().any(|u| {
        u.trim().is_empty() || !u.starts_with("zach-") || u.chars().any(char::is_whitespace)
    }) {
        return Err("ambiguous persisted worker unit identity".into());
    }
    drop(conn);
    let sockets = [state.join("zach.sock"), configured_socket];
    preflight(&units, &sockets)?;
    if std::time::SystemTime::now()
        .duration_since(export_modified)
        .map_err(|_| "export timestamp is in the future")?
        > std::time::Duration::from_secs(OFFLINE_EXPORT_MAX_AGE_SECS)
    {
        return Err("export became stale during preflight".into());
    }
    let mut store = V2Store::open(&db).map_err(|e| e.to_string())?;
    let summary = zach::v2::intake::ingest_task_records_with_mode(
        &mut store,
        records,
        zach::v2::store::SyncMode::ReconcileFinishedLegacy,
    )
    .map_err(|e| e.to_string())?;
    after_sync(&store)?;
    Ok(summary)
}

fn run_v2_sync(args: &[String]) {
    if has_flag(args, "--reconcile-finished-legacy") {
        match reconcile_finished_legacy(args) {
            Ok(result) => println!("{}", serde_json::to_string_pretty(&result).unwrap()),
            Err(error) => {
                eprintln!("offline reconciliation failed: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    let mut store = open_store(args);
    let summary = if let Some(export_file) = flag_value(args, "--export-file") {
        let payload = fs::read_to_string(&export_file).unwrap_or_else(|error| {
            eprintln!("failed to read {export_file}: {error}");
            std::process::exit(1);
        });
        ingest_export_json(&mut store, &payload)
    } else {
        let ws_task = flag_value(args, "--ws-task-bin")
            .map(PathBuf::from)
            .unwrap_or_else(default_ws_task_bin);
        sync_from_ws_task(&mut store, &ws_task)
    };

    match summary {
        Ok(result) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_owned())
            );
        }
        Err(error) => {
            eprintln!("sync failed: {error}");
            std::process::exit(1);
        }
    }
}

fn run_v2_config(args: &[String]) {
    let mut store = open_store(args);
    if let Some(raw_max) = flag_value(args, "--max-parallel") {
        let parsed = raw_max
            .parse::<usize>()
            .unwrap_or_else(|_| usage_error("invalid --max-parallel value"));
        if let Err(error) = store.set_max_parallel_tasks(parsed) {
            eprintln!("config update failed: {error}");
            std::process::exit(1);
        }
    }
    let max_parallel = store.max_parallel_tasks().unwrap_or(2);
    println!("max_parallel_tasks={max_parallel}");
}

fn run_v2_run(args: &[String]) {
    let dry_run = has_flag(args, "--dry-run");
    if !dry_run {
        // The daemon schedules pipelines and poll_post_merge_deliveries on bounded workers.
        let socket_path = flag_value(args, "--socket")
            .map(PathBuf::from)
            .unwrap_or_else(default_socket_path);
        let mut stream =
            std::os::unix::net::UnixStream::connect(&socket_path).unwrap_or_else(|error| {
                eprintln!("connect to zachd at {}: {error}", socket_path.display());
                std::process::exit(1)
            });
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap_or_else(|error| {
                eprintln!("run socket timeout: {error}");
                std::process::exit(1)
            });
        write_ndjson(
            &mut stream,
            &ClientCommand::Run {
                task: flag_value(args, "--task"),
                group: flag_value(args, "--group"),
                once: has_flag(args, "--once"),
            },
        )
        .unwrap_or_else(|error| {
            eprintln!("submit run: {error}");
            std::process::exit(1)
        });
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(stream)
            .read_line(&mut line)
            .unwrap_or_else(|error| {
                eprintln!("run acknowledgment: {error}");
                std::process::exit(1)
            });
        let reply: serde_json::Value = serde_json::from_str(&line).unwrap_or_else(|error| {
            eprintln!("invalid daemon acknowledgment: {error}");
            std::process::exit(1)
        });
        println!("{}", line.trim());
        if reply["type"] == "ERROR" {
            std::process::exit(1);
        }
        return;
    }
    let db = flag_value(args, "--db")
        .map(PathBuf::from)
        .unwrap_or_else(default_db_path);
    let store = V2Store::open_read_only(&db).unwrap_or_else(|error| {
        eprintln!("read-only task store: {error}");
        std::process::exit(1)
    });
    let once = has_flag(args, "--once");
    let group = flag_value(args, "--group");

    let tasks = if let Some(task_id) = flag_value(args, "--task") {
        match store.get_task(&task_id) {
            Ok(Some(t)) => vec![t],
            Ok(None) => {
                eprintln!("task not found: {task_id}");
                std::process::exit(1);
            }
            Err(error) => {
                eprintln!("failed to query task {task_id}: {error}");
                std::process::exit(1);
            }
        }
    } else {
        let mut queue = store
            .list_ready_queue(group.as_deref())
            .unwrap_or_else(|error| {
                eprintln!("failed to query ready queue: {error}");
                std::process::exit(1);
            });
        if !dry_run {
            queue.retain(|t| {
                matches!(
                    t.weight.to_ascii_uppercase().as_str(),
                    "XS" | "S" | "M" | "L"
                )
            });
        }
        if once && queue.len() > 1 {
            queue.truncate(1);
        }
        queue
    };

    if dry_run {
        let mut plans = Vec::new();
        for task in &tasks {
            match plan_task_execution(task) {
                Ok(plan) => plans.push(plan),
                Err(error) => {
                    eprintln!("dry-run planning failed for {}: {error}", task.task_id);
                    std::process::exit(1);
                }
            }
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&plans).unwrap_or_else(|_| "[]".to_owned())
        );
    }
}

fn run_ledger_validator(config: &BootstrapConfig) {
    if let Err(error) = ledger::serve_from_env(&config.bind_addr) {
        eprintln!("ledger validator failed: {error}");
        std::process::exit(1);
    }
}

fn run_audit(args: &[String]) {
    let task_id = flag_value(args, "--task-id").unwrap_or_else(|| usage_error("missing --task-id"));
    let request_id =
        flag_value(args, "--request-id").unwrap_or_else(|| usage_error("missing --request-id"));

    let config = GithubConfig::from_env().unwrap_or_else(|error| {
        eprintln!("configuration error: {error}");
        std::process::exit(2);
    });
    let request = AuditRequest {
        task_id,
        request_id,
    };

    match audit_task_integration(&config, &request) {
        Ok(receipt_json) => println!("{receipt_json}"),
        Err(error) => {
            eprintln!("audit failed: {error}");
            std::process::exit(1);
        }
    }
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|item| item == flag)
}

fn usage_error(message: &str) -> ! {
    eprintln!("{message}");
    print_usage();
    std::process::exit(2);
}

fn run_v2_daemon(args: &[String]) {
    if has_flag(args, "--help") || has_flag(args, "-h") {
        print_usage();
        return;
    }
    let gateway_config = gateway_options(args, true);
    let state_dir = default_state_dir();
    let _lock = zach::v2::coordinator::DaemonLock::acquire(&state_dir).unwrap_or_else(|error| {
        eprintln!("daemon lock: {error}");
        std::process::exit(1)
    });
    let state_dir = std::fs::canonicalize(&state_dir).unwrap_or_else(|error| {
        eprintln!("canonical daemon state directory: {error}");
        std::process::exit(1)
    });
    let store = open_store(args);
    let socket_path = flag_value(args, "--socket")
        .map(PathBuf::from)
        .unwrap_or_else(default_socket_path);
    let once = has_flag(args, "--once");

    let initial_seq = store.max_seq_id().unwrap_or(0);
    let mut server = DaemonServer::bind(&socket_path, initial_seq).unwrap_or_else(|error| {
        eprintln!(
            "failed to bind daemon socket at {}: {error}",
            socket_path.display()
        );
        std::process::exit(1);
    });

    zach::v2::socket::install_shutdown_signals().unwrap_or_else(|error| {
        eprintln!("install shutdown signals: {error}");
        std::process::exit(1)
    });
    let gateway = gateway_config.map(start_web_gateway);
    println!(
        "zachd started · socket={} · initial_seq={} · once={}",
        socket_path.display(),
        initial_seq,
        once
    );
    let coordinator = zach::v2::coordinator::Coordinator::spawn(store, state_dir);
    let result = server.run_coordinated(coordinator, once);
    // Always stop and join the optional listener before any process::exit.
    let web_result = gateway.map(GatewayHandle::shutdown_and_join).transpose();
    if let Err(error) = result {
        eprintln!("daemon error: {error}");
        std::process::exit(1);
    }
    if let Err(error) = web_result {
        eprintln!("web gateway shutdown failed: {error}");
        std::process::exit(1);
    }
    if once {
        println!("zachd: completed single loop execution");
    }
}

fn gateway_options(args: &[String], daemon: bool) -> Option<GatewayConfig> {
    let env_bind = match env::var("ZACH_WEB_ADDR") {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(_) => usage_error("ZACH_WEB_ADDR must be valid UTF-8"),
    };
    parse_gateway_options(args, daemon, env_bind.as_deref())
        .unwrap_or_else(|error| usage_error(&error))
}

fn parse_gateway_options(
    args: &[String],
    daemon: bool,
    env_bind: Option<&str>,
) -> Result<Option<GatewayConfig>, String> {
    let mut enabled = !daemon;
    let mut port = None;
    let mut bind = None;
    let mut socket = None;
    let mut allowed_origins = Vec::new();
    let mut allowed_decision_kinds = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut i = 0;
    while i < args.len() {
        let key = match args[i].as_str() {
            "--web" if daemon => "web",
            "--once" if daemon => "once",
            "--db" if daemon => "db",
            "--web-allow-origin" => "origin",
            "--web-allow-decision-kind" => "kind",
            "--socket" => "socket",
            "--web-port" => "port",
            "--port" if !daemon => "port",
            "--bind" => "bind",
            "--web-bind" if daemon => "bind",
            _ => return Err("unsupported web/daemon option; see --help".into()),
        };
        if !matches!(key, "origin" | "kind") && !seen.insert(key) {
            return Err("duplicate web/daemon option".into());
        }
        if key == "web" {
            enabled = true;
        } else if key != "once" {
            i += 1;
            let value = args
                .get(i)
                .filter(|value| !value.is_empty() && !value.starts_with('-'))
                .ok_or("web/daemon option requires a value")?;
            match key {
                "port" => {
                    port = Some(
                        value
                            .parse::<u16>()
                            .ok()
                            .filter(|p| *p > 0)
                            .ok_or("web port must be an integer from 1 to 65535")?,
                    )
                }
                "bind" => bind = Some(value.as_str()),
                "socket" => socket = Some(PathBuf::from(value)),
                "origin" => {
                    if allowed_origins.len() >= 16 {
                        return Err("too many allowed origins".into());
                    }
                    allowed_origins.push(value.clone());
                }
                "kind" => {
                    if allowed_decision_kinds.len() >= 32 {
                        return Err("too many allowed decision kinds".into());
                    }
                    allowed_decision_kinds.push(value.clone());
                }
                _ => {}
            }
        }
        i += 1;
    }
    zach::v2::web_gateway::validate_web_policy(&allowed_origins, &allowed_decision_kinds)
        .map_err(|_| "invalid web policy configuration")?;
    if !enabled {
        if port.is_some()
            || bind.is_some()
            || !allowed_origins.is_empty()
            || !allowed_decision_kinds.is_empty()
        {
            return Err("web binding options require --web".into());
        }
        return Ok(None);
    }
    if port.is_some() && bind.is_some() {
        return Err("use a bind address with port, or --web-port; do not combine them".into());
    }
    let default = format!("127.0.0.1:{DEFAULT_WEB_PORT}");
    let mut addr: std::net::SocketAddr = bind
        .or(env_bind)
        .unwrap_or(&default)
        .parse()
        .map_err(|_| "web bind must be a numeric loopback address and port")?;
    if let Some(port) = port {
        addr.set_port(port);
    }
    if !addr.ip().is_loopback() || addr.port() == 0 {
        return Err("web gateway must bind to loopback with a nonzero port".into());
    }
    Ok(Some(GatewayConfig {
        bind_addr: addr,
        socket_path: socket.unwrap_or_else(default_socket_path),
        state_dir: default_state_dir(),
        allowed_origins,
        allowed_decision_kinds,
    }))
}

fn start_web_gateway(config: GatewayConfig) -> GatewayHandle {
    let gateway = WebGateway::bind(config).unwrap_or_else(|_| {
        eprintln!("web gateway setup failed (check bind address and private state directory)");
        std::process::exit(1)
    });
    let addr = gateway.local_addr().unwrap_or_else(|_| {
        eprintln!("cannot inspect bound web listener");
        std::process::exit(1)
    });
    let handle = gateway.spawn().unwrap_or_else(|_| {
        eprintln!("cannot start web gateway worker");
        std::process::exit(1)
    });
    println!("zach web listening on http://{addr}");
    handle
}

static WEB_SHUTDOWN: AtomicBool = AtomicBool::new(false);
extern "C" fn web_shutdown_signal(_: libc::c_int) {
    WEB_SHUTDOWN.store(true, Ordering::Relaxed);
}

fn run_v2_web(args: &[String]) {
    if has_flag(args, "--help") || has_flag(args, "-h") {
        print_usage();
        return;
    }
    let config = gateway_options(args, false).expect("standalone web is enabled");
    WEB_SHUTDOWN.store(false, Ordering::Relaxed);
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = web_shutdown_signal as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) != 0
            || libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0
        {
            eprintln!("cannot install web shutdown signals");
            std::process::exit(1)
        }
    }
    let handle = start_web_gateway(config);
    while !WEB_SHUTDOWN.load(Ordering::Relaxed) && !handle.is_finished() {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if handle.shutdown_and_join().is_err() {
        eprintln!("web gateway stopped with an error");
        std::process::exit(1)
    }
}

fn run_v2_attach(args: &[String]) {
    let socket_path = flag_value(args, "--socket")
        .map(PathBuf::from)
        .unwrap_or_else(default_socket_path);
    let group = flag_value(args, "--group");
    let since_seq = flag_value(args, "--since-seq").and_then(|v| v.parse::<i64>().ok());
    let once = has_flag(args, "--once");

    let mut stream =
        std::os::unix::net::UnixStream::connect(&socket_path).unwrap_or_else(|error| {
            eprintln!(
                "failed to connect to socket at {}: {error}",
                socket_path.display()
            );
            std::process::exit(1);
        });

    let cmd = ClientCommand::Subscribe {
        group,
        since_seq,
        once: if once { Some(true) } else { None },
    };

    if let Err(error) = write_ndjson(&mut stream, &cmd) {
        eprintln!("failed to send subscribe command: {error}");
        std::process::exit(1);
    }

    use std::io::{BufRead, BufReader};
    let reader = BufReader::new(stream);
    for line_result in reader.lines() {
        match line_result {
            Ok(line) => {
                println!("{line}");
                if once {
                    break;
                }
            }
            Err(error) => {
                eprintln!("connection closed: {error}");
                break;
            }
        }
    }
}

fn run_v2_events(args: &[String]) {
    let group = flag_value(args, "--group");
    let since_seq = flag_value(args, "--since-seq").and_then(|v| v.parse::<i64>().ok());
    let wait = has_flag(args, "--wait");

    if wait {
        let socket_path = flag_value(args, "--socket")
            .map(PathBuf::from)
            .unwrap_or_else(default_socket_path);

        let mut stream =
            std::os::unix::net::UnixStream::connect(&socket_path).unwrap_or_else(|error| {
                eprintln!(
                    "failed to connect to socket at {}: {error}",
                    socket_path.display()
                );
                std::process::exit(1);
            });

        let cmd = ClientCommand::Subscribe {
            group,
            since_seq,
            once: Some(false),
        };

        if let Err(error) = write_ndjson(&mut stream, &cmd) {
            eprintln!("failed to send subscribe command: {error}");
            std::process::exit(1);
        }

        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(stream);
        for line_result in reader.lines() {
            match line_result {
                Ok(line) => println!("{line}"),
                Err(error) => {
                    eprintln!("connection closed: {error}");
                    break;
                }
            }
        }
    } else {
        let store = open_store(args);
        let events = store
            .list_events_since(group.as_deref(), since_seq.unwrap_or(0), 5000)
            .unwrap_or_else(|error| {
                eprintln!("events query failed: {error}");
                std::process::exit(1);
            });

        for event in &events {
            println!("{}", serde_json::to_string(event).unwrap_or_default());
        }
    }
}

fn print_usage() {
    println!("Usage: zach [--health | --config]");
    println!("       zach {}", ledger::PUBLIC_WEBHOOK_OPERATIONS[0]);
    println!(
        "       zach governance.audit-task-integration --task-id <TASK-ID> --request-id <REQUEST-ID>"
    );
    println!("       zach status [--sync] [--json] [--db <PATH>]");
    println!("       zach queue [--group <GROUP>] [--merge-queue] [--sync] [--json] [--db <PATH>]");
    println!("       zach decisions [--group <GROUP>] [--all] [--json] [--db <PATH>]");
    println!(
        "       zach decide <DECISION_ID> --choice <CHOICE> [--by <ACTOR>] [--note <NOTE>] [--db <PATH>]"
    );
    println!(
        "       zach sync [--export-file <PATH>] [--ws-task-bin <PATH>] [--db <PATH>] [--reconcile-finished-legacy]"
    );
    println!("       zach config [--max-parallel <1..16>] [--db <PATH>]");
    println!(
        "       zach run [--task <TASK_ID>] [--group <GROUP>] [--once] [--dry-run] [--json] [--db <PATH>]"
    );
    println!("       zach doctor [--json] [--worktree <PATH>]");
    println!(
        "       zach daemon [--socket <PATH>] [--db <PATH>] [--once] [--web] [--web-port <PORT>] [--web-bind <IP:PORT>]"
    );
    println!("       zach web [--socket <PATH>] [--web-port <PORT>] [--bind <IP:PORT>]");
    println!(
        "       Web policy (both forms): [--web-allow-origin <ORIGIN>] [--web-allow-decision-kind <KIND>] (repeatable)"
    );
    println!("       zach attach [--group <GROUP>] [--since-seq <N>] [--once] [--socket <PATH>]");
    println!(
        "       zach events [--group <GROUP>] [--since-seq <N>] [--wait] [--socket <PATH>] [--db <PATH>]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OfflineTestDir(PathBuf);
    impl OfflineTestDir {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let path = env::temp_dir().join(format!(
                "zach-offline-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for OfflineTestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    struct OfflineUnits {
        listed: bool,
        exact: bool,
        fail: bool,
    }
    impl zach::v2::runner::UnitController for OfflineUnits {
        fn inspect(&self, _: &str) -> Result<zach::v2::runner::UnitObservation, String> {
            if self.fail {
                return Err("inspection uncertain".into());
            }
            Ok(zach::v2::runner::UnitObservation {
                load_state: if self.exact { "loaded" } else { "not-found" }.into(),
                active_state: "inactive".into(),
                sub_state: "dead".into(),
                ..Default::default()
            })
        }
        fn list_units(&self) -> Result<Vec<String>, String> {
            if self.fail && self.listed {
                return Err("enumeration uncertain".into());
            }
            Ok(if self.listed {
                vec!["zach-stage-synthetic.service".into()]
            } else {
                vec![]
            })
        }
        fn launch(&self, _: &zach::v2::runner::AttemptManifest) -> Result<(), String> {
            panic!("offline must not launch")
        }
        fn stop(&self, _: &str) -> Result<(), String> {
            panic!("offline must not stop")
        }
        fn reset_failed(&self, _: &str) -> Result<(), String> {
            panic!("offline must not reset")
        }
    }

    fn offline_entry_fixture(dir: &OfflineTestDir) -> (PathBuf, Vec<String>) {
        use std::os::unix::fs::PermissionsExt;
        let db = dir.0.join("zach-v2.sqlite3");
        let export = dir.0.join("export.json");
        let payload = r#"{"schema_version":2,"tasks":[{"id":"SYNTHETIC-CLI","repository":"zach","status":"Done","weight":"S","autonomous_consent":true}]}"#;
        fs::write(&export, payload).unwrap();
        fs::set_permissions(&export, fs::Permissions::from_mode(0o600)).unwrap();
        let mut store = V2Store::open(&db).unwrap();
        ingest_export_json(&mut store, payload).unwrap();
        let mut task = store.get_task("SYNTHETIC-CLI").unwrap().unwrap();
        task.status = "Queued for Merge".into();
        task.stages_completed = vec!["impl".into()];
        task.current_stage = Some("impl".into());
        task.active_attempt_id = Some("finished-cli".into());
        store.upsert_task(&task).unwrap();
        store.connection_mut().execute_batch("INSERT INTO stage_attempts(attempt_id,task_id,stage,model,effort,systemd_unit,started_epoch,ended_epoch,status,phase) VALUES('finished-cli','SYNTHETIC-CLI','impl','synthetic','low','zach-stage-finished-cli',1,2,'PASSED','COMPLETE'); INSERT INTO merge_queue(repo,task_id,pr_number,reviewed_sha,enqueued_epoch,state) VALUES('zach','SYNTHETIC-CLI',1,'sha',2,'FAILED'); ALTER TABLE stage_attempts DROP COLUMN phase; UPDATE daemon_meta SET value='2' WHERE key='schema_version'; PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        drop(store);
        let args = vec![
            "--reconcile-finished-legacy".into(),
            "--export-file".into(),
            export.to_string_lossy().into_owned(),
            "--db".into(),
            db.to_string_lossy().into_owned(),
        ];
        (db, args)
    }
    fn assert_legacy_schema(db: &std::path::Path) {
        let conn =
            rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM pragma_table_info('stage_attempts') WHERE name='phase'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn offline_entry_preopen_failures_preserve_real_legacy_database_bytes_and_schema() {
        for case in [
            "lock",
            "enumeration",
            "exact-unit",
            "exact-error",
            "process",
            "process-error",
            "socket",
            "malformed-export",
            "path",
        ] {
            let dir = OfflineTestDir::new();
            let (db, mut args) = offline_entry_fixture(&dir);
            let bytes = fs::read(&db).unwrap();
            let socket = dir.0.join("zach.sock");
            let _held = if case == "lock" {
                Some(zach::v2::coordinator::DaemonLock::acquire(&dir.0).unwrap())
            } else {
                None
            };
            if case == "socket" {
                fs::write(&socket, "").unwrap();
            }
            if case == "malformed-export" {
                fs::write(&args[2], "not json").unwrap();
            }
            if case == "path" {
                let other = dir.0.join("other.sqlite3");
                fs::copy(&db, &other).unwrap();
                args[4] = other.to_string_lossy().into_owned();
            }
            let reached = std::cell::Cell::new(false);
            let result = reconcile_finished_legacy_in(
                &args,
                &dir.0,
                socket,
                |units, sockets| {
                    reached.set(true);
                    // This is the actual orchestration entry point: the native lock
                    // is already held and writable initialization has not occurred.
                    assert!(zach::v2::coordinator::DaemonLock::acquire(&dir.0).is_err());
                    assert_legacy_schema(&db);
                    assert_eq!(units, &["zach-stage-finished-cli".to_owned()]);
                    let controller = OfflineUnits {
                        listed: case == "enumeration",
                        exact: case == "exact-unit",
                        fail: matches!(case, "enumeration" | "exact-error"),
                    };
                    offline_absence_check(&controller, units, sockets)?;
                    let proc_dir = dir.0.join("proc");
                    if case == "process-error" {
                        return reject_zach_processes(&proc_dir, 999);
                    }
                    fs::create_dir(&proc_dir).unwrap();
                    if case == "process" {
                        let process = proc_dir.join("123");
                        fs::create_dir(&process).unwrap();
                        fs::write(process.join("comm"), "zachd\n").unwrap();
                        fs::write(process.join("cgroup"), "0::/user.slice\n").unwrap();
                    }
                    reject_zach_processes(&proc_dir, 999)
                },
                |_| panic!("failed preflight must not reach writable sync"),
            );
            assert!(result.is_err(), "{case}");
            assert_eq!(
                reached.get(),
                !matches!(case, "lock" | "malformed-export" | "path"),
                "{case}"
            );
            assert_eq!(
                fs::read(&db).unwrap(),
                bytes,
                "database bytes changed on {case}"
            );
            assert_legacy_schema(&db);
        }
    }

    #[test]
    fn offline_entry_success_routes_opt_in_and_holds_native_lock_through_sync() {
        let dir = OfflineTestDir::new();
        let (db, args) = offline_entry_fixture(&dir);
        let before = std::cell::Cell::new(false);
        let after = std::cell::Cell::new(false);
        let result = reconcile_finished_legacy_in(
            &args,
            &dir.0,
            dir.0.join("zach.sock"),
            |units, sockets| {
                before.set(true);
                assert!(zach::v2::coordinator::DaemonLock::acquire(&dir.0).is_err());
                assert_legacy_schema(&db);
                offline_absence_check(
                    &OfflineUnits {
                        listed: false,
                        exact: false,
                        fail: false,
                    },
                    units,
                    sockets,
                )?;
                // Path replacement after validation cannot replace the retained content.
                fs::remove_file(&args[2]).unwrap();
                fs::write(&args[2], "replacement is not JSON").unwrap();
                Ok(())
            },
            |store| {
                after.set(true);
                assert!(zach::v2::coordinator::DaemonLock::acquire(&dir.0).is_err());
                let task = store.get_task("SYNTHETIC-CLI").unwrap().unwrap();
                assert_eq!(task.status, "Done");
                assert!(task.active_attempt_id.is_none());
                assert_eq!(task.stages_completed, vec!["impl"]);
                assert_eq!(
                    store
                        .get_stage_attempt("finished-cli")
                        .unwrap()
                        .unwrap()
                        .phase,
                    "COMPLETE"
                );
                assert!(store.list_merge_queue(None).unwrap().is_empty());
                assert!(store.lifecycle_ops().unwrap().is_empty());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(result.ingested_count, 1);
        assert!(before.get() && after.get());
        assert!(zach::v2::coordinator::DaemonLock::acquire(&dir.0).is_ok());
    }

    #[test]
    fn offline_sync_requires_explicit_unambiguous_local_export() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for bad in [
            vec!["--reconcile-finished-legacy"],
            vec![
                "--reconcile-finished-legacy",
                "--export-file",
                "file",
                "--ws-task-bin",
                "bin",
            ],
            vec!["--export-file", "file"],
            vec![
                "--reconcile-finished-legacy",
                "--export-file",
                "file",
                "--export-file",
                "other",
            ],
        ] {
            assert!(offline_sync_options(&args(&bad)).is_err());
        }
        assert!(
            offline_sync_options(&args(&[
                "--reconcile-finished-legacy",
                "--export-file",
                "file"
            ]))
            .is_ok()
        );
    }

    #[test]
    fn offline_export_is_private_fresh_opened_content_without_path_following() {
        use std::os::unix::fs::PermissionsExt;
        let dir = OfflineTestDir::new();
        let path = dir.0.join("export.json");
        fs::write(&path, r#"{"schema_version":2,"tasks":[]}"#).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_private_export(&path).is_ok());
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_private_export(&link).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_export(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        let old = std::time::SystemTime::now()
            - std::time::Duration::from_secs(OFFLINE_EXPORT_MAX_AGE_SECS + 2);
        file.set_times(fs::FileTimes::new().set_modified(old))
            .unwrap();
        assert!(read_private_export(&path).is_err());
        fs::write(&path, "not json").unwrap();
        assert!(read_private_export(&path).is_err());
    }

    #[test]
    fn offline_preflight_blocks_live_exact_units_sockets_and_uncertainty_without_db_writes() {
        let dir = OfflineTestDir::new();
        let db = dir.0.join("zach-v2.sqlite3");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE stage_attempts(systemd_unit TEXT);")
            .unwrap();
        drop(conn);
        let bytes = fs::read(&db).unwrap();
        let socket = dir.0.join("zach.sock");
        let units = vec!["zach-stage-synthetic.service".into()];
        for check in [
            OfflineUnits {
                listed: true,
                exact: false,
                fail: false,
            },
            OfflineUnits {
                listed: false,
                exact: true,
                fail: false,
            },
            OfflineUnits {
                listed: false,
                exact: false,
                fail: true,
            },
        ] {
            assert!(offline_absence_check(&check, &units, std::slice::from_ref(&socket)).is_err());
            assert_eq!(fs::read(&db).unwrap(), bytes);
        }
        let safe = OfflineUnits {
            listed: false,
            exact: false,
            fail: false,
        };
        assert!(offline_absence_check(&safe, &units, std::slice::from_ref(&socket)).is_ok());
        fs::write(&socket, "").unwrap();
        assert!(offline_absence_check(&safe, &units, &[socket]).is_err());
        let lock = zach::v2::coordinator::DaemonLock::acquire(&dir.0).unwrap();
        assert!(zach::v2::coordinator::DaemonLock::acquire(&dir.0).is_err());
        drop(lock);
        assert_eq!(fs::read(&db).unwrap(), bytes);
    }

    #[test]
    fn offline_process_checks_use_identity_not_arguments_and_fail_closed() {
        let dir = OfflineTestDir::new();
        let pid = dir.0.join("123");
        fs::create_dir(&pid).unwrap();
        fs::write(pid.join("comm"), "zachd\n").unwrap();
        fs::write(pid.join("cgroup"), "0::/user.slice\n").unwrap();
        assert!(reject_zach_processes(&dir.0, 999).is_err());
        assert!(reject_zach_processes(&dir.0, 123).is_ok());
        fs::write(pid.join("comm"), "codex\n").unwrap();
        fs::write(
            pid.join("cgroup"),
            "0::/zach-workers.slice/worker.service\n",
        )
        .unwrap();
        assert!(reject_zach_processes(&dir.0, 999).is_err());
        fs::write(pid.join("cgroup"), "0::/user.slice\n").unwrap();
        assert!(reject_zach_processes(&dir.0, 999).is_ok());
        assert!(reject_zach_processes(&dir.0.join("missing"), 999).is_err());
    }

    #[test]
    fn default_bind_address_is_loopback() {
        assert_eq!(DEFAULT_BIND_ADDR, "127.0.0.1:8090");
    }

    #[test]
    fn ledger_is_the_only_public_webhook_operation() {
        assert_eq!(
            ledger::PUBLIC_WEBHOOK_OPERATIONS,
            &["governance.validate-ledger"]
        );
    }

    fn web_options(
        args: &[&str],
        daemon: bool,
        env: Option<&str>,
    ) -> Result<Option<GatewayConfig>, String> {
        let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        parse_gateway_options(&args, daemon, env)
    }

    #[test]
    fn gateway_cli_is_explicit_and_keeps_socket_and_bind_configuration() {
        let config = web_options(&[], false, None).unwrap().unwrap();
        assert_eq!(config.bind_addr.to_string(), "127.0.0.1:8096");
        assert!(
            web_options(&[], true, Some("0.0.0.0:9000"))
                .unwrap()
                .is_none()
        );
        assert!(
            web_options(
                &[
                    "--db",
                    "/tmp/example.sqlite",
                    "--socket",
                    "/tmp/control.sock",
                    "--once"
                ],
                true,
                None
            )
            .unwrap()
            .is_none()
        );
        let config = web_options(
            &[
                "--web",
                "--web-port",
                "8097",
                "--socket",
                "/tmp/control.sock",
            ],
            true,
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(config.bind_addr.to_string(), "127.0.0.1:8097");
        assert_eq!(config.socket_path, PathBuf::from("/tmp/control.sock"));
        let config = web_options(&["--bind", "127.0.0.1:8098"], false, Some("0.0.0.0:9000"))
            .unwrap()
            .unwrap();
        assert_eq!(
            config.bind_addr.port(),
            8098,
            "explicit address overrides environment default"
        );
        let config = web_options(&["--web", "--web-bind", "[::1]:8099"], true, None)
            .unwrap()
            .unwrap();
        assert!(config.bind_addr.ip().is_loopback());
    }

    #[test]
    fn gateway_cli_rejects_invalid_exposure_and_ambiguous_options_before_startup() {
        for args in [
            vec!["--bind", "0.0.0.0:8096"],
            vec!["--bind", "[::]:8096"],
            vec!["--bind", "192.0.2.1:8096"],
            vec!["--bind", "127.0.0.1:0"],
            vec!["--bind", "localhost:8096"],
            vec!["--web-port", "0"],
            vec!["--web-port", "65536"],
            vec!["--web-port", "bad"],
            vec!["--web-port"],
            vec!["--socket"],
            vec!["--port", "8096", "--web-port", "8097"],
            vec!["--bind", "127.0.0.1:8096", "--web-port", "8097"],
            vec!["--socket", "/tmp/a", "--socket", "/tmp/b"],
            vec!["--db", "/tmp/no-gateway-database"],
            vec!["--unknown"],
        ] {
            assert!(
                web_options(&args, false, None).is_err(),
                "accepted {args:?}"
            );
        }
        for args in [
            vec!["--web-port", "8097"],
            vec!["--web-bind", "127.0.0.1:8097"],
            vec!["--web", "--web"],
            vec!["--once", "--once"],
            vec!["--db"],
            vec!["--socket", "--once"],
            vec!["--web", "--bind", "0.0.0.0:8096"],
            vec!["--unknown"],
        ] {
            assert!(web_options(&args, true, None).is_err(), "accepted {args:?}");
        }
        assert!(web_options(&[], false, Some("0.0.0.0:8096")).is_err());
        assert!(web_options(&[], false, Some("invalid")).is_err());
    }
    #[test]
    fn web_options_policy_validation_and_daemon_requires_web() {
        for daemon in [false, true] {
            let mut args = vec![
                "--web-allow-origin",
                "https://zach.shocker.cl",
                "--web-allow-origin",
                "http://[::1]:8096",
                "--web-allow-decision-kind",
                "merge_approval",
            ];
            if daemon {
                args.push("--web");
            }
            let config = web_options(&args, daemon, None).unwrap().unwrap();
            assert_eq!(config.allowed_origins.len(), 2);
            assert_eq!(config.allowed_decision_kinds, ["merge_approval"]);
            for bad in [
                vec!["--web-allow-origin", "*"],
                vec!["--web-allow-origin", "null"],
                vec!["--web-allow-origin", "https://a/"],
                vec![
                    "--web-allow-origin",
                    "https://a",
                    "--web-allow-origin",
                    "https://a",
                ],
                vec!["--web-allow-decision-kind", "UPPER"],
                vec![
                    "--web-allow-decision-kind",
                    "a",
                    "--web-allow-decision-kind",
                    "a",
                ],
            ] {
                let mut bad = bad;
                if daemon {
                    bad.push("--web");
                }
                assert!(web_options(&bad, daemon, None).is_err());
            }
            for (flag, count) in [
                ("--web-allow-origin", 17),
                ("--web-allow-decision-kind", 33),
            ] {
                let mut args = Vec::new();
                for i in 0..count {
                    args.push(flag.to_string());
                    args.push(if flag.ends_with("origin") {
                        format!("https://a{i}")
                    } else {
                        format!("kind{i}")
                    });
                }
                if daemon {
                    args.push("--web".into());
                }
                assert!(parse_gateway_options(&args, daemon, None).is_err());
            }
        }
        assert!(web_options(&["--web-allow-origin", "https://a"], true, None).is_err());
        assert!(web_options(&["--web-allow-decision-kind", "merge_approval"], true, None).is_err());
    }
}
