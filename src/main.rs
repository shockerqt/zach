use std::env;
use std::fs;
use std::path::PathBuf;

use zach::ledger;
use zach::v2::intake::{ingest_export_json, sync_from_ws_task};
use zach::v2::pipeline::plan_task_execution;
use zach::v2::socket::{ClientCommand, DaemonServer, write_ndjson};
use zach::v2::store::{DecisionResolution, V2Store};
use zach::v2::{default_db_path, default_socket_path, default_state_dir, default_ws_task_bin};
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

fn run_v2_sync(args: &[String]) {
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

    println!(
        "zachd started · socket={} · initial_seq={} · once={}",
        socket_path.display(),
        initial_seq,
        once
    );

    zach::v2::socket::install_shutdown_signals().unwrap_or_else(|error| {
        eprintln!("install shutdown signals: {error}");
        std::process::exit(1)
    });
    let coordinator = zach::v2::coordinator::Coordinator::spawn(store, state_dir);
    if let Err(error) = server.run_coordinated(coordinator, once) {
        eprintln!("daemon error: {error}");
        std::process::exit(1);
    }
    if once {
        println!("zachd: completed single loop execution");
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
    println!("       zach sync [--export-file <PATH>] [--ws-task-bin <PATH>] [--db <PATH>]");
    println!("       zach config [--max-parallel <1..16>] [--db <PATH>]");
    println!(
        "       zach run [--task <TASK_ID>] [--group <GROUP>] [--once] [--dry-run] [--json] [--db <PATH>]"
    );
    println!("       zach doctor [--json] [--worktree <PATH>]");
    println!("       zach daemon [--socket <PATH>] [--db <PATH>] [--once]");
    println!("       zach attach [--group <GROUP>] [--since-seq <N>] [--once] [--socket <PATH>]");
    println!(
        "       zach events [--group <GROUP>] [--since-seq <N>] [--wait] [--socket <PATH>] [--db <PATH>]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
