use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use zach::ledger::actions::{MAX_EVENT_BYTES, TrustedIssuePolicy, decode_issue_event};
use zach::ledger::actions_journal::{
    ClaimOutcome, JournalRecord, JournalState, MAX_JOURNAL_BYTES, TrustedReconciliationObservation,
};

struct CliError {
    exit_code: i32,
    code: &'static str,
}

impl CliError {
    fn io(code: &'static str) -> Self {
        Self { exit_code: 1, code }
    }

    fn validation(code: &'static str) -> Self {
        Self { exit_code: 2, code }
    }
}

fn read_bounded_file(
    path: &str,
    limit_bytes: usize,
    oversized_code: &'static str,
) -> Result<String, CliError> {
    let mut file = File::open(path).map_err(|_| CliError::io("io_error"))?;
    if let Ok(meta) = file.metadata()
        && meta.is_file()
        && meta.len() > limit_bytes as u64
    {
        return Err(CliError::validation(oversized_code));
    }
    let mut buf = Vec::new();
    let mut take = (&mut file).take((limit_bytes as u64) + 1);
    take.read_to_end(&mut buf)
        .map_err(|_| CliError::io("io_error"))?;
    if buf.len() > limit_bytes {
        return Err(CliError::validation(oversized_code));
    }
    String::from_utf8(buf).map_err(|_| {
        if oversized_code == "event_payload_too_large" {
            CliError::validation("malformed_event_json")
        } else {
            CliError::validation("journal_json_malformed")
        }
    })
}

struct ParsedFlags {
    flags: BTreeMap<String, String>,
}

impl ParsedFlags {
    fn parse(args: &[String], allowed_flags: &[&str]) -> Result<Self, CliError> {
        let mut flags = BTreeMap::new();
        let mut seen = BTreeSet::new();
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            if !arg.starts_with("--") || arg == "--" {
                return Err(CliError::validation("unexpected_positional"));
            }
            if !allowed_flags.contains(&arg.as_str()) {
                return Err(CliError::validation("unknown_flag"));
            }
            if !seen.insert(arg.clone()) {
                return Err(CliError::validation("duplicate_flag"));
            }
            i += 1;
            if i >= args.len() || args[i].starts_with("--") {
                return Err(CliError::validation("missing_flag_value"));
            }
            let value = &args[i];
            flags.insert(arg.clone(), value.clone());
            i += 1;
        }
        Ok(Self { flags })
    }

    fn require(&self, flag: &str) -> Result<&str, CliError> {
        self.flags
            .get(flag)
            .map(|s| s.as_str())
            .ok_or_else(|| CliError::validation("missing_required_flag"))
    }

    fn optional(&self, flag: &str) -> Option<&str> {
        self.flags.get(flag).map(|s| s.as_str())
    }
}

fn parse_u64_flag(s: &str) -> Result<u64, CliError> {
    s.parse::<u64>()
        .map_err(|_| CliError::validation("invalid_flag_value"))
}

fn parse_allowed_actor_ids(s: &str) -> Result<Vec<u64>, CliError> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut ids = Vec::new();
    for part in s.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            return Err(CliError::validation("invalid_flag_value"));
        }
        let id = trimmed
            .parse::<u64>()
            .map_err(|_| CliError::validation("invalid_flag_value"))?;
        ids.push(id);
    }
    Ok(ids)
}

fn parse_state(s: &str) -> Result<JournalState, CliError> {
    match s {
        "succeeded" => Ok(JournalState::Succeeded),
        "rejected" => Ok(JournalState::Rejected),
        _ => Err(CliError::validation("invalid_flag_value")),
    }
}

fn run_accept(args: &[String]) -> Result<(), CliError> {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        print_accept_help();
        return Ok(());
    }
    let allowed = [
        "--event",
        "--event-name",
        "--repository-id",
        "--repository-full-name",
        "--allowed-actor-ids",
        "--accepted-at",
        "--policy-revision",
    ];
    let parsed = ParsedFlags::parse(args, &allowed)?;
    let event_path = parsed.require("--event")?;
    let event_name = parsed.require("--event-name")?;
    let repo_id_str = parsed.require("--repository-id")?;
    let repo_full_name = parsed.require("--repository-full-name")?;
    let actor_ids_str = parsed.require("--allowed-actor-ids")?;
    let accepted_at = parsed.require("--accepted-at")?;
    let policy_rev = parsed.require("--policy-revision")?;

    let repo_id = parse_u64_flag(repo_id_str)?;
    let actor_ids = parse_allowed_actor_ids(actor_ids_str)?;

    let event_content = read_bounded_file(event_path, MAX_EVENT_BYTES, "event_payload_too_large")?;

    let policy = TrustedIssuePolicy::new(repo_id, repo_full_name, actor_ids)
        .map_err(|e| CliError::validation(e.code()))?;

    let accepted = decode_issue_event(event_name, &event_content, &policy)
        .map_err(|e| CliError::validation(e.code()))?;

    let record = JournalRecord::new(accepted, accepted_at, policy_rev)
        .map_err(|e| CliError::validation(e.code()))?;

    let json = record
        .to_json()
        .map_err(|e| CliError::validation(e.code()))?;
    println!("{json}");
    Ok(())
}

fn run_replay(args: &[String]) -> Result<(), CliError> {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        print_replay_help();
        return Ok(());
    }
    let allowed = [
        "--record",
        "--event",
        "--event-name",
        "--repository-id",
        "--repository-full-name",
        "--allowed-actor-ids",
    ];
    let parsed = ParsedFlags::parse(args, &allowed)?;
    let record_path = parsed.require("--record")?;
    let event_path = parsed.require("--event")?;
    let event_name = parsed.require("--event-name")?;
    let repo_id_str = parsed.require("--repository-id")?;
    let repo_full_name = parsed.require("--repository-full-name")?;
    let actor_ids_str = parsed.require("--allowed-actor-ids")?;

    let repo_id = parse_u64_flag(repo_id_str)?;
    let actor_ids = parse_allowed_actor_ids(actor_ids_str)?;

    let record_content =
        read_bounded_file(record_path, MAX_JOURNAL_BYTES, "journal_payload_too_large")?;
    let record =
        JournalRecord::from_json(&record_content).map_err(|e| CliError::validation(e.code()))?;

    let event_content = read_bounded_file(event_path, MAX_EVENT_BYTES, "event_payload_too_large")?;

    let policy = TrustedIssuePolicy::new(repo_id, repo_full_name, actor_ids)
        .map_err(|e| CliError::validation(e.code()))?;

    let incoming = decode_issue_event(event_name, &event_content, &policy)
        .map_err(|e| CliError::validation(e.code()))?;

    record
        .check_replay(&incoming)
        .map_err(|e| CliError::validation(e.code()))?;

    let json = record
        .to_json()
        .map_err(|e| CliError::validation(e.code()))?;
    println!("{json}");
    Ok(())
}

fn run_claim(args: &[String]) -> Result<(), CliError> {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        print_claim_help();
        return Ok(());
    }
    let allowed = ["--record", "--execution-id"];
    let parsed = ParsedFlags::parse(args, &allowed)?;
    let record_path = parsed.require("--record")?;
    let execution_id = parsed.require("--execution-id")?;

    let record_content =
        read_bounded_file(record_path, MAX_JOURNAL_BYTES, "journal_payload_too_large")?;
    let mut record =
        JournalRecord::from_json(&record_content).map_err(|e| CliError::validation(e.code()))?;

    let outcome = record
        .claim_execution(execution_id)
        .map_err(|e| CliError::validation(e.code()))?;

    let json = record
        .to_json()
        .map_err(|e| CliError::validation(e.code()))?;
    println!("{json}");

    match outcome {
        ClaimOutcome::Granted => std::process::exit(0),
        ClaimOutcome::TerminalReplay { .. } => std::process::exit(10),
        ClaimOutcome::ReconciliationRequired => std::process::exit(75),
    }
}

fn run_complete(args: &[String]) -> Result<(), CliError> {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        print_complete_help();
        return Ok(());
    }
    let allowed = ["--record", "--state", "--code", "--reference"];
    let parsed = ParsedFlags::parse(args, &allowed)?;
    let record_path = parsed.require("--record")?;
    let state_str = parsed.require("--state")?;
    let code = parsed.require("--code")?;
    let reference = parsed.optional("--reference");

    let state = parse_state(state_str)?;

    let record_content =
        read_bounded_file(record_path, MAX_JOURNAL_BYTES, "journal_payload_too_large")?;
    let mut record =
        JournalRecord::from_json(&record_content).map_err(|e| CliError::validation(e.code()))?;

    record
        .complete_terminal(state, code, reference)
        .map_err(|e| CliError::validation(e.code()))?;

    let json = record
        .to_json()
        .map_err(|e| CliError::validation(e.code()))?;
    println!("{json}");
    Ok(())
}

fn run_ambiguous(args: &[String]) -> Result<(), CliError> {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        print_ambiguous_help();
        return Ok(());
    }
    let allowed = ["--record"];
    let parsed = ParsedFlags::parse(args, &allowed)?;
    let record_path = parsed.require("--record")?;

    let record_content =
        read_bounded_file(record_path, MAX_JOURNAL_BYTES, "journal_payload_too_large")?;
    let mut record =
        JournalRecord::from_json(&record_content).map_err(|e| CliError::validation(e.code()))?;

    record
        .mark_ambiguous()
        .map_err(|e| CliError::validation(e.code()))?;

    let json = record
        .to_json()
        .map_err(|e| CliError::validation(e.code()))?;
    println!("{json}");
    Ok(())
}

fn run_reconcile(args: &[String]) -> Result<(), CliError> {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        print_reconcile_help();
        return Ok(());
    }
    let allowed = ["--record", "--state", "--code", "--reference"];
    let parsed = ParsedFlags::parse(args, &allowed)?;
    let record_path = parsed.require("--record")?;
    let state_str = parsed.require("--state")?;
    let code = parsed.require("--code")?;
    let reference = parsed.optional("--reference");

    let observation = match state_str {
        "succeeded" => TrustedReconciliationObservation::succeeded(code, reference),
        "rejected" => TrustedReconciliationObservation::rejected(code, reference),
        _ => return Err(CliError::validation("invalid_flag_value")),
    };

    let record_content =
        read_bounded_file(record_path, MAX_JOURNAL_BYTES, "journal_payload_too_large")?;
    let mut record =
        JournalRecord::from_json(&record_content).map_err(|e| CliError::validation(e.code()))?;

    record
        .resolve_trusted_reconciliation(&observation)
        .map_err(|e| CliError::validation(e.code()))?;

    let json = record
        .to_json()
        .map_err(|e| CliError::validation(e.code()))?;
    println!("{json}");
    Ok(())
}

fn print_usage() {
    println!("Usage: zach-actions <command> [options]");
    println!();
    println!("Commands:");
    println!(
        "  accept     Decode an issue event, validate policy, and freeze an accepted journal record"
    );
    println!("  replay     Verify an issue event against an existing frozen journal record");
    println!("  claim      Claim execution for a journal record");
    println!(
        "  complete   Record terminal outcome (succeeded or rejected) for an executing record"
    );
    println!("  ambiguous  Mark an executing record as ambiguous");
    println!("  reconcile  Resolve an ambiguous record to terminal outcome");
    println!(
        "             RESTRICTION: Explicitly restricted to independently verified effect observations."
    );
    println!("             Do not invent retries, TTLs or evidence.");
}

fn print_accept_help() {
    println!(
        "Usage: zach-actions accept --event FILE --event-name issues --repository-id ID --repository-full-name OWNER/REPO --allowed-actor-ids COMMA_IDS --accepted-at UTC --policy-revision SHA"
    );
}

fn print_replay_help() {
    println!(
        "Usage: zach-actions replay --record FILE --event FILE --event-name issues --repository-id ID --repository-full-name OWNER/REPO --allowed-actor-ids COMMA_IDS"
    );
}

fn print_claim_help() {
    println!("Usage: zach-actions claim --record FILE --execution-id ID");
}

fn print_complete_help() {
    println!(
        "Usage: zach-actions complete --record FILE --state succeeded|rejected --code CODE [--reference VALUE]"
    );
}

fn print_ambiguous_help() {
    println!("Usage: zach-actions ambiguous --record FILE");
}

fn print_reconcile_help() {
    println!(
        "Usage: zach-actions reconcile --record FILE --state succeeded|rejected --code CODE [--reference VALUE]"
    );
    println!();
    println!("RESTRICTION: Explicitly restricted to independently verified effect observations.");
    println!("Do not invent retries, TTLs or evidence.");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("missing_command");
        std::process::exit(2);
    }
    let command = &args[1];
    if command == "--help" || command == "-h" || command == "help" {
        print_usage();
        std::process::exit(0);
    }
    let cmd_args = &args[2..];
    let result = match command.as_str() {
        "accept" => run_accept(cmd_args),
        "replay" => run_replay(cmd_args),
        "claim" => run_claim(cmd_args),
        "complete" => run_complete(cmd_args),
        "ambiguous" => run_ambiguous(cmd_args),
        "reconcile" => run_reconcile(cmd_args),
        _ => {
            eprintln!("unknown_command");
            std::process::exit(2);
        }
    };
    if let Err(err) = result {
        eprintln!("{}", err.code);
        std::process::exit(err.exit_code);
    }
}
