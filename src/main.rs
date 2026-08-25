use std::env;

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
        "governance.audit-task-integration" => run_audit(&args[2..]),
        "--help" | "-h" => print_usage(),
        unknown => {
            eprintln!("unknown option: {unknown}");
            print_usage();
            std::process::exit(2);
        }
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

fn usage_error(message: &str) -> ! {
    eprintln!("{message}");
    print_usage();
    std::process::exit(2);
}

fn print_usage() {
    println!("Usage: zach [--health | --config]");
    println!(
        "       zach governance.audit-task-integration --task-id <TASK-ID> --request-id <REQUEST-ID>"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bind_address_is_loopback() {
        assert_eq!(DEFAULT_BIND_ADDR, "127.0.0.1:8090");
    }
}
