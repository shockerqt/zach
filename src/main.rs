use std::env;

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
    let command = env::args().nth(1).unwrap_or_else(|| "--health".to_owned());
    let config = BootstrapConfig::from_env();

    match command.as_str() {
        "--health" => println!("zach: healthy"),
        "--config" => println!("bind_addr={}", config.bind_addr),
        "--help" | "-h" => print_usage(),
        unknown => {
            eprintln!("unknown option: {unknown}");
            print_usage();
            std::process::exit(2);
        }
    }
}

fn print_usage() {
    println!("Usage: zach [--health | --config]");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bind_address_is_loopback() {
        assert_eq!(DEFAULT_BIND_ADDR, "127.0.0.1:8090");
    }
}
