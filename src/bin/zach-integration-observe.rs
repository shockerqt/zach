use std::path::PathBuf;
use zach::integration_observer::execute_integration_observer_input;
use zach::ledger::candidate::{read_bounded, write_private};

fn run() -> Result<(), &'static str> {
    let mut args = std::env::args_os().skip(1);
    let mut input = None;
    let mut output = None;
    while let Some(flag) = args.next() {
        let slot = match flag.to_str() {
            Some("--input") => &mut input,
            Some("--output") => &mut output,
            _ => return Err("observer-arguments-invalid"),
        };
        if slot.is_some() {
            return Err("observer-arguments-invalid");
        }
        let path = PathBuf::from(args.next().ok_or("observer-arguments-invalid")?);
        if !path.is_absolute() {
            return Err("observer-arguments-invalid");
        }
        *slot = Some(path);
    }
    let input = input.ok_or("observer-arguments-invalid")?;
    let output = output.ok_or("observer-arguments-invalid")?;
    let raw = read_bounded(&input).map_err(|_| "observer-input-invalid")?;
    let token = std::env::var("ZACH_INSTALLATION_TOKEN").unwrap_or_default();
    let bytes = execute_integration_observer_input(&raw, &token)?;
    write_private(&output, &bytes).map_err(|_| "observer-output-invalid")
}

fn main() {
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(1);
    }
}
