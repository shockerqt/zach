use std::path::PathBuf;
use zach::ledger::candidate::{
    TrustedLedgerContext, derive_candidate, read_bounded, write_private,
};

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut values = std::collections::BTreeMap::new();
    while let Some(flag) = args.next() {
        if ![
            "--mirror",
            "--request",
            "--accepted-at",
            "--trusted-context",
            "--output",
        ]
        .contains(&flag.as_str())
        {
            return Err("arguments-invalid".into());
        }
        let value = args.next().ok_or("arguments-invalid")?;
        if values.insert(flag, value).is_some() {
            return Err("arguments-invalid".into());
        }
    }
    let required = |key: &str| {
        values
            .get(key)
            .ok_or_else(|| "arguments-invalid".to_owned())
    };
    let request = read_bounded(&PathBuf::from(required("--request")?)).map_err(str::to_owned)?;
    let context = match values.get("--trusted-context") {
        Some(path) => {
            TrustedLedgerContext::parse(&read_bounded(&PathBuf::from(path)).map_err(str::to_owned)?)
                .map_err(str::to_owned)?
        }
        None => TrustedLedgerContext::default(),
    };
    let result = derive_candidate(
        PathBuf::from(required("--mirror")?),
        &request,
        required("--accepted-at")?,
        &context,
    )?;
    write_private(&PathBuf::from(required("--output")?), result.as_bytes()).map_err(str::to_owned)
}
fn main() {
    if let Err(code) = run() {
        // Only bounded machine codes cross this CLI boundary.
        let safe = !code.is_empty()
            && code.len() <= 80
            && code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-');
        eprintln!("{}", if safe { &code } else { "candidate-invalid" });
        std::process::exit(1);
    }
}
