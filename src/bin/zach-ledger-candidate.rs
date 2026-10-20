use std::path::PathBuf;
use zach::ledger::candidate::{
    TrustedLedgerContext, derive_actions_candidate, derive_actions_closure_candidate,
    derive_candidate, read_bounded, write_private,
};

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut values = std::collections::BTreeMap::new();
    while let Some(flag) = args.next() {
        if ![
            "--mirror",
            "--request",
            "--accepted-at",
            "--journal-record",
            "--accepted-revision",
            "--claim-revision",
            "--trusted-context",
            "--output",
            "--profile",
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
    let journal_mode = values.contains_key("--journal-record");
    let closure = match values.get("--profile").map(String::as_str) {
        None => false,
        Some("integration-closure") if journal_mode => true,
        _ => return Err("arguments-invalid".into()),
    };
    let mode_fields = if journal_mode {
        [
            "--journal-record",
            "--accepted-revision",
            "--claim-revision",
        ]
        .as_slice()
    } else {
        ["--request", "--accepted-at"].as_slice()
    };
    if mode_fields.iter().any(|key| !values.contains_key(*key))
        || values.keys().any(|key| {
            !["--mirror", "--trusted-context", "--output", "--profile"].contains(&key.as_str())
                && !mode_fields.contains(&key.as_str())
        })
    {
        return Err("arguments-invalid".into());
    }
    required("--mirror")?;
    required("--output")?;
    let context = match values.get("--trusted-context") {
        Some(path) => {
            let text = read_bounded(&PathBuf::from(path)).map_err(str::to_owned)?;
            (if closure {
                TrustedLedgerContext::parse_closure(&text)
            } else {
                TrustedLedgerContext::parse(&text)
            })
            .map_err(str::to_owned)?
        }
        None if closure => return Err("invalid-trusted-context".into()),
        None => TrustedLedgerContext::default(),
    };
    let result = if journal_mode {
        let journal =
            read_bounded(&PathBuf::from(required("--journal-record")?)).map_err(str::to_owned)?;
        (if closure {
            derive_actions_closure_candidate
        } else {
            derive_actions_candidate
        })(
            PathBuf::from(required("--mirror")?),
            &journal,
            required("--accepted-revision")?,
            required("--claim-revision")?,
            &context,
        )?
    } else {
        let request =
            read_bounded(&PathBuf::from(required("--request")?)).map_err(str::to_owned)?;
        derive_candidate(
            PathBuf::from(required("--mirror")?),
            &request,
            required("--accepted-at")?,
            &context,
        )?
    };
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
