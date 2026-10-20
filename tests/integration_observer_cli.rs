use std::path::PathBuf;
use std::process::{Command, Output};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zach-integration-observe"))
        .env_remove("ZACH_INSTALLATION_TOKEN")
        .args(args)
        .output()
        .unwrap()
}

fn rejected(output: Output, expected: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, format!("{expected}\n").as_bytes());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("plaintext-sensitive-value"));
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "zach-integration-cli-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn invoke(&self, raw: &str) -> Output {
        let input = self.0.join("input.json");
        let output = self.0.join("output.json");
        std::fs::write(&input, raw).unwrap();
        let result = cli(&[
            "--input",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ]);
        assert!(!output.exists());
        result
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn valid() -> String {
    format!(
        r#"{{"request":{{"governance_sha":"{}","task_id":"ZACH-002","run_id":"ZACH-002-20261020-000000-implementation","request_id":"request-0001"}},"bindings":{{"accepted_journal_sha":"{}","request_digest":"{}","policy_revision":"{}","tool_revision":"{}","verified_at":"2026-10-20T01:02:03Z"}}}}"#,
        "a".repeat(40),
        "b".repeat(40),
        "c".repeat(64),
        "d".repeat(40),
        "e".repeat(40)
    )
}

#[test]
fn arguments_are_strict_and_never_echo_values() {
    for args in [
        vec![],
        vec!["--unknown", "plaintext-sensitive-value"],
        vec!["--input", "relative", "--output", "/unused"],
        vec!["--input", "/unused", "--input", "/duplicate"],
        vec!["--input", "/unused"],
        vec!["--input", "/unused", "--output"],
    ] {
        rejected(cli(&args), "observer-arguments-invalid");
    }
}

#[test]
fn input_shape_size_depth_and_bindings_fail_before_http() {
    let fixture = Fixture::new();
    for raw in [
        "plaintext-sensitive-value".into(),
        "{}".into(),
        valid().replace("\"request\":", "\"request\":{},\"request\":"),
        valid().replace(
            "\"request\":",
            "\"api_url\":\"plaintext-sensitive-value\",\"request\":",
        ),
        valid().replace("2026-10-20", "2026-02-30"),
        valid().replace("\"task_id\":\"ZACH-002\"", "\"task_id\":false"),
        format!("{} ", "[".repeat(33)),
        format!("{}{}", " ".repeat(16_384), valid()),
        valid().replace("\"request\":", "\"request\":[],\"other\":"),
        valid().replace(
            "\"tool_revision\":",
            "\"token\":\"plaintext-sensitive-value\",\"tool_revision\":",
        ),
        valid().replace("\"request-0001\"", "\"request.0001\""),
        valid().replace("\"verified_at\"", "\"verified_at\u{8}\""),
    ] {
        rejected(fixture.invoke(&raw), "observer-input-invalid");
    }
    let mut trailing = valid();
    trailing.insert(trailing.len() - 1, ',');
    rejected(fixture.invoke(&trailing), "observer-input-invalid");
}

#[test]
fn missing_token_is_static_and_prevents_collection() {
    rejected(
        Fixture::new().invoke(&valid()),
        "observer-token-unavailable",
    );
    let fixture = Fixture::new();
    let input = fixture.0.join("input.json");
    std::fs::write(&input, valid()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_zach-integration-observe"))
        .env(
            "ZACH_INSTALLATION_TOKEN",
            "plaintext-sensitive-value\ninvalid",
        )
        .args([
            "--input",
            input.to_str().unwrap(),
            "--output",
            fixture.0.join("output.json").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    rejected(output, "observer-token-unavailable");
}

#[cfg(target_os = "linux")]
#[test]
fn symlink_and_nonregular_input_are_rejected() {
    let fixture = Fixture::new();
    let target = fixture.0.join("target.json");
    std::fs::write(&target, valid()).unwrap();
    let link = fixture.0.join("input.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    for input in [&link, &fixture.0] {
        rejected(
            cli(&[
                "--input",
                input.to_str().unwrap(),
                "--output",
                fixture.0.join("output.json").to_str().unwrap(),
            ]),
            "observer-input-invalid",
        );
    }
}
