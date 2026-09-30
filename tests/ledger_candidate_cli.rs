use std::process::Command;

#[test]
fn invalid_arguments_expose_only_codes() {
    for args in [
        vec![],
        vec!["--unknown", "secret-value"],
        vec!["--request", "a", "--request", "b"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_zach-ledger-candidate"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"arguments-invalid\n");
    }
}

#[test]
fn unreadable_input_does_not_echo_paths_or_context() {
    let output = Command::new(env!("CARGO_BIN_EXE_zach-ledger-candidate"))
        .args([
            "--mirror",
            "/trusted-mirror",
            "--request",
            "/nonexistent-sensitive-input",
            "--accepted-at",
            "invalid",
            "--output",
            "/unused-output",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    #[cfg(target_os = "linux")]
    assert_eq!(output.stderr, b"input-file-invalid\n");
    #[cfg(not(target_os = "linux"))]
    assert_eq!(output.stderr, b"unsupported-platform\n");
}
