//! Opt-in, inference-free systemd/bubblewrap supervision contract test.
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zach::v2::isolation::{NetworkPolicy, PreparedResources, ProxyHandle};
use zach::v2::router::{ModelFamily, resolve_stage_route};
use zach::v2::runner::{
    AttemptManifest, StageCommandSpec, SystemUnitController, UnitController, UnitObservation,
    UnitState, build_clean_env_from_process, harvest_detached, read_attempt_manifest,
    stop_and_cleanup,
};

fn directory(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn artifact(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
struct TestRoot(PathBuf);
impl Drop for TestRoot {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct UnitGuard(String);
impl Drop for UnitGuard {
    fn drop(&mut self) {
        if let Err(error) = SystemUnitController.stop(&self.0) {
            eprintln!("host-test final stop: {error}");
        }
    }
}

struct ProxyOwnerProcess(std::process::Child);
impl Drop for ProxyOwnerProcess {
    fn drop(&mut self) {
        let _kill = self.0.kill();
        let _wait = self.0.wait();
    }
}

#[test]
#[ignore = "subprocess fixture for the opt-in host supervision test"]
fn host_proxy_owner_process_fixture() {
    let Ok(net) = std::env::var("ZACH_HOST_PROXY_FIXTURE_NET") else {
        return;
    };
    let net = PathBuf::from(net);
    let _proxy = ProxyHandle::start(&net, ModelFamily::OpenAiSol).unwrap();
    artifact(&net.join("owner-ready"), b"ready");
    std::thread::sleep(Duration::from_secs(60));
}

fn manifest(root: &Path, id: &str, worker: Vec<String>, network: NetworkPolicy) -> AttemptManifest {
    let dir = root.join("attempts").join(id);
    directory(&dir);
    for file in ["stdin", "stdout.jsonl", "stderr.log"] {
        artifact(&dir.join(file), b"");
    }
    let unit = format!("zach-stage-host-test-{}-{id}", std::process::id());
    let mut args = vec![
        "--user".into(),
        "--no-block".into(),
        "--service-type=exec".into(),
        format!("--unit={unit}.service"),
        "--slice=zach-workers.slice".into(),
    ];
    for property in [
        "RemainAfterExit=yes".to_string(),
        "CollectMode=inactive".into(),
        "RuntimeMaxSec=30".into(),
        "KillMode=control-group".into(),
        "TimeoutStopSec=3".into(),
        format!("StandardInput=file:{}", dir.join("stdin").display()),
        format!("StandardOutput=file:{}", dir.join("stdout.jsonl").display()),
        format!("StandardError=file:{}", dir.join("stderr.log").display()),
    ] {
        args.extend(["-p".into(), property]);
    }
    args.push("--".into());
    args.extend(worker);
    let spec = StageCommandSpec {
        network,
        writable: false,
        unit_name: unit,
        program: "systemd-run".into(),
        args,
        env: build_clean_env_from_process(),
        worktree_path: dir.to_string_lossy().into_owned(),
        timeout_secs: 30,
        stall_timeout_secs: 15,
        prompt: String::new(),
        stdin_payload: String::new(),
        output_schema_json: None,
    };
    let m = AttemptManifest {
        mount_layout_version: 1,
        attempt_id: id.into(),
        task_id: "HOST-TEST".into(),
        route: resolve_stage_route("S", "impl", 0, None).unwrap().unwrap(),
        spec,
        sha_before: "host-test-no-git-mutations".into(),
        attempt_dir: dir,
    };
    artifact(
        &m.attempt_dir.join("manifest.json"),
        &serde_json::to_vec_pretty(&m).unwrap(),
    );
    m
}
fn wait_for<F: FnMut() -> bool>(label: &str, mut predicate: F) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out: {label}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

struct OrderCheckingController {
    dir: PathBuf,
    require_harvest: bool,
}
impl UnitController for OrderCheckingController {
    fn inspect(&self, unit: &str) -> Result<UnitObservation, String> {
        SystemUnitController.inspect(unit)
    }
    fn launch(&self, m: &AttemptManifest) -> Result<(), String> {
        SystemUnitController.launch(m)
    }
    fn list_units(&self) -> Result<Vec<String>, String> {
        SystemUnitController.list_units()
    }
    fn stop(&self, unit: &str) -> Result<(), String> {
        assert!(
            self.dir.join("codex-home").is_dir(),
            "auth deleted before stop"
        );
        assert!(
            self.dir.join("net").is_dir(),
            "mounted directory deleted before stop"
        );
        if self.require_harvest {
            assert!(
                self.dir.join("harvest.json").is_file(),
                "harvest receipt missing before stop"
            );
        }
        SystemUnitController.stop(unit)
    }
    fn reset_failed(&self, unit: &str) -> Result<(), String> {
        SystemUnitController.reset_failed(unit)
    }
}

#[test]
#[ignore = "opt-in harmless user systemd and bubblewrap integration; no provider inference"]
fn host_supervision_retained_exit_restart_proxy_rebind_and_ordered_cleanup() {
    assert_eq!(
        std::env::var("ZACH_RUN_HOST_SUPERVISION_TEST").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("target/z25-host-{}", std::process::id()));
    directory(&root);
    let root = TestRoot(fs::canonicalize(root).unwrap());
    let output = "{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"harmless exit zero\"}}";
    let m = manifest(
        &root.0,
        "exit-zero",
        vec!["/usr/bin/printf".into(), "%s\n".into(), output.into()],
        NetworkPolicy::None,
    );
    let _unit = UnitGuard(m.spec.unit_name.clone());
    SystemUnitController.launch(&m).unwrap();
    wait_for("retained active/exited exit-0", || {
        SystemUnitController
            .inspect(&m.spec.unit_name)
            .unwrap()
            .state()
            .unwrap()
            == UnitState::Exited
    });
    let observation = SystemUnitController.inspect(&m.spec.unit_name).unwrap();
    assert_eq!(observation.active_state, "active");
    assert_eq!(observation.sub_state, "exited");
    assert!(observation.success());
    // Reconstruct the supervisor from disk, using a fresh controller instance.
    let restored = read_attempt_manifest(&root.0, "exit-zero").unwrap();
    assert_eq!(restored.spec.unit_name, m.spec.unit_name);
    let result = harvest_detached(&restored, &observation).unwrap();
    assert_eq!(result.status, "PASSED");
    assert_eq!(
        result.sha_before.as_deref(),
        Some("host-test-no-git-mutations")
    );
    directory(&m.attempt_dir.join("codex-home"));
    directory(&m.attempt_dir.join("net"));
    stop_and_cleanup(
        &OrderCheckingController {
            dir: m.attempt_dir.clone(),
            require_harvest: true,
        },
        &m.spec.unit_name,
        &m.attempt_dir,
        None,
        false,
    )
    .unwrap();
    assert!(!m.attempt_dir.join("codex-home").exists());
    assert!(!m.attempt_dir.join("net").exists());
    assert!(m.attempt_dir.join("harvest.json").exists());
    println!(
        "PASS: RemainAfterExit=yes retained active/exited exit-0; disk reattachment; harvest before stop and cleanup"
    );

    let id = "live-proxy";
    let dir = root.0.join("attempts").join(id);
    directory(&dir);
    directory(&dir.join("net"));
    directory(&dir.join("codex-home"));
    artifact(&dir.join("codex-home/auth.json"), b"{}");
    let inode = fs::metadata(dir.join("net")).unwrap().ino();
    let mut proxy_owner = ProxyOwnerProcess(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "host_proxy_owner_process_fixture"])
            .env("ZACH_HOST_PROXY_FIXTURE_NET", dir.join("net"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for("proxy-owner process ready", || {
        dir.join("net/owner-ready").is_file()
    });
    let script = r#"import os,socket,time
p='/run/zach-net/'
def connect():
 s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(p+'proxy.sock');s.sendall(b'CONNECT forbidden.example:443 HTTP/1.1\r\n\r\n');assert b'403' in s.recv(4096);s.close()
connect();print('FIRST_CONNECTION',flush=True)
while not os.path.exists(p+'continue'): time.sleep(.05)
connect();print('REBOUND_CONNECTION',flush=True)
time.sleep(20)
"#;
    let worker = vec![
        "/usr/bin/bwrap".into(),
        "--unshare-all".into(),
        "--new-session".into(),
        "--ro-bind".into(),
        "/".into(),
        "/".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--tmpfs".into(),
        "/run".into(),
        "--ro-bind".into(),
        dir.join("net").to_string_lossy().into_owned(),
        "/run/zach-net".into(),
        "--".into(),
        "/usr/bin/python3".into(),
        "-c".into(),
        script.into(),
    ];
    let m = manifest(
        &root.0,
        id,
        worker,
        NetworkPolicy::ProviderApi(ModelFamily::OpenAiSol),
    );
    let _live_unit = UnitGuard(m.spec.unit_name.clone());
    SystemUnitController.launch(&m).unwrap();
    wait_for("sandbox's initial proxy connection", || {
        fs::read_to_string(dir.join("stdout.jsonl"))
            .unwrap()
            .contains("FIRST_CONNECTION")
    });
    let before = SystemUnitController.inspect(&m.spec.unit_name).unwrap();
    assert_eq!(before.state().unwrap(), UnitState::Running);
    assert!(!before.invocation_id.is_empty());
    // Kill the actual proxy owner without running destructors. Its stale socket
    // inode and required auth/net directory must survive for cold recovery.
    proxy_owner.0.kill().unwrap();
    assert!(!proxy_owner.0.wait().unwrap().success());
    assert!(dir.join("net").is_dir());
    assert!(dir.join("net/proxy.sock").exists());
    let restored = read_attempt_manifest(&root.0, id).unwrap();
    let resources = PreparedResources::recover(
        &restored.attempt_dir,
        restored.route.family,
        restored.spec.network,
    )
    .unwrap();
    assert_eq!(fs::metadata(dir.join("net")).unwrap().ino(), inode);
    artifact(&dir.join("net/continue"), b"continue");
    wait_for(
        "surviving sandbox reconnects through replacement socket inode",
        || {
            fs::read_to_string(dir.join("stdout.jsonl"))
                .unwrap()
                .contains("REBOUND_CONNECTION")
        },
    );
    let after = SystemUnitController.inspect(&m.spec.unit_name).unwrap();
    assert_eq!(before.invocation_id, after.invocation_id);
    assert_eq!(after.state().unwrap(), UnitState::Running);
    stop_and_cleanup(
        &OrderCheckingController {
            dir: dir.clone(),
            require_harvest: false,
        },
        &m.spec.unit_name,
        &dir,
        Some(resources),
        false,
    )
    .unwrap();
    assert!(!dir.join("net").exists());
    assert!(!dir.join("codex-home").exists());
    println!(
        "PASS: proxy-owner SIGKILL left stale socket; cold reattachment kept InvocationID; directory-mounted proxy.sock rebound; surviving sandbox reconnected; stop confirmed before auth/net cleanup"
    );
}
