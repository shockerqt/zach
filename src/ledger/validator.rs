use super::json::{Json, object_bool, object_get, object_string};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const TRUSTED_CONTRACT_REVISION: &str = "3bbbb3463573893571f45ee92625a54414f8df13";
pub(super) const TRUSTED_VALIDATOR_REVISION: &str = "3bbbb3463573893571f45ee92625a54414f8df13";
const TRUSTED_CONTRACT_BLOB: &str = "8c6e1a0e502e1e71582586d5db766f7f3dbd8a13";
const TRUSTED_MUTATOR_BLOB: &str = "470db19c42f7184d068d42c273071aa60ec3a039";
pub(super) const MAX_CHANGED_FILES: usize = 8;
pub(super) const MAX_TOTAL_RESULT_UTF8_BYTES: usize = 48_000;
pub(super) const MAX_RECEIPT_UTF8_BYTES: usize = 60_000;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LedgerRequest {
    pub request_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub base_sha: String,
    pub operation: String,
    pub parameters: Json,
    pub contract_revision: String,
    pub canonical_json: String,
    pub request_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChangeOperation {
    Upsert,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LedgerChange {
    pub path: String,
    pub operation: ChangeOperation,
    pub content: Option<String>,
    pub blob_sha: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedLedgerResult {
    pub changes: Vec<LedgerChange>,
    pub validated_tree_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidationError {
    pub code: String,
    pub detail: String,
}

impl ValidationError {
    pub(super) fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for ValidationError {}

pub(crate) trait LedgerValidator: Send + Sync {
    fn validator_revision(&self) -> &str;
    fn validate(
        &self,
        request: &LedgerRequest,
        accepted_at: &str,
    ) -> Result<ValidatedLedgerResult, ValidationError>;
}

#[derive(Debug, Clone)]
pub(super) struct PinnedGovernanceValidator {
    mirror: PathBuf,
}

impl PinnedGovernanceValidator {
    pub(super) fn new(mirror: PathBuf) -> Result<Self, ValidationError> {
        if !mirror.is_absolute() {
            return Err(ValidationError::new(
                "trusted-validator-unavailable",
                "Governance mirror path must be absolute trusted configuration",
            ));
        }
        Ok(Self { mirror })
    }
}

impl LedgerValidator for PinnedGovernanceValidator {
    fn validator_revision(&self) -> &str {
        TRUSTED_VALIDATOR_REVISION
    }

    fn validate(
        &self,
        request: &LedgerRequest,
        accepted_at: &str,
    ) -> Result<ValidatedLedgerResult, ValidationError> {
        if request.contract_revision != TRUSTED_CONTRACT_REVISION {
            return Err(ValidationError::new(
                "contract-revision-mismatch",
                "request contract revision does not match trusted integrated Governance contract",
            ));
        }
        if !sha40(&request.base_sha) {
            return Err(ValidationError::new(
                "invalid-request",
                "base_sha is not an immutable Git commit identity",
            ));
        }

        let workspace = TempDirectory::new("zach-ledger-validation")?;
        let validator_root = workspace.path.join("validator");
        let base_root = workspace.path.join("base");
        materialize_revision(&self.mirror, TRUSTED_VALIDATOR_REVISION, &validator_root)?;
        materialize_revision(&self.mirror, &request.base_sha, &base_root)?;
        verify_tooling_pin(&validator_root)?;
        let observed_base = command_text(
            Command::new("git")
                .arg("-C")
                .arg(&base_root)
                .args(["rev-parse", "HEAD"]),
            "read materialized Governance base HEAD",
        )?;
        if observed_base.trim() != request.base_sha {
            return Err(ValidationError::new(
                "base-mismatch",
                "materialized Governance base does not equal requested immutable SHA",
            ));
        }

        let request_path = workspace.path.join("request.json");
        fs::write(&request_path, &request.canonical_json).map_err(|error| {
            ValidationError::new(
                "validator-io",
                format!("could not materialize canonical request: {error}"),
            )
        })?;
        let output_path = workspace.path.join("result.json");
        let mut command = Command::new("python3");
        command
            .arg(validator_root.join("bin/ws-ledger-mutate"))
            .arg("--root")
            .arg(&base_root)
            .arg("--request")
            .arg(&request_path)
            .arg("--expected-base-sha")
            .arg(&request.base_sha)
            .arg("--expected-contract-revision")
            .arg(TRUSTED_CONTRACT_REVISION)
            .arg("--accepted-at")
            .arg(accepted_at)
            .arg("--output")
            .arg(&output_path);
        let output = command.output().map_err(|error| {
            ValidationError::new(
                "trusted-validator-unavailable",
                format!("could not execute pinned Governance validator: {error}"),
            )
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let code = parse_rejected_code(&stderr).unwrap_or("candidate-invalid");
            return Err(ValidationError::new(
                code,
                "pinned Governance validator rejected the transaction",
            ));
        }

        let result_text = fs::read_to_string(&output_path).map_err(|error| {
            ValidationError::new(
                "validator-output-invalid",
                format!("could not read trusted validator result: {error}"),
            )
        })?;
        let result = Json::parse(&result_text)
            .map_err(|error| ValidationError::new("validator-output-invalid", error.to_string()))?;
        let object = result.as_object().ok_or_else(|| {
            ValidationError::new(
                "validator-output-invalid",
                "validator result is not an object",
            )
        })?;
        if object_string(object, "request_digest") != Some(request.request_digest.as_str())
            || object_bool(object, "candidate_validated") != Some(true)
        {
            return Err(ValidationError::new(
                "validator-output-invalid",
                "trusted validator output is not bound to the canonical request",
            ));
        }
        let raw_changes = object_get(object, "changes")
            .and_then(Json::as_array)
            .ok_or_else(|| {
                ValidationError::new("validator-output-invalid", "validator changes are missing")
            })?;
        let changes = parse_changes(raw_changes)?;
        enforce_result_limits(&changes)?;
        let tree_sha = materialize_and_verify_result(&base_root, &changes)?;
        Ok(ValidatedLedgerResult {
            changes,
            validated_tree_sha: tree_sha,
        })
    }
}

fn materialize_revision(
    mirror: &Path,
    revision: &str,
    destination: &Path,
) -> Result<(), ValidationError> {
    if !sha40(revision) {
        return Err(ValidationError::new(
            "trusted-validator-unavailable",
            "materialization revision is not an immutable SHA",
        ));
    }
    command_success(
        Command::new("git")
            .args(["clone", "--quiet", "--no-checkout", "--shared"])
            .arg(mirror)
            .arg(destination),
        "materialize configured Governance mirror",
    )?;
    command_success(
        Command::new("git")
            .arg("-C")
            .arg(destination)
            .args(["checkout", "--quiet", "--detach", revision]),
        "checkout immutable Governance revision",
    )
}

fn verify_tooling_pin(root: &Path) -> Result<(), ValidationError> {
    let head = command_text(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"]),
        "read trusted validator HEAD",
    )?;
    if head.trim() != TRUSTED_VALIDATOR_REVISION {
        return Err(ValidationError::new(
            "validator-revision-mismatch",
            "trusted validator checkout HEAD does not match compiled revision",
        ));
    }
    for (path, expected) in [
        (
            "contracts/governance-ledger-fast-path.yaml",
            TRUSTED_CONTRACT_BLOB,
        ),
        ("bin/ws-ledger-mutate", TRUSTED_MUTATOR_BLOB),
    ] {
        let selector = format!("HEAD:{path}");
        let observed = command_text(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(["rev-parse", &selector]),
            "verify trusted Governance tooling blob",
        )?;
        if observed.trim() != expected {
            return Err(ValidationError::new(
                "validator-revision-mismatch",
                format!("trusted tooling blob {path} does not match compiled pin"),
            ));
        }
    }
    Ok(())
}

fn parse_changes(values: &[Json]) -> Result<Vec<LedgerChange>, ValidationError> {
    let mut changes = Vec::with_capacity(values.len());
    let mut paths = BTreeSet::new();
    let mut previous = None::<String>;
    for value in values {
        let object = value.as_object().ok_or_else(|| {
            ValidationError::new("validator-output-invalid", "change entry is not an object")
        })?;
        let path = object_string(object, "path")
            .ok_or_else(|| ValidationError::new("validator-output-invalid", "change path missing"))?
            .to_owned();
        validate_change_path(&path)?;
        if !paths.insert(path.clone()) {
            return Err(ValidationError::new(
                "result-conflict",
                "validator returned duplicate changed path",
            ));
        }
        if previous.as_ref().is_some_and(|value| value >= &path) {
            return Err(ValidationError::new(
                "validator-output-invalid",
                "trusted validator changes are not strictly sorted by path",
            ));
        }
        previous = Some(path.clone());
        let operation = object_string(object, "operation").ok_or_else(|| {
            ValidationError::new("validator-output-invalid", "change operation missing")
        })?;
        let content = object_get(object, "content");
        let blob = object_get(object, "blob_sha");
        let change = match operation {
            "upsert" => {
                let content = content.and_then(Json::as_str).ok_or_else(|| {
                    ValidationError::new(
                        "validator-output-invalid",
                        "upsert change must carry UTF-8 content",
                    )
                })?;
                let blob_sha = blob.and_then(Json::as_str).ok_or_else(|| {
                    ValidationError::new(
                        "validator-output-invalid",
                        "upsert change must carry a blob SHA",
                    )
                })?;
                if !sha40(blob_sha) || git_blob_sha(content.as_bytes()) != blob_sha {
                    return Err(ValidationError::new(
                        "validator-output-invalid",
                        "upsert blob identity does not bind the complete content",
                    ));
                }
                LedgerChange {
                    path,
                    operation: ChangeOperation::Upsert,
                    content: Some(content.to_owned()),
                    blob_sha: Some(blob_sha.to_owned()),
                }
            }
            "delete" => {
                if !matches!(content, Some(Json::Null)) || !matches!(blob, Some(Json::Null)) {
                    return Err(ValidationError::new(
                        "validator-output-invalid",
                        "delete change must carry null content/blob identity",
                    ));
                }
                LedgerChange {
                    path,
                    operation: ChangeOperation::Delete,
                    content: None,
                    blob_sha: None,
                }
            }
            _ => {
                return Err(ValidationError::new(
                    "validator-output-invalid",
                    "validator returned unsupported change operation",
                ));
            }
        };
        changes.push(change);
    }
    Ok(changes)
}

pub(super) fn enforce_result_limits(changes: &[LedgerChange]) -> Result<(), ValidationError> {
    if changes.len() > MAX_CHANGED_FILES {
        return Err(ValidationError::new(
            "result-too-large",
            format!(
                "result changes {} files; maximum is {MAX_CHANGED_FILES}",
                changes.len()
            ),
        ));
    }
    let total = changes
        .iter()
        .filter_map(|change| change.content.as_ref())
        .map(|content| content.len())
        .sum::<usize>();
    if total > MAX_TOTAL_RESULT_UTF8_BYTES {
        return Err(ValidationError::new(
            "result-too-large",
            format!("result UTF-8 bytes {total}; maximum is {MAX_TOTAL_RESULT_UTF8_BYTES}"),
        ));
    }
    Ok(())
}

pub(super) fn materialize_and_verify_result(
    root: &Path,
    changes: &[LedgerChange],
) -> Result<String, ValidationError> {
    let mut expected_paths = Vec::with_capacity(changes.len());
    for change in changes {
        validate_change_path(&change.path)?;
        let path = root.join(&change.path);
        match (&change.operation, &change.content) {
            (ChangeOperation::Upsert, Some(content)) => {
                secure_candidate_upsert(root, &path, content.as_bytes())?;
            }
            (ChangeOperation::Delete, None) => {
                secure_candidate_delete(root, &path)?;
            }
            _ => {
                return Err(ValidationError::new(
                    "validator-output-invalid",
                    "change operation/content pair is incoherent",
                ));
            }
        }
        expected_paths.push(change.path.clone());
    }

    if !expected_paths.is_empty() {
        let mut command = Command::new("git");
        command.arg("-C").arg(root).args(["add", "-A", "--"]);
        for path in &expected_paths {
            command.arg(path);
        }
        command_success(&mut command, "stage exact validated Governance changes")?;
    }
    let staged = command_bytes(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["diff", "--cached", "--name-only", "-z"]),
        "read exact staged Governance paths",
    )?;
    let mut staged_paths = staged
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
        .map(|value| {
            String::from_utf8(value.to_vec()).map_err(|_| {
                ValidationError::new(
                    "validator-output-invalid",
                    "staged Governance path is not UTF-8",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    staged_paths.sort();
    if staged_paths != expected_paths {
        return Err(ValidationError::new(
            "validator-output-invalid",
            "materialized Git candidate changed paths outside the trusted result set",
        ));
    }

    for change in changes {
        match change.operation {
            ChangeOperation::Upsert => {
                let output = command_text(
                    Command::new("git")
                        .arg("-C")
                        .arg(root)
                        .args(["ls-files", "-s", "--"])
                        .arg(&change.path),
                    "read staged Governance blob identity",
                )?;
                let observed = output.split_whitespace().nth(1).ok_or_else(|| {
                    ValidationError::new(
                        "validator-output-invalid",
                        "staged upsert lacks Git blob identity",
                    )
                })?;
                if change.blob_sha.as_deref() != Some(observed) {
                    return Err(ValidationError::new(
                        "validator-output-invalid",
                        "staged Git blob differs from trusted complete change content",
                    ));
                }
            }
            ChangeOperation::Delete => {
                let output = command_text(
                    Command::new("git")
                        .arg("-C")
                        .arg(root)
                        .args(["ls-files", "-s", "--"])
                        .arg(&change.path),
                    "verify staged Governance deletion",
                )?;
                if !output.trim().is_empty() {
                    return Err(ValidationError::new(
                        "validator-output-invalid",
                        "staged deletion still has a Git index entry",
                    ));
                }
            }
        }
    }

    let tree = command_text(
        Command::new("git").arg("-C").arg(root).arg("write-tree"),
        "derive exact validated Governance result tree",
    )?;
    let tree = tree.trim().to_owned();
    if !sha40(&tree) {
        return Err(ValidationError::new(
            "validator-output-invalid",
            "Git write-tree returned an invalid tree identity",
        ));
    }
    Ok(tree)
}

#[cfg(target_os = "linux")]
fn secure_candidate_upsert(
    root: &Path,
    path: &Path,
    content: &[u8],
) -> Result<(), ValidationError> {
    secure_linux::with_candidate_parent(root, path, true, |parent_fd, leaf| {
        secure_linux::write_leaf_no_follow(parent_fd, leaf, content)
    })
}

#[cfg(not(target_os = "linux"))]
fn secure_candidate_upsert(
    _root: &Path,
    _path: &Path,
    _content: &[u8],
) -> Result<(), ValidationError> {
    Err(ValidationError::new(
        "validator-io",
        "secure candidate materialization is unavailable on this platform",
    ))
}

#[cfg(target_os = "linux")]
fn secure_candidate_delete(root: &Path, path: &Path) -> Result<(), ValidationError> {
    secure_linux::with_candidate_parent(root, path, false, |parent_fd, leaf| {
        secure_linux::delete_leaf_no_follow(parent_fd, leaf)
    })
}

#[cfg(not(target_os = "linux"))]
fn secure_candidate_delete(_root: &Path, _path: &Path) -> Result<(), ValidationError> {
    Err(ValidationError::new(
        "validator-io",
        "secure candidate materialization is unavailable on this platform",
    ))
}

#[cfg(target_os = "linux")]
mod secure_linux {
    use super::ValidationError;
    use std::ffi::{CString, OsStr, c_char, c_int};
    use std::fs::{File, OpenOptions};
    use std::io::{ErrorKind, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Component, Path};

    const O_RDONLY: c_int = 0;
    const O_WRONLY: c_int = 1;
    const O_CREAT: c_int = 0o100;
    const O_TRUNC: c_int = 0o1000;
    const O_CLOEXEC: c_int = 0o2000000;
    const O_DIRECTORY: c_int = 0o200000;
    const O_NOFOLLOW: c_int = 0o400000;

    unsafe extern "C" {
        fn openat(dirfd: c_int, pathname: *const c_char, flags: c_int, ...) -> c_int;
        fn mkdirat(dirfd: c_int, pathname: *const c_char, mode: u32) -> c_int;
        fn unlinkat(dirfd: c_int, pathname: *const c_char, flags: c_int) -> c_int;
    }

    pub(super) fn with_candidate_parent<T>(
        root: &Path,
        path: &Path,
        create_parents: bool,
        operation: impl FnOnce(c_int, &OsStr) -> Result<T, ValidationError>,
    ) -> Result<T, ValidationError> {
        let relative = path.strip_prefix(root).map_err(|_| {
            ValidationError::new(
                "result-conflict",
                "candidate path escaped materialized root",
            )
        })?;
        let components = relative
            .components()
            .map(|component| match component {
                Component::Normal(value) => Ok(value),
                _ => Err(ValidationError::new(
                    "result-conflict",
                    "candidate path contains a non-normal component",
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (leaf, parents) = components.split_last().ok_or_else(|| {
            ValidationError::new("result-conflict", "candidate path has no leaf component")
        })?;

        let root_file = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            .open(root)
            .map_err(|error| candidate_io("open materialized candidate root", error))?;
        let mut current_fd = root_file.as_raw_fd();
        let mut opened = Vec::<OwnedFd>::with_capacity(parents.len());
        for component in parents {
            let name = c_name(component)?;
            let next = match open_dir_at(current_fd, &name) {
                Ok(value) => value,
                Err(error) if error.kind() == ErrorKind::NotFound && create_parents => {
                    create_dir_at(current_fd, &name)?;
                    open_dir_at(current_fd, &name).map_err(|error| {
                        candidate_io("open newly created candidate directory", error)
                    })?
                }
                Err(error) => {
                    return Err(candidate_io(
                        "open candidate ancestor without following symbolic links",
                        error,
                    ));
                }
            };
            opened.push(next);
            current_fd = opened
                .last()
                .expect("candidate ancestor descriptor was just pushed")
                .as_raw_fd();
        }
        operation(current_fd, leaf)
    }

    pub(super) fn write_leaf_no_follow(
        parent_fd: c_int,
        leaf: &OsStr,
        content: &[u8],
    ) -> Result<(), ValidationError> {
        let name = c_name(leaf)?;
        // SAFETY: parent_fd is held open by with_candidate_parent, name is NUL-terminated,
        // and the flags force the kernel to reject a symbolic-link leaf.
        let fd = unsafe {
            openat(
                parent_fd,
                name.as_ptr(),
                O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                0o666_u32,
            )
        };
        if fd < 0 {
            return Err(candidate_io(
                "open candidate leaf without following symbolic links",
                std::io::Error::last_os_error(),
            ));
        }
        // SAFETY: openat returned a new owned descriptor on success.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut file = File::from(owned);
        file.write_all(content)
            .map_err(|error| candidate_io("write candidate leaf", error))
    }

    pub(super) fn delete_leaf_no_follow(
        parent_fd: c_int,
        leaf: &OsStr,
    ) -> Result<(), ValidationError> {
        let name = c_name(leaf)?;
        // Probe with O_NOFOLLOW first. A symbolic-link leaf fails here rather than being deleted
        // as if it were a normal candidate file.
        // SAFETY: parent_fd is live and name is NUL-terminated.
        let fd = unsafe { openat(parent_fd, name.as_ptr(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == ErrorKind::NotFound {
                return Ok(());
            }
            return Err(candidate_io(
                "inspect candidate deletion leaf without following symbolic links",
                error,
            ));
        }
        // SAFETY: openat returned a new owned descriptor on success. Holding it closes the
        // check/unlink replacement window for the underlying inode; unlinkat remains parent-fd relative.
        let _leaf_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: parent_fd remains live and unlinkat with flags=0 never follows a leaf symlink.
        if unsafe { unlinkat(parent_fd, name.as_ptr(), 0) } != 0 {
            return Err(candidate_io(
                "delete candidate leaf without path traversal",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    fn open_dir_at(parent_fd: c_int, name: &CString) -> std::io::Result<OwnedFd> {
        // SAFETY: parent_fd is live and name is NUL-terminated. O_DIRECTORY|O_NOFOLLOW rejects
        // both non-directories and symbolic-link ancestors atomically in the kernel.
        let fd = unsafe {
            openat(
                parent_fd,
                name.as_ptr(),
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            // SAFETY: openat returned a new owned descriptor on success.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    fn create_dir_at(parent_fd: c_int, name: &CString) -> Result<(), ValidationError> {
        // SAFETY: parent_fd is live and name is NUL-terminated. mkdirat is relative to the held
        // descriptor and cannot traverse a replacement path prefix.
        if unsafe { mkdirat(parent_fd, name.as_ptr(), 0o777_u32) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == ErrorKind::AlreadyExists {
            Ok(())
        } else {
            Err(candidate_io("create candidate directory", error))
        }
    }

    fn c_name(name: &OsStr) -> Result<CString, ValidationError> {
        CString::new(name.as_bytes()).map_err(|_| {
            ValidationError::new("result-conflict", "candidate path component contains NUL")
        })
    }

    fn candidate_io(action: &str, error: std::io::Error) -> ValidationError {
        ValidationError::new("result-conflict", format!("could not {action}: {error}"))
    }
}

fn validate_change_path(path: &str) -> Result<(), ValidationError> {
    if path.is_empty()
        || path.starts_with('/')
        || Path::new(path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || !(path.starts_with("tasks/")
            || path.starts_with("runs/")
            || path.starts_with("indexes/"))
    {
        return Err(ValidationError::new(
            "strict-path",
            format!("unsafe or unsupported fast-path result path {path}"),
        ));
    }
    Ok(())
}

fn git_blob_sha(content: &[u8]) -> String {
    let mut material = format!("blob {}\0", content.len()).into_bytes();
    material.extend_from_slice(content);
    sha1_hex(&material)
}

fn sha1_hex(input: &[u8]) -> String {
    let mut h = [
        0x67452301_u32,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in message.as_chunks::<64>().0 {
        let mut words = [0_u32; 80];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        for (index, word) in words.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    h.iter().map(|value| format!("{value:08x}")).collect()
}

fn parse_rejected_code(stderr: &str) -> Option<&str> {
    stderr
        .lines()
        .find_map(|line| line.strip_prefix("REJECTED "))
        .and_then(|rest| rest.split(':').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn command_success(command: &mut Command, label: &str) -> Result<(), ValidationError> {
    let output = run_command(command, label)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(ValidationError::new(
            "trusted-validator-unavailable",
            format!("fixed internal command failed while trying to {label}"),
        ))
    }
}

fn command_text(command: &mut Command, label: &str) -> Result<String, ValidationError> {
    let bytes = command_bytes(command, label)?;
    String::from_utf8(bytes).map_err(|_| {
        ValidationError::new(
            "validator-output-invalid",
            format!("fixed internal command for {label} returned non-UTF-8 output"),
        )
    })
}

fn command_bytes(command: &mut Command, label: &str) -> Result<Vec<u8>, ValidationError> {
    let output = run_command(command, label)?;
    if !output.status.success() {
        return Err(ValidationError::new(
            "trusted-validator-unavailable",
            format!("fixed internal command failed while trying to {label}"),
        ));
    }
    Ok(output.stdout)
}

fn run_command(command: &mut Command, label: &str) -> Result<Output, ValidationError> {
    command.output().map_err(|error| {
        ValidationError::new(
            "trusted-validator-unavailable",
            format!("could not execute fixed internal command for {label}: {error}"),
        )
    })
}

fn sha40(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

struct TempDirectory {
    path: PathBuf,
}

impl TempDirectory {
    fn new(prefix: &str) -> Result<Self, ValidationError> {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{id}", std::process::id()));
        fs::create_dir(&path).map_err(|error| {
            ValidationError::new(
                "validator-io",
                format!("could not create validation workspace: {error}"),
            )
        })?;
        Ok(Self { path })
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::super::json::{jcs, sha256_hex};
    use super::*;

    fn run(command: &mut Command) {
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn init_repo(repo: &TempDirectory) {
        run(Command::new("git")
            .arg("init")
            .arg("--quiet")
            .arg(&repo.path));
        run(Command::new("git").arg("-C").arg(&repo.path).args([
            "config",
            "user.name",
            "Zach Test",
        ]));
        run(Command::new("git").arg("-C").arg(&repo.path).args([
            "config",
            "user.email",
            "zach-test@example.invalid",
        ]));
    }

    #[test]
    fn deterministic_tree_derivation_matches_native_git() {
        let repo = TempDirectory::new("zach-tree-test").unwrap();
        init_repo(&repo);
        fs::create_dir_all(repo.path.join("tasks")).unwrap();
        fs::write(repo.path.join("tasks/A.md"), "before\n").unwrap();
        run(Command::new("git")
            .arg("-C")
            .arg(&repo.path)
            .args(["add", "."]));
        run(Command::new("git")
            .arg("-C")
            .arg(&repo.path)
            .args(["commit", "--quiet", "-m", "base"]));
        let content = "after\n";
        let changes = vec![LedgerChange {
            path: "tasks/A.md".into(),
            operation: ChangeOperation::Upsert,
            content: Some(content.into()),
            blob_sha: Some(git_blob_sha(content.as_bytes())),
        }];
        let first = materialize_and_verify_result(&repo.path, &changes).unwrap();
        let second = command_text(
            Command::new("git")
                .arg("-C")
                .arg(&repo.path)
                .arg("write-tree"),
            "derive test tree",
        )
        .unwrap();
        assert_eq!(first, second.trim());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn leaf_symlink_upsert_fails_closed_without_changing_external_target() {
        use std::os::unix::fs::symlink;

        let repo = TempDirectory::new("zach-leaf-symlink-test").unwrap();
        init_repo(&repo);
        fs::create_dir_all(repo.path.join("tasks")).unwrap();
        fs::write(repo.path.join("tasks/base.md"), "base\n").unwrap();
        run(Command::new("git")
            .arg("-C")
            .arg(&repo.path)
            .args(["add", "."]));
        run(Command::new("git")
            .arg("-C")
            .arg(&repo.path)
            .args(["commit", "--quiet", "-m", "base"]));

        let external = TempDirectory::new("zach-external-leaf").unwrap();
        let external_file = external.path.join("outside.md");
        let original = b"outside stays byte-identical\n";
        fs::write(&external_file, original).unwrap();
        symlink(&external_file, repo.path.join("tasks/escape.md")).unwrap();

        let replacement = "attacker-controlled overwrite\n";
        let changes = vec![LedgerChange {
            path: "tasks/escape.md".into(),
            operation: ChangeOperation::Upsert,
            content: Some(replacement.into()),
            blob_sha: Some(git_blob_sha(replacement.as_bytes())),
        }];
        assert!(materialize_and_verify_result(&repo.path, &changes).is_err());
        assert_eq!(fs::read(&external_file).unwrap(), original);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ancestor_symlink_upsert_fails_closed_without_changing_external_target() {
        use std::os::unix::fs::symlink;

        let repo = TempDirectory::new("zach-ancestor-symlink-test").unwrap();
        init_repo(&repo);
        fs::write(repo.path.join("README.md"), "base\n").unwrap();
        run(Command::new("git")
            .arg("-C")
            .arg(&repo.path)
            .args(["add", "."]));
        run(Command::new("git")
            .arg("-C")
            .arg(&repo.path)
            .args(["commit", "--quiet", "-m", "base"]));

        let external = TempDirectory::new("zach-external-ancestor").unwrap();
        let external_file = external.path.join("outside.md");
        let original = b"ancestor target stays unchanged\n";
        fs::write(&external_file, original).unwrap();
        symlink(&external.path, repo.path.join("tasks")).unwrap();

        let replacement = "attacker-controlled overwrite\n";
        let changes = vec![LedgerChange {
            path: "tasks/outside.md".into(),
            operation: ChangeOperation::Upsert,
            content: Some(replacement.into()),
            blob_sha: Some(git_blob_sha(replacement.as_bytes())),
        }];
        assert!(materialize_and_verify_result(&repo.path, &changes).is_err());
        assert_eq!(fs::read(&external_file).unwrap(), original);
    }

    #[test]
    fn changed_files_must_be_sorted() {
        let first = LedgerChange {
            path: "tasks/B.md".into(),
            operation: ChangeOperation::Delete,
            content: None,
            blob_sha: None,
        };
        let second = LedgerChange {
            path: "tasks/A.md".into(),
            operation: ChangeOperation::Delete,
            content: None,
            blob_sha: None,
        };
        let raw = Json::Array(vec![change_json(&first), change_json(&second)]);
        assert!(parse_changes(raw.as_array().unwrap()).is_err());
    }

    #[test]
    fn result_boundaries_reject_only_above_limits() {
        let exact = vec![LedgerChange {
            path: "tasks/A.md".into(),
            operation: ChangeOperation::Upsert,
            content: Some("x".repeat(MAX_TOTAL_RESULT_UTF8_BYTES)),
            blob_sha: None,
        }];
        assert!(enforce_result_limits(&exact).is_ok());
        let over = vec![LedgerChange {
            content: Some("x".repeat(MAX_TOTAL_RESULT_UTF8_BYTES + 1)),
            ..exact[0].clone()
        }];
        assert_eq!(
            enforce_result_limits(&over).unwrap_err().code,
            "result-too-large"
        );
        let eight = (0..MAX_CHANGED_FILES)
            .map(|index| LedgerChange {
                path: format!("tasks/{index}.md"),
                operation: ChangeOperation::Delete,
                content: None,
                blob_sha: None,
            })
            .collect::<Vec<_>>();
        assert!(enforce_result_limits(&eight).is_ok());
        let nine = (0..=MAX_CHANGED_FILES)
            .map(|index| LedgerChange {
                path: format!("tasks/{index}.md"),
                operation: ChangeOperation::Delete,
                content: None,
                blob_sha: None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            enforce_result_limits(&nine).unwrap_err().code,
            "result-too-large"
        );
    }

    fn change_json(change: &LedgerChange) -> Json {
        Json::Object(vec![
            ("path".into(), Json::String(change.path.clone())),
            (
                "operation".into(),
                Json::String(match change.operation {
                    ChangeOperation::Upsert => "upsert".into(),
                    ChangeOperation::Delete => "delete".into(),
                }),
            ),
            (
                "content".into(),
                change
                    .content
                    .clone()
                    .map(Json::String)
                    .unwrap_or(Json::Null),
            ),
            (
                "blob_sha".into(),
                change
                    .blob_sha
                    .clone()
                    .map(Json::String)
                    .unwrap_or(Json::Null),
            ),
        ])
    }

    #[test]
    fn validator_revision_is_compiled_trusted_configuration() {
        let request_data = Json::Object(vec![(
            "validator_revision".into(),
            Json::String("ffffffffffffffffffffffffffffffffffffffff".into()),
        )]);
        let canonical = jcs(&request_data).unwrap();
        assert!(canonical.contains("ffffffff"));
        assert_eq!(TRUSTED_VALIDATOR_REVISION, TRUSTED_CONTRACT_REVISION);
        assert_ne!(
            TRUSTED_VALIDATOR_REVISION,
            "ffffffffffffffffffffffffffffffffffffffff"
        );
        assert_eq!(sha256_hex(canonical.as_bytes()).len(), 64);
    }
}
