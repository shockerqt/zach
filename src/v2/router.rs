use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

pub const NO_CROSS_FAMILY_REVIEWER_ERR: &str = "NO_CROSS_FAMILY_REVIEWER";

pub fn is_no_cross_family_reviewer_error(err: &str) -> bool {
    err.contains(NO_CROSS_FAMILY_REVIEWER_ERR)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelFamily {
    OpenAiSol,
    GeminiAgy,
}

impl ModelFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OpenAiSol => "openai-sol",
            Self::GeminiAgy => "gemini-agy",
        }
    }

    pub fn opposite(&self) -> Self {
        match self {
            Self::OpenAiSol => Self::GeminiAgy,
            Self::GeminiAgy => Self::OpenAiSol,
        }
    }
}

/// Infers the [`ModelFamily`] from a model name string.
pub fn infer_model_family(model: &str) -> ModelFamily {
    let lower = model.trim().to_ascii_lowercase();
    if lower.starts_with("gpt-")
        || lower.starts_with("o1")
        || lower.starts_with("o3")
        || lower.starts_with("o4")
        || lower.contains("openai")
        || lower.contains("codex")
        || lower.contains("sol")
        || lower.contains("astra")
    {
        ModelFamily::OpenAiSol
    } else {
        ModelFamily::GeminiAgy
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReasoningEffort {
    #[serde(alias = "Low")]
    Low,
    #[serde(alias = "Medium")]
    Medium,
    #[serde(alias = "High")]
    High,
}

impl ReasoningEffort {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub fn escalate(&self) -> Self {
        match self {
            Self::Low => Self::Medium,
            Self::Medium => Self::High,
            Self::High => Self::High,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageRoute {
    pub weight: String,
    pub stage: String,
    pub family: ModelFamily,
    pub model: String,
    pub effort: ReasoningEffort,
    pub fallback_family: Option<ModelFamily>,
    pub fallback_model: Option<String>,
    pub fallback_effort: Option<ReasoningEffort>,
    pub max_task_tokens: u64,
    pub timeout_secs: u64,
    pub stall_timeout_secs: u64,
}

pub const DEFAULT_STALL_TIMEOUT_SECS: u64 = 600;

/// Returns `true` if `model` refers to `gpt-6-astra`.
/// Kept for diagnostics; no longer blocks autonomous daemon runs.
pub fn is_forbidden_daemon_model(_model: &str) -> bool {
    false
}

/// Validates that a model identifier is non-empty.
pub fn validate_daemon_model(model: &str) -> Result<(), String> {
    if model.trim().is_empty() {
        return Err("model identifier cannot be empty".to_owned());
    }
    Ok(())
}

pub fn max_task_tokens_for_weight(weight: &str) -> u64 {
    match weight.trim().to_ascii_uppercase().as_str() {
        "XS" => 150_000,
        "S" => 400_000,
        "M" => 1_200_000,
        "L" => 2_500_000,
        _ => 400_000,
    }
}

pub fn stage_timeout_secs(weight: &str, stage: &str) -> u64 {
    let w = weight.trim().to_ascii_uppercase();
    match stage.trim().to_ascii_lowercase().as_str() {
        "plan" => 1_200,
        "plan-review" => 600,
        "impl" => match w.as_str() {
            "XS" | "S" => 1_800,
            _ => 3_600,
        },
        "pr-review" => 900,
        _ => 1_800,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouterEnvOverrides {
    pub flash_only: bool,
    pub forced_model: Option<String>,
}

impl RouterEnvOverrides {
    pub fn from_env() -> Self {
        let is_enabled = |name: &str| {
            std::env::var(name)
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
        };
        let flash_only = is_enabled("ZACH_USE_FLASH_ONLY") || is_enabled("ZACH_USE_HYDROGEN_ONLY");
        let forced_model = std::env::var("ZACH_FORCE_MODEL").ok();
        Self {
            flash_only,
            forced_model,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteEndpoint {
    pub model: String,
    pub effort: ReasoningEffort,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RouteEndpointOverride {
    pub model: Option<String>,
    pub effort: Option<ReasoningEffort>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CrossFamilyAltOverride {
    pub model: Option<String>,
    pub effort: Option<ReasoningEffort>,
    pub retry_model: Option<String>,
    pub retry_effort: Option<ReasoningEffort>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StageOverride {
    pub model: Option<String>,
    pub effort: Option<ReasoningEffort>,
    pub retry_model: Option<String>,
    pub retry_effort: Option<ReasoningEffort>,
    pub fallback_model: Option<String>,
    pub fallback_effort: Option<ReasoningEffort>,
    pub retry_fallback_model: Option<String>,
    pub retry_fallback_effort: Option<ReasoningEffort>,
    pub cross_family_alt: Option<CrossFamilyAltOverride>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RouterConfig {
    pub routes: BTreeMap<String, BTreeMap<String, StageOverride>>,
    pub flash_only: RouteEndpoint,
    pub agy_infra_fallback: RouteEndpoint,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterConfig {
    routes: BTreeMap<String, BTreeMap<String, StageOverride>>,
    flash_only: RouteEndpoint,
    agy_infra_fallback: RouteEndpoint,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouterConfigOverlay {
    #[serde(default)]
    routes: Option<BTreeMap<String, BTreeMap<String, StageOverride>>>,
    #[serde(default)]
    flash_only: Option<RouteEndpointOverride>,
    #[serde(default)]
    agy_infra_fallback: Option<RouteEndpointOverride>,
}

pub const DEFAULT_ROUTER_CONFIG_JSON: &str = include_str!("../../config/router.json");

pub fn default_router_config_json() -> &'static str {
    DEFAULT_ROUTER_CONFIG_JSON
}

static BASE_ROUTER_CONFIG: OnceLock<RouterConfig> = OnceLock::new();

fn base_router_config() -> &'static RouterConfig {
    BASE_ROUTER_CONFIG.get_or_init(|| {
        let raw: RawRouterConfig = serde_json::from_str(DEFAULT_ROUTER_CONFIG_JSON)
            .expect("embedded config/router.json must be valid JSON");
        RouterConfig {
            routes: raw.routes,
            flash_only: raw.flash_only,
            agy_infra_fallback: raw.agy_infra_fallback,
        }
    })
}

impl Default for RouterConfig {
    fn default() -> Self {
        base_router_config().clone()
    }
}

fn merge_endpoint(base: &mut RouteEndpoint, ov: RouteEndpointOverride) {
    if let Some(m) = ov.model {
        base.model = m;
    }
    if let Some(eff) = ov.effort {
        base.effort = eff;
    }
}

fn merge_cross_family_alt(base: &mut CrossFamilyAltOverride, ov: CrossFamilyAltOverride) {
    if ov.model.is_some() {
        base.model = ov.model;
    }
    if ov.effort.is_some() {
        base.effort = ov.effort;
    }
    if ov.retry_model.is_some() {
        base.retry_model = ov.retry_model;
    }
    if ov.retry_effort.is_some() {
        base.retry_effort = ov.retry_effort;
    }
}

fn merge_stage_override(base: &mut StageOverride, ov: StageOverride) {
    if ov.model.is_some() {
        base.model = ov.model;
    }
    if ov.effort.is_some() {
        base.effort = ov.effort;
    }
    if ov.retry_model.is_some() {
        base.retry_model = ov.retry_model;
    }
    if ov.retry_effort.is_some() {
        base.retry_effort = ov.retry_effort;
    }
    if ov.fallback_model.is_some() {
        base.fallback_model = ov.fallback_model;
    }
    if ov.fallback_effort.is_some() {
        base.fallback_effort = ov.fallback_effort;
    }
    if ov.retry_fallback_model.is_some() {
        base.retry_fallback_model = ov.retry_fallback_model;
    }
    if ov.retry_fallback_effort.is_some() {
        base.retry_fallback_effort = ov.retry_fallback_effort;
    }
    if let Some(alt) = ov.cross_family_alt {
        let target = base
            .cross_family_alt
            .get_or_insert_with(CrossFamilyAltOverride::default);
        merge_cross_family_alt(target, alt);
    }
}

impl<'de> Deserialize<'de> for RouterConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let overlay = RouterConfigOverlay::deserialize(deserializer)?;
        let mut cfg = RouterConfig::default();
        if let Some(flash_ov) = overlay.flash_only {
            merge_endpoint(&mut cfg.flash_only, flash_ov);
        }
        if let Some(agy_ov) = overlay.agy_infra_fallback {
            merge_endpoint(&mut cfg.agy_infra_fallback, agy_ov);
        }
        if let Some(routes_ov) = overlay.routes {
            for (w_key, stage_map) in routes_ov {
                let existing_weight_key = cfg
                    .routes
                    .keys()
                    .find(|k| k.trim().eq_ignore_ascii_case(w_key.trim()))
                    .cloned();
                let target_weight_key = existing_weight_key.unwrap_or(w_key);
                let base_stages = cfg.routes.entry(target_weight_key).or_default();
                for (s_key, stage_ov) in stage_map {
                    let existing_stage_key = base_stages
                        .keys()
                        .find(|k| k.trim().eq_ignore_ascii_case(s_key.trim()))
                        .cloned();
                    if let Some(k) = existing_stage_key {
                        if let Some(base_stage) = base_stages.get_mut(&k) {
                            merge_stage_override(base_stage, stage_ov);
                        }
                    } else {
                        base_stages.insert(s_key, stage_ov);
                    }
                }
            }
        }
        Ok(cfg)
    }
}

static ACTIVE_ROUTER_CONFIG: OnceLock<RwLock<RouterConfig>> = OnceLock::new();

pub fn default_router_config_path() -> PathBuf {
    if let Ok(raw) = std::env::var("ZACH_ROUTER_CONFIG") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let trimmed = xdg.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed).join("zach").join("router.json");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
    PathBuf::from(home)
        .join(".config")
        .join("zach")
        .join("router.json")
}

fn active_router_config_lock() -> &'static RwLock<RouterConfig> {
    ACTIVE_ROUTER_CONFIG.get_or_init(|| {
        let path = default_router_config_path();
        let initial = if path.exists() {
            match load_router_config_from_path(&path) {
                Ok((cfg, warnings)) => {
                    for w in warnings {
                        eprintln!("warning: {w}");
                    }
                    cfg
                }
                Err(err) => {
                    eprintln!(
                        "warning: failed to load router config at {}: {err}; using built-in defaults",
                        path.display()
                    );
                    RouterConfig::default()
                }
            }
        } else {
            RouterConfig::default()
        };
        RwLock::new(initial)
    })
}

pub fn active_router_config() -> RouterConfig {
    active_router_config_lock()
        .read()
        .map(|g| g.clone())
        .unwrap_or_default()
}

pub fn load_router_config_from_path(path: &Path) -> Result<(RouterConfig, Vec<String>), String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let cfg: RouterConfig = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid router config JSON in {}: {e}", path.display()))?;
    let warnings = validate_router_config(&cfg)?;
    Ok((cfg, warnings))
}

/// Validates a [`RouterConfig`] and returns non-blocking warnings (e.g. same-family review).
pub fn validate_router_config(cfg: &RouterConfig) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();
    for (field, model) in [
        ("flash_only.model", cfg.flash_only.model.as_str()),
        (
            "agy_infra_fallback.model",
            cfg.agy_infra_fallback.model.as_str(),
        ),
    ] {
        if model.trim().is_empty() {
            return Err(format!("empty {field} in router config"));
        }
        validate_daemon_model(model)?;
    }

    for (weight, stages) in &cfg.routes {
        let norm_weight = weight.trim().to_ascii_uppercase();
        if !matches!(norm_weight.as_str(), "XS" | "S" | "M" | "L") {
            return Err(format!("unsupported weight '{weight}' in router config"));
        }
        for (stage, ov) in stages {
            let norm_stage = stage.trim().to_ascii_lowercase();
            if !matches!(
                norm_stage.as_str(),
                "plan" | "plan-review" | "impl" | "pr-review"
            ) {
                return Err(format!(
                    "unsupported stage '{stage}' for weight '{weight}' in router config"
                ));
            }
            if resolve_stage_route_with_config(
                &norm_weight,
                &norm_stage,
                0,
                None,
                &RouterEnvOverrides::default(),
                cfg,
            )?
            .is_none()
            {
                return Err(format!(
                    "stage '{stage}' is not applicable to weight '{weight}' in router config"
                ));
            }
            for (field, val) in [
                ("model", ov.model.as_deref()),
                ("retry_model", ov.retry_model.as_deref()),
                ("fallback_model", ov.fallback_model.as_deref()),
                ("retry_fallback_model", ov.retry_fallback_model.as_deref()),
            ] {
                if let Some(m) = val {
                    if m.trim().is_empty() {
                        return Err(format!(
                            "empty {field} for {weight}.{stage} in router config"
                        ));
                    }
                    validate_daemon_model(m)?;
                }
            }
            let is_review_stage = matches!(norm_stage.as_str(), "plan-review" | "pr-review");
            if let Some(alt) = ov.cross_family_alt.as_ref() {
                if !is_review_stage {
                    return Err(format!(
                        "cross_family_alt is only valid for review stages, not {weight}.{stage}"
                    ));
                }
                for (field, val) in [
                    ("cross_family_alt.model", alt.model.as_deref()),
                    ("cross_family_alt.retry_model", alt.retry_model.as_deref()),
                ] {
                    if let Some(m) = val {
                        if m.trim().is_empty() {
                            return Err(format!(
                                "empty {field} for {weight}.{stage} in router config"
                            ));
                        }
                        validate_daemon_model(m)?;
                    }
                }
            } else if is_review_stage {
                return Err(format!(
                    "missing cross_family_alt for review stage {weight}.{stage} in router config"
                ));
            }
        }
    }

    // Emit non-blocking cross-family suggestions for review stages.
    let no_env = RouterEnvOverrides::default();
    for weight in ["S", "M", "L"] {
        let author_stage = if weight == "S" { "impl" } else { "plan" };
        let author_family =
            resolve_stage_route_with_config(weight, author_stage, 0, None, &no_env, cfg)?
                .map(|r| r.family)
                .unwrap_or(ModelFamily::OpenAiSol);
        for review_stage in ["plan-review", "pr-review"] {
            if let Some(rev) = resolve_stage_route_with_config(
                weight,
                review_stage,
                0,
                Some(author_family),
                &no_env,
                cfg,
            )? && rev.family == author_family
            {
                warnings.push(format!(
                    "suggestion: {weight}.{review_stage} uses {} ({}) which is the same family as {weight}.{author_stage} ({}); cross-family review is recommended",
                    rev.model,
                    rev.family.as_str(),
                    author_family.as_str()
                ));
            }
        }
    }

    Ok(warnings)
}

/// Writes the canonical `config/router.json` to `path` (or `default_router_config_path()`).
/// Refuses to overwrite an existing file unless `force` is `true`.
pub fn init_router_config(path: Option<&Path>, force: bool) -> Result<PathBuf, String> {
    let target = path
        .map(PathBuf::from)
        .unwrap_or_else(default_router_config_path);
    if target.exists() && !force {
        return Err(format!(
            "router config already exists at {} (pass --force to overwrite)",
            target.display()
        ));
    }
    if let Some(parent) = target.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create directory {}: {e}", parent.display()))?;
    }
    std::fs::write(&target, DEFAULT_ROUTER_CONFIG_JSON)
        .map_err(|e| format!("failed to write {}: {e}", target.display()))?;
    Ok(target)
}

/// Validates and hot-reloads the active router config from `path` (or default path).
/// If validation fails, the previous active config is preserved.
pub fn reload_router_config(path: Option<&Path>) -> Result<(PathBuf, Vec<String>), String> {
    let target = path
        .map(PathBuf::from)
        .unwrap_or_else(default_router_config_path);
    let (cfg, warnings) = if target.exists() {
        load_router_config_from_path(&target)?
    } else if path.is_some() {
        return Err(format!(
            "router config file not found: {}",
            target.display()
        ));
    } else {
        let cfg = RouterConfig::default();
        let warnings = validate_router_config(&cfg)?;
        (cfg, warnings)
    };
    let lock = active_router_config_lock();
    let mut guard = lock
        .write()
        .map_err(|_| "router config lock poisoned".to_owned())?;
    *guard = cfg;
    Ok((target, warnings))
}

pub fn format_effective_routes_table(cfg: &RouterConfig) -> String {
    let no_env = RouterEnvOverrides::default();
    let mut lines = vec![
        "weight | stage       | model                    | effort | retry_model              | fallback_model".to_owned(),
        "-------+-------------+--------------------------+--------+--------------------------+-------------------------".to_owned(),
    ];
    for weight in ["XS", "S", "M", "L"] {
        for stage in ["plan", "plan-review", "impl", "pr-review"] {
            let author_hint = if matches!(stage, "plan-review" | "pr-review") {
                Some(ModelFamily::OpenAiSol)
            } else {
                None
            };
            if let Ok(Some(r0)) =
                resolve_stage_route_with_config(weight, stage, 0, author_hint, &no_env, cfg)
            {
                let r1 =
                    resolve_stage_route_with_config(weight, stage, 1, author_hint, &no_env, cfg)
                        .ok()
                        .flatten();
                let retry_col = r1
                    .as_ref()
                    .map(|r| format!("{} ({})", r.model, r.effort.as_str()))
                    .unwrap_or_else(|| "-".to_owned());
                let fb_col = r0
                    .fallback_model
                    .as_deref()
                    .map(|m| {
                        let eff = r0.fallback_effort.map(|e| e.as_str()).unwrap_or("medium");
                        format!("{m} ({eff})")
                    })
                    .unwrap_or_else(|| "-".to_owned());
                lines.push(format!(
                    "{:<6} | {:<11} | {:<24} | {:<6} | {:<24} | {}",
                    weight,
                    stage,
                    r0.model,
                    r0.effort.as_str(),
                    retry_col,
                    fb_col
                ));
            }
        }
    }
    lines.join("\n")
}

/// Deterministically resolves the model, reasoning effort, fallback, and budgets
/// for a given `(weight, stage, retry_count, author_family)`.
///
/// Returns `Ok(None)` for stages that are not applicable to `weight` or that are
/// pure human gates (`human-plan-approval`, `human-merge-approval`).
pub fn resolve_stage_route(
    weight: &str,
    stage: &str,
    retry_count: i64,
    author_family: Option<ModelFamily>,
) -> Result<Option<StageRoute>, String> {
    resolve_stage_route_with(
        weight,
        stage,
        retry_count,
        author_family,
        &RouterEnvOverrides::from_env(),
    )
}

/// Pure route resolver accepting explicit environment overrides so tests do not mutate process env.
pub fn resolve_stage_route_with(
    weight: &str,
    stage: &str,
    retry_count: i64,
    author_family: Option<ModelFamily>,
    overrides: &RouterEnvOverrides,
) -> Result<Option<StageRoute>, String> {
    let cfg = active_router_config();
    resolve_stage_route_with_config(weight, stage, retry_count, author_family, overrides, &cfg)
}

pub fn resolve_stage_route_with_config(
    weight: &str,
    stage: &str,
    retry_count: i64,
    author_family: Option<ModelFamily>,
    overrides: &RouterEnvOverrides,
    cfg: &RouterConfig,
) -> Result<Option<StageRoute>, String> {
    let norm_weight = weight.trim().to_ascii_uppercase();
    if !matches!(norm_weight.as_str(), "XS" | "S" | "M" | "L") {
        return Err(format!("unsupported task weight '{weight}'"));
    }

    let norm_stage = stage.trim().to_ascii_lowercase();
    if matches!(
        norm_stage.as_str(),
        "human-plan-approval" | "human-merge-approval"
    ) {
        return Ok(None);
    }
    if !matches!(
        norm_stage.as_str(),
        "plan" | "plan-review" | "impl" | "pr-review"
    ) {
        return Err(format!("unsupported stage '{stage}' for weight '{weight}'"));
    }

    let applicable = match norm_weight.as_str() {
        "XS" => norm_stage == "impl",
        "S" => matches!(norm_stage.as_str(), "impl" | "pr-review"),
        "M" | "L" => true,
        _ => false,
    };
    if !applicable {
        return Ok(None);
    }

    let is_retry = retry_count >= 1;
    let max_task_tokens = max_task_tokens_for_weight(&norm_weight);
    let timeout_secs = stage_timeout_secs(&norm_weight, &norm_stage);

    let ov = cfg
        .routes
        .iter()
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(&norm_weight))
        .and_then(|(_, stage_map)| {
            stage_map
                .iter()
                .find(|(k, _)| k.trim().eq_ignore_ascii_case(&norm_stage))
                .map(|(_, v)| v)
        })
        .ok_or_else(|| format!("missing route for {norm_weight}.{norm_stage} in router config"))?;

    let use_cross_family_alt = matches!(norm_stage.as_str(), "plan-review" | "pr-review")
        && author_family == Some(ModelFamily::GeminiAgy);

    let (model, effort, fallback_model, fallback_effort) = if use_cross_family_alt {
        let alt = ov.cross_family_alt.as_ref().ok_or_else(|| {
            format!("missing cross_family_alt for {norm_weight}.{norm_stage} in router config")
        })?;
        let model = if is_retry {
            alt.retry_model
                .as_deref()
                .or(alt.model.as_deref())
                .ok_or_else(|| {
                    format!(
                        "missing cross_family_alt.model for {norm_weight}.{norm_stage} in router config"
                    )
                })?
                .to_owned()
        } else {
            alt.model
                .as_deref()
                .ok_or_else(|| {
                    format!(
                        "missing cross_family_alt.model for {norm_weight}.{norm_stage} in router config"
                    )
                })?
                .to_owned()
        };
        let effort = if is_retry {
            alt.retry_effort.or(alt.effort).ok_or_else(|| {
                format!(
                    "missing cross_family_alt.effort for {norm_weight}.{norm_stage} in router config"
                )
            })?
        } else {
            alt.effort.ok_or_else(|| {
                format!(
                    "missing cross_family_alt.effort for {norm_weight}.{norm_stage} in router config"
                )
            })?
        };
        (model, effort, None, None)
    } else {
        let model = if is_retry {
            ov.retry_model
                .as_deref()
                .or(ov.model.as_deref())
                .ok_or_else(|| {
                    format!("missing model for {norm_weight}.{norm_stage} in router config")
                })?
                .to_owned()
        } else {
            ov.model
                .as_deref()
                .ok_or_else(|| {
                    format!("missing model for {norm_weight}.{norm_stage} in router config")
                })?
                .to_owned()
        };
        let effort = if is_retry {
            ov.retry_effort.or(ov.effort).ok_or_else(|| {
                format!("missing effort for {norm_weight}.{norm_stage} in router config")
            })?
        } else {
            ov.effort.ok_or_else(|| {
                format!("missing effort for {norm_weight}.{norm_stage} in router config")
            })?
        };
        let fallback_model = if is_retry {
            ov.retry_fallback_model
                .as_deref()
                .or(ov.fallback_model.as_deref())
                .map(str::to_owned)
        } else {
            ov.fallback_model.clone()
        };
        let fallback_effort = if is_retry {
            ov.retry_fallback_effort.or(ov.fallback_effort)
        } else {
            ov.fallback_effort
        };
        (model, effort, fallback_model, fallback_effort)
    };

    let mut route = StageRoute {
        weight: norm_weight,
        stage: norm_stage,
        family: infer_model_family(&model),
        model,
        effort,
        fallback_family: fallback_model.as_deref().map(infer_model_family),
        fallback_model,
        fallback_effort,
        max_task_tokens,
        timeout_secs,
        stall_timeout_secs: DEFAULT_STALL_TIMEOUT_SECS,
    };

    let forced_non_empty = overrides
        .forced_model
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(forced) = forced_non_empty {
        route.family = infer_model_family(forced);
        route.model = forced.to_owned();
        route.effort = ReasoningEffort::High;
        route.fallback_family = None;
        route.fallback_model = None;
        route.fallback_effort = None;
    } else if overrides.flash_only {
        route.family = infer_model_family(&cfg.flash_only.model);
        route.model = cfg.flash_only.model.clone();
        route.effort = cfg.flash_only.effort;
        route.fallback_family = None;
        route.fallback_model = None;
        route.fallback_effort = None;
    }

    validate_daemon_model(&route.model)?;
    if let Some(ref fb) = route.fallback_model {
        validate_daemon_model(fb)?;
    }

    if matches!(route.stage.as_str(), "plan-review" | "pr-review")
        && let Some(author) = author_family
        && route.family == author
    {
        eprintln!(
            "suggestion: {} uses {} ({}) which matches author family ({}); cross-family review is recommended",
            route.stage,
            route.model,
            route.family.as_str(),
            author.as_str()
        );
    }

    Ok(Some(route))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_allows_astra_and_rejects_empty_model() {
        assert!(!is_forbidden_daemon_model("gpt-6-astra"));
        assert!(validate_daemon_model("gpt-6-astra").is_ok());
        assert!(validate_daemon_model("gpt-6.2-astra").is_ok());
        assert!(validate_daemon_model("gpt-6.2-sol").is_ok());
        assert!(validate_daemon_model("").is_err());
    }

    #[test]
    fn router_uses_hydrogen_defaults_and_cross_model_review_separation() {
        // S impl uses OpenAiSol (gpt-6.2-sol medium -> high on retry)
        let s_impl_0 = resolve_stage_route("S", "impl", 0, None).unwrap().unwrap();
        assert_eq!(s_impl_0.family, ModelFamily::OpenAiSol);
        assert_eq!(s_impl_0.model, "gpt-6.2-sol");
        assert_eq!(s_impl_0.effort, ReasoningEffort::Medium);
        assert_eq!(s_impl_0.max_task_tokens, 400_000);
        assert_eq!(
            s_impl_0.fallback_model.as_deref(),
            Some("gemini-4-hydrogen-medium")
        );

        let s_impl_1 = resolve_stage_route("S", "impl", 1, None).unwrap().unwrap();
        assert_eq!(s_impl_1.effort, ReasoningEffort::High);

        // S pr-review when author is OpenAiSol uses GeminiAgy hydrogen
        let s_rev_0 = resolve_stage_route("S", "pr-review", 0, Some(ModelFamily::OpenAiSol))
            .unwrap()
            .unwrap();
        assert_eq!(s_rev_0.family, ModelFamily::GeminiAgy);
        assert_ne!(s_rev_0.family, s_impl_0.family);
        assert_eq!(s_rev_0.model, "gemini-4-hydrogen-high");

        // On retry_count == 1, S pr-review stays on gemini-4-hydrogen-high
        let s_rev_1 = resolve_stage_route("S", "pr-review", 1, Some(ModelFamily::OpenAiSol))
            .unwrap()
            .unwrap();
        assert_eq!(s_rev_1.family, ModelFamily::GeminiAgy);
        assert_eq!(s_rev_1.model, "gemini-4-hydrogen-high");

        // M plan and impl fallback use gemini-4-hydrogen-high
        let m_plan_0 = resolve_stage_route("M", "plan", 0, None).unwrap().unwrap();
        assert_eq!(
            m_plan_0.fallback_model.as_deref(),
            Some("gemini-4-hydrogen-high")
        );
        let m_plan_rev = resolve_stage_route("M", "plan-review", 0, Some(ModelFamily::OpenAiSol))
            .unwrap()
            .unwrap();
        assert_eq!(m_plan_rev.model, "gemini-4-hydrogen-medium");

        // Conversely, if author was GeminiAgy, reviewer uses OpenAiSol
        let s_rev_alt = resolve_stage_route("S", "pr-review", 0, Some(ModelFamily::GeminiAgy))
            .unwrap()
            .unwrap();
        assert_eq!(s_rev_alt.family, ModelFamily::OpenAiSol);
        assert_eq!(s_rev_alt.model, "gpt-6.2-sol");

        // XS has no plan or pr-review model stages
        assert!(
            resolve_stage_route("XS", "plan", 0, None)
                .unwrap()
                .is_none()
        );
        assert!(
            resolve_stage_route("XS", "pr-review", 0, None)
                .unwrap()
                .is_none()
        );
        let xs_impl = resolve_stage_route("XS", "impl", 0, None).unwrap().unwrap();
        assert_eq!(xs_impl.effort, ReasoningEffort::Low);
        assert_eq!(xs_impl.max_task_tokens, 150_000);
        assert_eq!(
            xs_impl.fallback_model.as_deref(),
            Some("gemini-4-hydrogen-medium")
        );
    }

    #[test]
    fn router_honors_flash_only_and_forced_model_overrides() {
        let flash_route = resolve_stage_route_with(
            "S",
            "impl",
            0,
            None,
            &RouterEnvOverrides {
                flash_only: true,
                forced_model: None,
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(flash_route.family, ModelFamily::GeminiAgy);
        assert_eq!(flash_route.model, "gemini-4-hydrogen-high");
        assert!(flash_route.fallback_model.is_none());

        let forced_route = resolve_stage_route_with(
            "M",
            "plan",
            0,
            None,
            &RouterEnvOverrides {
                flash_only: false,
                forced_model: Some("gpt-6-astra".to_owned()),
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(forced_route.family, ModelFamily::OpenAiSol);
        assert_eq!(forced_route.model, "gpt-6-astra");
        assert_eq!(forced_route.effort, ReasoningEffort::High);
        assert!(forced_route.fallback_model.is_none());
    }

    #[test]
    fn router_treats_same_family_review_as_non_blocking_suggestion() {
        let ok_flash = resolve_stage_route_with(
            "S",
            "pr-review",
            0,
            Some(ModelFamily::GeminiAgy),
            &RouterEnvOverrides {
                flash_only: true,
                forced_model: None,
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(ok_flash.family, ModelFamily::GeminiAgy);
        assert_eq!(ok_flash.model, "gemini-4-hydrogen-high");

        let ok_forced_sol = resolve_stage_route_with(
            "M",
            "plan-review",
            0,
            Some(ModelFamily::OpenAiSol),
            &RouterEnvOverrides {
                flash_only: false,
                forced_model: Some("gpt-6.1-sol".to_owned()),
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(ok_forced_sol.family, ModelFamily::OpenAiSol);
        assert_eq!(ok_forced_sol.model, "gpt-6.1-sol");
    }

    #[test]
    fn router_config_overrides_and_validates_with_warnings() {
        let raw = r#"{
            "routes": {
                "M": {
                    "plan": {
                        "model": "gpt-6-astra",
                        "effort": "high",
                        "fallback_model": "gemini-4-hydrogen-high",
                        "fallback_effort": "medium"
                    },
                    "plan-review": {
                        "model": "gpt-6.1-sol",
                        "effort": "medium"
                    }
                }
            }
        }"#;
        let cfg: RouterConfig = serde_json::from_str(raw).unwrap();
        let warnings = validate_router_config(&cfg).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("M.plan-review"));
        assert!(warnings[0].contains("cross-family review is recommended"));

        let route = resolve_stage_route_with_config(
            "M",
            "plan",
            0,
            None,
            &RouterEnvOverrides::default(),
            &cfg,
        )
        .unwrap()
        .unwrap();
        assert_eq!(route.model, "gpt-6-astra");
        assert_eq!(
            route.fallback_model.as_deref(),
            Some("gemini-4-hydrogen-high")
        );
        assert_eq!(route.fallback_effort, Some(ReasoningEffort::Medium));

        let bad_cfg: RouterConfig =
            serde_json::from_str(r#"{"routes":{"XS":{"plan":{"model":"gpt-6.1-sol"}}}}"#).unwrap();
        assert!(validate_router_config(&bad_cfg).is_err());
    }

    #[test]
    fn embedded_router_json_validates_cleanly_and_merges_partial_overlays() {
        let base = RouterConfig::default();
        let warnings = validate_router_config(&base).unwrap();
        assert!(
            warnings.is_empty(),
            "canonical config/router.json should have no warnings: {warnings:?}"
        );
        assert_eq!(base.flash_only.model, "gemini-4-hydrogen-high");
        assert_eq!(base.flash_only.effort, ReasoningEffort::High);
        assert_eq!(base.agy_infra_fallback.model, "gpt-6.2-sol");
        assert_eq!(base.agy_infra_fallback.effort, ReasoningEffort::High);

        // Partial user overlay preserves omitted effort, retry_model, and fallback_model.
        let partial_raw = r#"{
            "flash_only": { "model": "gemini-4-hydrogen-medium" },
            "agy_infra_fallback": { "model": "gpt-6.2-astra", "effort": "medium" },
            "routes": {
                "xs": {
                    "IMPL": { "model": "gpt-6.2-astra" }
                },
                "M": {
                    "plan": { "model": "gpt-6.2-astra" }
                }
            }
        }"#;
        let merged: RouterConfig = serde_json::from_str(partial_raw).unwrap();
        assert!(validate_router_config(&merged).unwrap().is_empty());
        assert_eq!(merged.flash_only.model, "gemini-4-hydrogen-medium");
        assert_eq!(merged.flash_only.effort, ReasoningEffort::High);
        assert_eq!(merged.agy_infra_fallback.model, "gpt-6.2-astra");
        assert_eq!(merged.agy_infra_fallback.effort, ReasoningEffort::Medium);

        let xs_impl = resolve_stage_route_with_config(
            "XS",
            "impl",
            0,
            None,
            &RouterEnvOverrides::default(),
            &merged,
        )
        .unwrap()
        .unwrap();
        assert_eq!(xs_impl.model, "gpt-6.2-astra");
        assert_eq!(xs_impl.effort, ReasoningEffort::Low);
        assert_eq!(
            xs_impl.fallback_model.as_deref(),
            Some("gemini-4-hydrogen-medium")
        );

        let m_plan_retry = resolve_stage_route_with_config(
            "M",
            "plan",
            1,
            None,
            &RouterEnvOverrides::default(),
            &merged,
        )
        .unwrap()
        .unwrap();
        assert_eq!(m_plan_retry.model, "gemini-4-hydrogen-high");
        assert_eq!(m_plan_retry.fallback_model.as_deref(), Some("gpt-6.2-sol"));

        let flash_route = resolve_stage_route_with_config(
            "S",
            "impl",
            0,
            None,
            &RouterEnvOverrides {
                flash_only: true,
                forced_model: None,
            },
            &merged,
        )
        .unwrap()
        .unwrap();
        assert_eq!(flash_route.model, "gemini-4-hydrogen-medium");
        assert_eq!(flash_route.effort, ReasoningEffort::High);
    }

    #[test]
    fn router_validation_rejects_empty_endpoints_and_invalid_cross_family_alt() {
        let empty_flash: RouterConfig =
            serde_json::from_str(r#"{"flash_only":{"model":"  "}}"#).unwrap();
        assert!(validate_router_config(&empty_flash).is_err());

        let empty_agy_fb: RouterConfig =
            serde_json::from_str(r#"{"agy_infra_fallback":{"model":""}}"#).unwrap();
        assert!(validate_router_config(&empty_agy_fb).is_err());

        let bad_alt: RouterConfig = serde_json::from_str(
            r#"{"routes":{"XS":{"impl":{"cross_family_alt":{"model":"gpt-6.2-sol"}}}}}"#,
        )
        .unwrap();
        assert!(validate_router_config(&bad_alt).is_err());
    }

    #[test]
    fn init_router_config_writes_canonical_json_and_respects_force() {
        let temp_dir = std::env::temp_dir().join(format!(
            "zach_router_init_test_{}_{}",
            std::process::id(),
            crate::v2::now_epoch()
        ));
        let target = temp_dir.join("nested").join("router.json");
        let written = init_router_config(Some(&target), false).unwrap();
        assert_eq!(written, target);
        let (loaded, warnings) = load_router_config_from_path(&target).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(loaded, RouterConfig::default());

        assert!(init_router_config(Some(&target), false).is_err());
        std::fs::write(&target, "{}").unwrap();
        init_router_config(Some(&target), true).unwrap();
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            default_router_config_json()
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
