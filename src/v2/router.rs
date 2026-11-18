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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StageOverride {
    pub model: Option<String>,
    pub effort: Option<ReasoningEffort>,
    pub retry_model: Option<String>,
    pub retry_effort: Option<ReasoningEffort>,
    pub fallback_model: Option<String>,
    pub fallback_effort: Option<ReasoningEffort>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RouterConfig {
    #[serde(default)]
    pub routes: BTreeMap<String, BTreeMap<String, StageOverride>>,
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

    let is_retry = retry_count >= 1;
    let max_task_tokens = max_task_tokens_for_weight(&norm_weight);
    let timeout_secs = stage_timeout_secs(&norm_weight, &norm_stage);

    let route = match (norm_weight.as_str(), norm_stage.as_str()) {
        // XS: 1-step pipeline (impl only)
        ("XS", "impl") => {
            let effort = if is_retry {
                ReasoningEffort::Medium
            } else {
                ReasoningEffort::Low
            };
            StageRoute {
                weight: norm_weight,
                stage: norm_stage,
                family: ModelFamily::OpenAiSol,
                model: "gpt-6.2-sol".to_owned(),
                effort,
                fallback_family: Some(ModelFamily::GeminiAgy),
                fallback_model: Some("gemini-4-hydrogen-medium".to_owned()),
                fallback_effort: Some(ReasoningEffort::Medium),
                max_task_tokens,
                timeout_secs,
                stall_timeout_secs: DEFAULT_STALL_TIMEOUT_SECS,
            }
        }
        ("XS", "plan" | "plan-review" | "pr-review") => return Ok(None),

        // S: 2-step pipeline (impl -> cross-model pr-review)
        ("S", "impl") => {
            let effort = if is_retry {
                ReasoningEffort::High
            } else {
                ReasoningEffort::Medium
            };
            StageRoute {
                weight: norm_weight,
                stage: norm_stage,
                family: ModelFamily::OpenAiSol,
                model: "gpt-6.2-sol".to_owned(),
                effort,
                fallback_family: Some(ModelFamily::GeminiAgy),
                fallback_model: Some("gemini-4-hydrogen-medium".to_owned()),
                fallback_effort: Some(ReasoningEffort::Medium),
                max_task_tokens,
                timeout_secs,
                stall_timeout_secs: DEFAULT_STALL_TIMEOUT_SECS,
            }
        }
        ("S", "pr-review") => build_cross_model_review_route(
            norm_weight,
            norm_stage,
            is_retry,
            author_family.unwrap_or(ModelFamily::OpenAiSol),
            "gemini-4-hydrogen-high",
            "gemini-4-hydrogen-high",
            ReasoningEffort::High,
            ReasoningEffort::Medium,
            max_task_tokens,
            timeout_secs,
        ),
        ("S", "plan" | "plan-review") => return Ok(None),

        // M: 4-step pipeline (plan -> plan-review -> impl -> pr-review)
        ("M", "plan") => {
            if is_retry {
                StageRoute {
                    weight: norm_weight,
                    stage: norm_stage,
                    family: ModelFamily::GeminiAgy,
                    model: "gemini-4-hydrogen-high".to_owned(),
                    effort: ReasoningEffort::High,
                    fallback_family: Some(ModelFamily::OpenAiSol),
                    fallback_model: Some("gpt-6.2-sol".to_owned()),
                    fallback_effort: Some(ReasoningEffort::High),
                    max_task_tokens,
                    timeout_secs,
                    stall_timeout_secs: DEFAULT_STALL_TIMEOUT_SECS,
                }
            } else {
                StageRoute {
                    weight: norm_weight,
                    stage: norm_stage,
                    family: ModelFamily::OpenAiSol,
                    model: "gpt-6.2-sol".to_owned(),
                    effort: ReasoningEffort::High,
                    fallback_family: Some(ModelFamily::GeminiAgy),
                    fallback_model: Some("gemini-4-hydrogen-high".to_owned()),
                    fallback_effort: Some(ReasoningEffort::High),
                    max_task_tokens,
                    timeout_secs,
                    stall_timeout_secs: DEFAULT_STALL_TIMEOUT_SECS,
                }
            }
        }
        ("M", "plan-review") => build_cross_model_review_route(
            norm_weight,
            norm_stage,
            is_retry,
            author_family.unwrap_or(ModelFamily::OpenAiSol),
            "gemini-4-hydrogen-medium",
            "gemini-4-hydrogen-high",
            if is_retry {
                ReasoningEffort::High
            } else {
                ReasoningEffort::Medium
            },
            ReasoningEffort::Medium,
            max_task_tokens,
            timeout_secs,
        ),
        ("M", "impl") => StageRoute {
            weight: norm_weight,
            stage: norm_stage,
            family: ModelFamily::OpenAiSol,
            model: "gpt-6.2-sol".to_owned(),
            effort: ReasoningEffort::High,
            fallback_family: Some(ModelFamily::GeminiAgy),
            fallback_model: Some("gemini-4-hydrogen-high".to_owned()),
            fallback_effort: Some(ReasoningEffort::High),
            max_task_tokens,
            timeout_secs,
            stall_timeout_secs: DEFAULT_STALL_TIMEOUT_SECS,
        },
        ("M", "pr-review") => build_cross_model_review_route(
            norm_weight,
            norm_stage,
            is_retry,
            author_family.unwrap_or(ModelFamily::OpenAiSol),
            "gemini-4-hydrogen-high",
            "gemini-4-hydrogen-high",
            ReasoningEffort::High,
            ReasoningEffort::Medium,
            max_task_tokens,
            timeout_secs,
        ),

        // L: 4-step pipeline + human gates
        ("L", "plan") => StageRoute {
            weight: norm_weight,
            stage: norm_stage,
            family: ModelFamily::OpenAiSol,
            model: "gpt-6.2-sol".to_owned(),
            effort: ReasoningEffort::High,
            fallback_family: None,
            fallback_model: None,
            fallback_effort: None,
            max_task_tokens,
            timeout_secs,
            stall_timeout_secs: DEFAULT_STALL_TIMEOUT_SECS,
        },
        ("L", "plan-review") => build_cross_model_review_route(
            norm_weight,
            norm_stage,
            is_retry,
            author_family.unwrap_or(ModelFamily::OpenAiSol),
            "gemini-4-hydrogen-high",
            "gemini-4-hydrogen-high",
            ReasoningEffort::High,
            ReasoningEffort::High,
            max_task_tokens,
            timeout_secs,
        ),
        ("L", "impl") => StageRoute {
            weight: norm_weight,
            stage: norm_stage,
            family: ModelFamily::OpenAiSol,
            model: "gpt-6.2-sol".to_owned(),
            effort: ReasoningEffort::High,
            fallback_family: None,
            fallback_model: None,
            fallback_effort: None,
            max_task_tokens,
            timeout_secs,
            stall_timeout_secs: DEFAULT_STALL_TIMEOUT_SECS,
        },
        ("L", "pr-review") => build_cross_model_review_route(
            norm_weight,
            norm_stage,
            is_retry,
            author_family.unwrap_or(ModelFamily::OpenAiSol),
            "gemini-4-hydrogen-high",
            "gemini-4-hydrogen-high",
            ReasoningEffort::High,
            ReasoningEffort::High,
            max_task_tokens,
            timeout_secs,
        ),

        _ => return Err(format!("unsupported stage '{stage}' for weight '{weight}'")),
    };

    let mut route = route;
    if let Some(stage_map) = cfg
        .routes
        .iter()
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(&route.weight))
        .map(|(_, v)| v)
        && let Some(ov) = stage_map
            .iter()
            .find(|(k, _)| k.trim().eq_ignore_ascii_case(&route.stage))
            .map(|(_, v)| v)
    {
        if is_retry {
            if let Some(ref m) = ov.retry_model {
                route.family = infer_model_family(m);
                route.model = m.clone();
            } else if let Some(ref m) = ov.model {
                route.family = infer_model_family(m);
                route.model = m.clone();
            }
            if let Some(eff) = ov.retry_effort.or(ov.effort) {
                route.effort = eff;
            }
        } else {
            if let Some(ref m) = ov.model {
                route.family = infer_model_family(m);
                route.model = m.clone();
            }
            if let Some(eff) = ov.effort {
                route.effort = eff;
            }
        }
        if let Some(ref fb) = ov.fallback_model {
            route.fallback_family = Some(infer_model_family(fb));
            route.fallback_model = Some(fb.clone());
        }
        if let Some(fb_eff) = ov.fallback_effort {
            route.fallback_effort = Some(fb_eff);
        }
    }

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
        route.family = ModelFamily::GeminiAgy;
        route.model = "gemini-4-hydrogen-high".to_owned();
        route.effort = ReasoningEffort::High;
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

#[allow(clippy::too_many_arguments)]
fn build_cross_model_review_route(
    weight: String,
    stage: String,
    is_retry: bool,
    author: ModelFamily,
    gemini_primary: &str,
    gemini_retry: &str,
    gemini_effort: ReasoningEffort,
    sol_base_effort: ReasoningEffort,
    max_task_tokens: u64,
    timeout_secs: u64,
) -> StageRoute {
    match author {
        ModelFamily::OpenAiSol => StageRoute {
            weight,
            stage,
            family: ModelFamily::GeminiAgy,
            model: if is_retry {
                gemini_retry.to_owned()
            } else {
                gemini_primary.to_owned()
            },
            effort: gemini_effort,
            fallback_family: None,
            fallback_model: None,
            fallback_effort: None,
            max_task_tokens,
            timeout_secs,
            stall_timeout_secs: DEFAULT_STALL_TIMEOUT_SECS,
        },
        ModelFamily::GeminiAgy => StageRoute {
            weight,
            stage,
            family: ModelFamily::OpenAiSol,
            model: "gpt-6.2-sol".to_owned(),
            effort: if is_retry {
                sol_base_effort.escalate()
            } else {
                sol_base_effort
            },
            fallback_family: None,
            fallback_model: None,
            fallback_effort: None,
            max_task_tokens,
            timeout_secs,
            stall_timeout_secs: DEFAULT_STALL_TIMEOUT_SECS,
        },
    }
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
}
