use serde::{Deserialize, Serialize};

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
pub enum ReasoningEffort {
    Low,
    Medium,
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

/// Returns `true` if `model` refers to a forbidden interactive-only model (`gpt-6-astra`).
pub fn is_forbidden_daemon_model(model: &str) -> bool {
    model.to_ascii_lowercase().contains("astra")
}

/// Validates that a model identifier is permitted in autonomous daemon runs.
pub fn validate_daemon_model(model: &str) -> Result<(), String> {
    if is_forbidden_daemon_model(model) {
        return Err(format!(
            "model '{model}' is forbidden in zachd autonomous runs (gpt-6-astra is reserved for interactive sessions)"
        ));
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
                model: "gpt-6.1-sol".to_owned(),
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
                model: "gpt-6.1-sol".to_owned(),
                effort,
                fallback_family: Some(ModelFamily::GeminiAgy),
                fallback_model: Some("gemini-4-argon-medium".to_owned()),
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
            "gemini-4-argon-high",
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
                    model: "gemini-4-argon-high".to_owned(),
                    effort: ReasoningEffort::High,
                    fallback_family: Some(ModelFamily::OpenAiSol),
                    fallback_model: Some("gpt-6.1-sol".to_owned()),
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
                    model: "gpt-6.1-sol".to_owned(),
                    effort: ReasoningEffort::High,
                    fallback_family: Some(ModelFamily::GeminiAgy),
                    fallback_model: Some("gemini-4-argon-high".to_owned()),
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
            "gemini-4-argon-medium",
            "gemini-4-argon-high",
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
            model: "gpt-6.1-sol".to_owned(),
            effort: ReasoningEffort::High,
            fallback_family: Some(ModelFamily::GeminiAgy),
            fallback_model: Some("gemini-4-argon-high".to_owned()),
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
            "gemini-4-argon-high",
            "gemini-4-argon-high",
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
            model: "gpt-6.1-sol".to_owned(),
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
            "gemini-4-argon-high",
            "gemini-4-argon-high",
            ReasoningEffort::High,
            ReasoningEffort::High,
            max_task_tokens,
            timeout_secs,
        ),
        ("L", "impl") => StageRoute {
            weight: norm_weight,
            stage: norm_stage,
            family: ModelFamily::OpenAiSol,
            model: "gpt-6.1-sol".to_owned(),
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
            "gemini-4-argon-high",
            "gemini-4-argon-high",
            ReasoningEffort::High,
            ReasoningEffort::High,
            max_task_tokens,
            timeout_secs,
        ),

        _ => return Err(format!("unsupported stage '{stage}' for weight '{weight}'")),
    };

    let mut route = route;
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
        return Err(format!(
            "{NO_CROSS_FAMILY_REVIEWER_ERR}: cannot run {} with {} ({}) when author used {}; cross-family review is mandatory",
            route.stage,
            route.model,
            route.family.as_str(),
            author.as_str()
        ));
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
            model: "gpt-6.1-sol".to_owned(),
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
    fn router_rejects_gpt_6_astra_and_never_routes_to_it() {
        assert!(is_forbidden_daemon_model("gpt-6-astra"));
        assert!(is_forbidden_daemon_model("GPT-6-ASTRA-HIGH"));
        assert!(!is_forbidden_daemon_model("gpt-6.1-sol"));
        assert!(!is_forbidden_daemon_model("gemini-4-hydrogen-medium"));
        assert!(!is_forbidden_daemon_model("gemini-4-hydrogen-high"));
        assert!(!is_forbidden_daemon_model("gemini-4-argon-high"));
        assert!(validate_daemon_model("gpt-6-astra").is_err());

        for weight in ["XS", "S", "M", "L"] {
            for stage in [
                "plan",
                "plan-review",
                "human-plan-approval",
                "impl",
                "pr-review",
                "human-merge-approval",
            ] {
                for retry in [0, 1] {
                    if let Some(route) = resolve_stage_route(weight, stage, retry, None).unwrap() {
                        assert!(!is_forbidden_daemon_model(&route.model));
                        if let Some(ref fb) = route.fallback_model {
                            assert!(!is_forbidden_daemon_model(fb));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn router_enforces_cross_model_review_family_separation_and_retry_escalation() {
        // S impl uses OpenAiSol (gpt-6.1-sol medium -> high on retry)
        let s_impl_0 = resolve_stage_route("S", "impl", 0, None).unwrap().unwrap();
        assert_eq!(s_impl_0.family, ModelFamily::OpenAiSol);
        assert_eq!(s_impl_0.model, "gpt-6.1-sol");
        assert_eq!(s_impl_0.effort, ReasoningEffort::Medium);
        assert_eq!(s_impl_0.max_task_tokens, 400_000);

        let s_impl_1 = resolve_stage_route("S", "impl", 1, None).unwrap().unwrap();
        assert_eq!(s_impl_1.effort, ReasoningEffort::High);

        // S pr-review when author is OpenAiSol must use GeminiAgy
        let s_rev_0 = resolve_stage_route("S", "pr-review", 0, Some(ModelFamily::OpenAiSol))
            .unwrap()
            .unwrap();
        assert_eq!(s_rev_0.family, ModelFamily::GeminiAgy);
        assert_ne!(s_rev_0.family, s_impl_0.family);
        assert_eq!(s_rev_0.model, "gemini-4-hydrogen-high");

        // On retry_count == 1, S pr-review escalates to gemini-4-argon-high while keeping cross-model family
        let s_rev_1 = resolve_stage_route("S", "pr-review", 1, Some(ModelFamily::OpenAiSol))
            .unwrap()
            .unwrap();
        assert_eq!(s_rev_1.family, ModelFamily::GeminiAgy);
        assert_eq!(s_rev_1.model, "gemini-4-argon-high");

        // Conversely, if author was GeminiAgy, reviewer must be OpenAiSol
        let s_rev_alt = resolve_stage_route("S", "pr-review", 0, Some(ModelFamily::GeminiAgy))
            .unwrap()
            .unwrap();
        assert_eq!(s_rev_alt.family, ModelFamily::OpenAiSol);
        assert_eq!(s_rev_alt.model, "gpt-6.1-sol");

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
                forced_model: Some("gemini-4-argon-high".to_owned()),
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(forced_route.family, ModelFamily::GeminiAgy);
        assert_eq!(forced_route.model, "gemini-4-argon-high");
        assert_eq!(forced_route.effort, ReasoningEffort::High);
        assert!(forced_route.fallback_model.is_none());
    }

    #[test]
    fn router_enforces_mandatory_cross_family_review_under_overrides() {
        assert_eq!(ModelFamily::OpenAiSol.opposite(), ModelFamily::GeminiAgy);
        assert_eq!(ModelFamily::GeminiAgy.opposite(), ModelFamily::OpenAiSol);
        assert_eq!(infer_model_family("gpt-6.1-sol"), ModelFamily::OpenAiSol);
        assert_eq!(
            infer_model_family("gemini-4-argon-high"),
            ModelFamily::GeminiAgy
        );

        // Default cross-family review routes never expose a same-family fallback
        for weight in ["S", "M", "L"] {
            for stage in ["plan-review", "pr-review"] {
                if let Some(route) =
                    resolve_stage_route(weight, stage, 0, Some(ModelFamily::OpenAiSol)).unwrap()
                {
                    assert_eq!(route.family, ModelFamily::GeminiAgy);
                    assert!(route.fallback_family.is_none());
                    assert!(route.fallback_model.is_none());
                }
                if let Some(route) =
                    resolve_stage_route(weight, stage, 0, Some(ModelFamily::GeminiAgy)).unwrap()
                {
                    assert_eq!(route.family, ModelFamily::OpenAiSol);
                    assert!(route.fallback_family.is_none());
                    assert!(route.fallback_model.is_none());
                }
            }
        }

        // flash_only cannot review GeminiAgy author
        let err_flash = resolve_stage_route_with(
            "S",
            "pr-review",
            0,
            Some(ModelFamily::GeminiAgy),
            &RouterEnvOverrides {
                flash_only: true,
                forced_model: None,
            },
        )
        .unwrap_err();
        assert!(is_no_cross_family_reviewer_error(&err_flash));

        // flash_only CAN review OpenAiSol author
        let ok_flash = resolve_stage_route_with(
            "S",
            "pr-review",
            0,
            Some(ModelFamily::OpenAiSol),
            &RouterEnvOverrides {
                flash_only: true,
                forced_model: None,
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(ok_flash.family, ModelFamily::GeminiAgy);

        // ZACH_FORCE_MODEL=gpt-6.1-sol cannot review OpenAiSol author
        let err_forced_sol = resolve_stage_route_with(
            "M",
            "plan-review",
            0,
            Some(ModelFamily::OpenAiSol),
            &RouterEnvOverrides {
                flash_only: false,
                forced_model: Some("gpt-6.1-sol".to_owned()),
            },
        )
        .unwrap_err();
        assert!(is_no_cross_family_reviewer_error(&err_forced_sol));

        // ZACH_FORCE_MODEL=gpt-6.1-sol CAN review GeminiAgy author
        let ok_forced_sol = resolve_stage_route_with(
            "M",
            "pr-review",
            0,
            Some(ModelFamily::GeminiAgy),
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
}
