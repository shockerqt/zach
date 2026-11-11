use serde::{Deserialize, Serialize};

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
                fallback_model: Some("gemini-3.8-flash-medium".to_owned()),
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
            "gemini-3.8-flash-high",
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
    let force_flash = std::env::var("ZACH_USE_FLASH_ONLY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let forced_model = std::env::var("ZACH_FORCE_MODEL").ok();
    if force_flash || forced_model.is_some() {
        let target_model = forced_model.unwrap_or_else(|| "gemini-3.8-flash-high".to_owned());
        route.family = ModelFamily::GeminiAgy;
        route.model = target_model;
        route.effort = ReasoningEffort::High;
        route.fallback_family = None;
        route.fallback_model = None;
        route.fallback_effort = None;
    }

    validate_daemon_model(&route.model)?;
    if let Some(ref fb) = route.fallback_model {
        validate_daemon_model(fb)?;
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
            fallback_family: Some(ModelFamily::OpenAiSol),
            fallback_model: Some("gpt-6.1-sol".to_owned()),
            fallback_effort: Some(sol_base_effort),
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
            fallback_family: Some(ModelFamily::GeminiAgy),
            fallback_model: Some(gemini_retry.to_owned()),
            fallback_effort: Some(ReasoningEffort::High),
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
        assert!(!is_forbidden_daemon_model("gemini-3.8-flash-high"));
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
        assert_eq!(s_rev_0.model, "gemini-3.8-flash-high");

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
    }

    #[test]
    fn router_honors_flash_only_env_override() {
        unsafe {
            std::env::set_var("ZACH_USE_FLASH_ONLY", "1");
        }
        let route = resolve_stage_route("S", "impl", 0, None).unwrap().unwrap();
        assert_eq!(route.family, ModelFamily::GeminiAgy);
        assert_eq!(route.model, "gemini-3.8-flash-high");
        unsafe {
            std::env::remove_var("ZACH_USE_FLASH_ONLY");
        }
    }
}
