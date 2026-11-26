use std::env;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use crate::v2::audit::redact_adr004_text;
use crate::v2::now_epoch;
use crate::v2::pipeline::{FAILURE_CLASS_INFRA, FAILURE_CLASS_POLICY, FAILURE_CLASS_SEMANTIC};

pub const DEFAULT_GEMINI_BASE_URL: &str = "https://generativelanguage.googleapis.com/v1beta";
pub const DEFAULT_GEMINI_DECISION_MODEL: &str = "gemini-decision-1";
pub const MAX_GEMINI_PROMPT_CHARS: usize = 1024;
pub const MAX_GEMINI_SYSTEM_CHARS: usize = 512;
pub const MAX_GEMINI_ERROR_CHARS: usize = 256;

#[derive(Debug, Clone)]
pub struct GeminiConfig {
    pub api_key: Option<String>,
    pub base_url: String,
    pub default_model: String,
    pub connect_timeout_secs: u64,
    pub max_timeout_secs: u64,
    pub offline: bool,
    pub circuit_breaker_threshold: u32,
    pub circuit_breaker_cooldown_secs: i64,
}

impl Default for GeminiConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl GeminiConfig {
    pub fn from_env() -> Self {
        let api_key = env::var("GEMINI_API_KEY")
            .ok()
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty());
        let base_url = env::var("ZACH_GEMINI_BASE_URL")
            .ok()
            .map(|v| v.trim().trim_end_matches('/').to_owned())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_GEMINI_BASE_URL.to_owned());
        let offline = env::var("ZACH_OFFLINE").ok().is_some_and(|v| {
            matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes")
        });
        Self {
            api_key,
            base_url,
            default_model: DEFAULT_GEMINI_DECISION_MODEL.to_owned(),
            connect_timeout_secs: 3,
            max_timeout_secs: 10,
            offline,
            circuit_breaker_threshold: 3,
            circuit_breaker_cooldown_secs: 60,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeminiError {
    Offline,
    MissingApiKey,
    CooldownActive { until_epoch: i64 },
    CircuitOpen { until_epoch: i64 },
    Transport(String),
    Parse(String),
}

impl std::fmt::Display for GeminiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Offline => write!(f, "gemini client is offline"),
            Self::MissingApiKey => write!(f, "GEMINI_API_KEY is not configured"),
            Self::CooldownActive { until_epoch } => {
                write!(f, "gemini provider cooldown active until {until_epoch}")
            }
            Self::CircuitOpen { until_epoch } => {
                write!(f, "gemini circuit breaker open until {until_epoch}")
            }
            Self::Transport(msg) => write!(f, "gemini transport error: {msg}"),
            Self::Parse(msg) => write!(f, "gemini parse error: {msg}"),
        }
    }
}

impl std::error::Error for GeminiError {}

#[derive(Debug, Clone)]
pub struct GenerateContentRequest {
    pub model: Option<String>,
    pub system_instruction: Option<String>,
    pub prompt: String,
    pub max_output_tokens: u32,
    pub temperature: Option<f32>,
    pub response_mime_type: Option<String>,
    pub provider_cooldown_until: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GenerateContentResponse {
    pub text: Option<String>,
    pub finish_reason: Option<String>,
    pub raw_json: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiHttpResponse {
    pub body: Vec<u8>,
}

pub trait GeminiTransport: Send + Sync {
    fn post_json(
        &self,
        url: &str,
        api_key: &str,
        body: &Value,
        connect_timeout_secs: u64,
        max_timeout_secs: u64,
    ) -> Result<GeminiHttpResponse, GeminiError>;
}

/// HTTPS transport backed by `curl --proto =https --tlsv1.2` with credentials
/// passed exclusively via stdin (`--config -`).
#[derive(Debug, Default)]
pub struct CurlGeminiTransport;

fn sanitize_error_text(raw: &str, api_key: Option<&str>) -> String {
    let scrubbed = match api_key {
        Some(key) if !key.is_empty() => raw.replace(key, "[REDACTED]"),
        _ => raw.to_owned(),
    };
    redact_adr004_text(&scrubbed, MAX_GEMINI_ERROR_CHARS)
}

fn escape_curl_config_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

fn build_curl_config(url: &str, api_key: &str, body: &Value) -> Result<String, GeminiError> {
    if !url.starts_with("https://") || url.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        return Err(GeminiError::Transport(
            "invalid gemini HTTPS endpoint".into(),
        ));
    }
    if api_key.is_empty() || api_key.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        return Err(GeminiError::Transport(
            "invalid gemini API key format".into(),
        ));
    }
    let json_body = serde_json::to_string(body)
        .map_err(|e| GeminiError::Parse(sanitize_error_text(&e.to_string(), Some(api_key))))?;
    Ok(format!(
        "url = \"{url}\"\nheader = \"x-goog-api-key: {key}\"\nheader = \"Content-Type: application/json\"\ndata = \"{data}\"\n",
        url = escape_curl_config_value(url),
        key = escape_curl_config_value(api_key),
        data = escape_curl_config_value(&json_body),
    ))
}

impl GeminiTransport for CurlGeminiTransport {
    fn post_json(
        &self,
        url: &str,
        api_key: &str,
        body: &Value,
        connect_timeout_secs: u64,
        max_timeout_secs: u64,
    ) -> Result<GeminiHttpResponse, GeminiError> {
        let config_stdin = build_curl_config(url, api_key, body)?;
        let connect_s = connect_timeout_secs.max(1).to_string();
        let max_s = max_timeout_secs.max(1).to_string();
        let mut child = Command::new("curl")
            .args([
                "--proto",
                "=https",
                "--tlsv1.2",
                "--fail",
                "--silent",
                "--show-error",
                "--connect-timeout",
                &connect_s,
                "--max-time",
                &max_s,
                "--config",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                GeminiError::Transport(sanitize_error_text(&e.to_string(), Some(api_key)))
            })?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(config_stdin.as_bytes()).map_err(|e| {
                GeminiError::Transport(sanitize_error_text(&e.to_string(), Some(api_key)))
            })?;
        }
        let output = child.wait_with_output().map_err(|e| {
            GeminiError::Transport(sanitize_error_text(&e.to_string(), Some(api_key)))
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let msg = if stderr.trim().is_empty() {
                format!("curl exited with status {}", output.status)
            } else {
                stderr.into_owned()
            };
            return Err(GeminiError::Transport(sanitize_error_text(
                &msg,
                Some(api_key),
            )));
        }
        Ok(GeminiHttpResponse {
            body: output.stdout,
        })
    }
}

#[derive(Debug, Default)]
struct CircuitBreakerState {
    consecutive_failures: u32,
    open_until_epoch: Option<i64>,
}

impl CircuitBreakerState {
    fn is_open(&self, now: i64) -> Option<i64> {
        self.open_until_epoch.filter(|&until| until > now)
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.open_until_epoch = None;
    }

    fn record_failure(&mut self, now: i64, threshold: u32, cooldown_secs: i64) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= threshold.max(1) {
            self.open_until_epoch = Some(now.saturating_add(cooldown_secs.max(1)));
        }
    }
}

#[derive(Clone)]
pub struct GeminiClient {
    config: GeminiConfig,
    transport: Arc<dyn GeminiTransport>,
    circuit: Arc<Mutex<CircuitBreakerState>>,
}

impl GeminiClient {
    pub fn new(config: GeminiConfig) -> Self {
        Self::with_transport(config, Arc::new(CurlGeminiTransport))
    }

    pub fn from_env() -> Self {
        Self::new(GeminiConfig::from_env())
    }

    pub fn with_transport(config: GeminiConfig, transport: Arc<dyn GeminiTransport>) -> Self {
        Self {
            config,
            transport,
            circuit: Arc::new(Mutex::new(CircuitBreakerState::default())),
        }
    }

    pub fn config(&self) -> &GeminiConfig {
        &self.config
    }

    /// Calls Gemini `generateContent` with ADR-004 redaction applied to all
    /// outbound text and returned error strings. Reusable by `ZACH-091`.
    pub fn generate_content(
        &self,
        req: &GenerateContentRequest,
    ) -> Result<GenerateContentResponse, GeminiError> {
        if self.config.offline {
            return Err(GeminiError::Offline);
        }
        let now = now_epoch();
        if let Some(until_epoch) = req.provider_cooldown_until.filter(|&u| u > now) {
            return Err(GeminiError::CooldownActive { until_epoch });
        }
        if let Ok(guard) = self.circuit.lock()
            && let Some(until_epoch) = guard.is_open(now)
        {
            return Err(GeminiError::CircuitOpen { until_epoch });
        }
        let api_key = self
            .config
            .api_key
            .as_deref()
            .filter(|k| !k.trim().is_empty())
            .ok_or(GeminiError::MissingApiKey)?;

        let model = req
            .model
            .as_deref()
            .filter(|m| !m.trim().is_empty())
            .unwrap_or(&self.config.default_model);
        let url = format!(
            "{}/models/{}:generateContent",
            self.config.base_url.trim_end_matches('/'),
            model
        );

        let redacted_prompt = redact_adr004_text(&req.prompt, MAX_GEMINI_PROMPT_CHARS);
        let mut generation_config = json!({
            "maxOutputTokens": req.max_output_tokens,
        });
        if let Some(temp) = req.temperature {
            generation_config["temperature"] = json!(temp);
        }
        if let Some(mime) = req.response_mime_type.as_deref() {
            generation_config["responseMimeType"] = json!(mime);
        }

        let mut payload = json!({
            "contents": [{
                "role": "user",
                "parts": [{ "text": redacted_prompt }]
            }],
            "generationConfig": generation_config,
        });
        if let Some(sys) = req.system_instruction.as_deref() {
            let redacted_sys = redact_adr004_text(sys, MAX_GEMINI_SYSTEM_CHARS);
            if !redacted_sys.is_empty() {
                payload["systemInstruction"] = json!({
                    "parts": [{ "text": redacted_sys }]
                });
            }
        }

        let resp = match self.transport.post_json(
            &url,
            api_key,
            &payload,
            self.config.connect_timeout_secs,
            self.config.max_timeout_secs,
        ) {
            Ok(resp) => resp,
            Err(err) => {
                if let Ok(mut guard) = self.circuit.lock() {
                    guard.record_failure(
                        now,
                        self.config.circuit_breaker_threshold,
                        self.config.circuit_breaker_cooldown_secs,
                    );
                }
                return Err(match err {
                    GeminiError::Transport(msg) => {
                        GeminiError::Transport(sanitize_error_text(&msg, Some(api_key)))
                    }
                    GeminiError::Parse(msg) => {
                        GeminiError::Parse(sanitize_error_text(&msg, Some(api_key)))
                    }
                    other => other,
                });
            }
        };

        let raw_json: Value = serde_json::from_slice(&resp.body).map_err(|e| {
            if let Ok(mut guard) = self.circuit.lock() {
                guard.record_failure(
                    now,
                    self.config.circuit_breaker_threshold,
                    self.config.circuit_breaker_cooldown_secs,
                );
            }
            GeminiError::Parse(sanitize_error_text(&e.to_string(), Some(api_key)))
        })?;

        if let Ok(mut guard) = self.circuit.lock() {
            guard.record_success();
        }

        let candidate = raw_json
            .get("candidates")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first());
        let finish_reason = candidate
            .and_then(|c| c.get("finishReason"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let text = candidate
            .and_then(|c| c.get("content"))
            .and_then(|c| c.get("parts"))
            .and_then(Value::as_array)
            .and_then(|parts| {
                let joined: Vec<&str> = parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(Value::as_str))
                    .collect();
                if joined.is_empty() {
                    None
                } else {
                    Some(joined.join(""))
                }
            });

        Ok(GenerateContentResponse {
            text,
            finish_reason,
            raw_json,
        })
    }

    /// Tier 2 classifier using `gemini-decision-1` with `maxOutputTokens: 0`
    /// and bounded, redacted failure context.
    pub fn classify_decision_1(
        &self,
        stage: &str,
        status: &str,
        message: &str,
        provider_cooldown_until: Option<i64>,
    ) -> Result<Option<&'static str>, GeminiError> {
        let clean_stage = redact_adr004_text(stage, 64);
        let clean_status = redact_adr004_text(status, 64);
        let clean_message = redact_adr004_text(message, 768);
        let prompt = format!(
            "Classify failure into one of: infra, semantic, policy.\nstage={clean_stage}\nstatus={clean_status}\nmessage={clean_message}"
        );
        let resp = self.generate_content(&GenerateContentRequest {
            model: Some(DEFAULT_GEMINI_DECISION_MODEL.to_owned()),
            system_instruction: Some(
                "Return failure class label: infra, semantic, or policy.".to_owned(),
            ),
            prompt,
            max_output_tokens: 0,
            temperature: Some(0.0),
            response_mime_type: None,
            provider_cooldown_until,
        })?;
        Ok(parse_decision_1_class(&resp))
    }
}

fn match_failure_class_label(raw: &str) -> Option<&'static str> {
    let trimmed = raw
        .trim()
        .trim_matches(|c: char| c == '"' || c == '\'' || c == '.');
    let lower = trimmed.to_ascii_lowercase();
    match lower.as_str() {
        "infra" | "infrastructure" | "transient" => Some(FAILURE_CLASS_INFRA),
        "semantic" | "code" | "test" | "review" => Some(FAILURE_CLASS_SEMANTIC),
        "policy" | "security" | "scope" => Some(FAILURE_CLASS_POLICY),
        _ => {
            if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
                for key in ["failure_class", "class", "decision", "label"] {
                    if let Some(s) = val.get(key).and_then(Value::as_str)
                        && let Some(matched) = match_failure_class_label(s)
                    {
                        return Some(matched);
                    }
                }
            }
            None
        }
    }
}

pub fn parse_decision_1_class(resp: &GenerateContentResponse) -> Option<&'static str> {
    if let Some(text) = resp.text.as_deref()
        && let Some(class) = match_failure_class_label(text)
    {
        return Some(class);
    }
    for key in ["decision", "classification", "failure_class", "label"] {
        if let Some(s) = resp.raw_json.get(key).and_then(Value::as_str)
            && let Some(class) = match_failure_class_label(s)
        {
            return Some(class);
        }
    }
    if let Some(candidate) = resp
        .raw_json
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
    {
        for key in ["decision", "classification", "failure_class", "label"] {
            if let Some(s) = candidate.get(key).and_then(Value::as_str)
                && let Some(class) = match_failure_class_label(s)
            {
                return Some(class);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type MockResponder =
        Box<dyn Fn(usize, &Value) -> Result<GeminiHttpResponse, GeminiError> + Send + Sync>;

    struct MockTransport {
        calls: AtomicUsize,
        captured_prompts: Mutex<Vec<String>>,
        captured_keys: Mutex<Vec<String>>,
        responder: MockResponder,
    }

    impl MockTransport {
        fn new<F>(f: F) -> Self
        where
            F: Fn(usize, &Value) -> Result<GeminiHttpResponse, GeminiError> + Send + Sync + 'static,
        {
            Self {
                calls: AtomicUsize::new(0),
                captured_prompts: Mutex::new(Vec::new()),
                captured_keys: Mutex::new(Vec::new()),
                responder: Box::new(f),
            }
        }
    }

    impl GeminiTransport for MockTransport {
        fn post_json(
            &self,
            _url: &str,
            api_key: &str,
            body: &Value,
            _connect_timeout_secs: u64,
            _max_timeout_secs: u64,
        ) -> Result<GeminiHttpResponse, GeminiError> {
            let idx = self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(text) = body["contents"][0]["parts"][0]["text"].as_str() {
                self.captured_prompts.lock().unwrap().push(text.to_owned());
            }
            self.captured_keys.lock().unwrap().push(api_key.to_owned());
            (self.responder)(idx, body)
        }
    }

    fn test_config(api_key: Option<&str>) -> GeminiConfig {
        GeminiConfig {
            api_key: api_key.map(str::to_owned),
            base_url: DEFAULT_GEMINI_BASE_URL.to_owned(),
            default_model: DEFAULT_GEMINI_DECISION_MODEL.to_owned(),
            connect_timeout_secs: 1,
            max_timeout_secs: 2,
            offline: false,
            circuit_breaker_threshold: 2,
            circuit_breaker_cooldown_secs: 60,
        }
    }

    #[test]
    fn missing_api_key_and_offline_and_cooldown_short_circuit_without_transport() {
        let transport = Arc::new(MockTransport::new(|_, _| {
            panic!("transport must not be called when bypassed");
        }));

        let missing_key = GeminiClient::with_transport(test_config(None), transport.clone());
        assert_eq!(
            missing_key.classify_decision_1("impl", "FAILED", "ambiguous", None),
            Err(GeminiError::MissingApiKey)
        );

        let mut offline_cfg = test_config(Some("AIzaFakeSecretKey12345"));
        offline_cfg.offline = true;
        let offline_client = GeminiClient::with_transport(offline_cfg, transport.clone());
        assert_eq!(
            offline_client.classify_decision_1("impl", "FAILED", "ambiguous", None),
            Err(GeminiError::Offline)
        );

        let cooldown_client = GeminiClient::with_transport(
            test_config(Some("AIzaFakeSecretKey12345")),
            transport.clone(),
        );
        let future = now_epoch() + 120;
        assert_eq!(
            cooldown_client.classify_decision_1("impl", "FAILED", "ambiguous", Some(future)),
            Err(GeminiError::CooldownActive {
                until_epoch: future
            })
        );
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn circuit_breaker_opens_after_consecutive_failures() {
        let transport = Arc::new(MockTransport::new(|_, _| {
            Err(GeminiError::Transport("connection timed out".into()))
        }));
        let client = GeminiClient::with_transport(
            test_config(Some("AIzaFakeSecretKey12345")),
            transport.clone(),
        );

        assert!(matches!(
            client.classify_decision_1("impl", "FAILED", "ambiguous", None),
            Err(GeminiError::Transport(_))
        ));
        assert!(matches!(
            client.classify_decision_1("impl", "FAILED", "ambiguous", None),
            Err(GeminiError::Transport(_))
        ));
        assert!(matches!(
            client.classify_decision_1("impl", "FAILED", "ambiguous", None),
            Err(GeminiError::CircuitOpen { .. })
        ));
        assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn redacts_secrets_in_outbound_prompts_and_returned_errors() {
        let secret_api_key = "AIzaSySecretKeyValue99999";
        let transport = Arc::new(MockTransport::new(move |_, _| {
            Err(GeminiError::Transport(format!(
                "curl failed for key {secret_api_key} with token ghp_supersecret1234567890"
            )))
        }));
        let client =
            GeminiClient::with_transport(test_config(Some(secret_api_key)), transport.clone());
        let err = client
            .classify_decision_1(
                "impl",
                "FAILED",
                "Bearer sk-ant-secret1234567890abcdef failed at step",
                None,
            )
            .unwrap_err();
        let err_str = err.to_string();
        assert!(
            !err_str.contains(secret_api_key),
            "err leaked api key: {err_str}"
        );
        assert!(
            !err_str.contains("ghp_supersecret"),
            "err leaked token: {err_str}"
        );

        let prompts = transport.captured_prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        assert!(
            !prompts[0].contains("sk-ant-secret1234567890abcdef"),
            "prompt leaked secret: {}",
            prompts[0]
        );
    }

    #[test]
    fn parses_decision_1_text_json_and_fallback_empty() {
        let transport = Arc::new(MockTransport::new(|idx, body| {
            assert_eq!(body["generationConfig"]["maxOutputTokens"], json!(0));
            let payload = match idx {
                0 => json!({"candidates": [{"content": {"parts": [{"text": "semantic"}]}}]}),
                1 => {
                    json!({"candidates": [{"content": {"parts": [{"text": "{\"failure_class\":\"policy\"}"}]}}]})
                }
                2 => json!({"candidates": [{"finishReason": "MAX_TOKENS", "decision": "infra"}]}),
                _ => json!({"candidates": [{"finishReason": "STOP"}]}),
            };
            Ok(GeminiHttpResponse {
                body: serde_json::to_vec(&payload).unwrap(),
            })
        }));
        let client =
            GeminiClient::with_transport(test_config(Some("AIzaFakeSecretKey12345")), transport);

        assert_eq!(
            client
                .classify_decision_1("impl", "FAILED", "weird error", None)
                .unwrap(),
            Some(FAILURE_CLASS_SEMANTIC)
        );
        assert_eq!(
            client
                .classify_decision_1("impl", "FAILED", "weird error", None)
                .unwrap(),
            Some(FAILURE_CLASS_POLICY)
        );
        assert_eq!(
            client
                .classify_decision_1("impl", "FAILED", "weird error", None)
                .unwrap(),
            Some(FAILURE_CLASS_INFRA)
        );
        assert_eq!(
            client
                .classify_decision_1("impl", "FAILED", "weird error", None)
                .unwrap(),
            None
        );
    }

    #[test]
    fn curl_config_passes_key_via_stdin_and_escapes_special_chars() {
        let cfg = build_curl_config(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-decision-1:generateContent",
            "key-\"abc\"",
            &json!({"contents": [{"parts": [{"text": "hello"}]}]}),
        )
        .unwrap();
        assert!(cfg.contains("header = \"x-goog-api-key: key-\\\"abc\\\"\""));
        assert!(!cfg.contains("key=\"abc\""));
    }
}
