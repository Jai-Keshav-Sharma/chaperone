//! Compiler providers (flows/01): the LLM client trait + the offline fixture.
//!
//! `anthropic | openai-compat | ollama | fixture` — the fixture provider
//! returns recorded responses (zero network; the offline CI path). The HTTP
//! providers are thin, local-first adapters: they send the schema-constrained
//! prompt and return raw IR text; validation/retry/trust live in the pipeline,
//! never in the client (Law 2: LLM output without human approval is inert).

/// Which provider kind is in use (config: `compiler.provider`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Anthropic,
    OpenaiCompat,
    Ollama,
    Fixture,
}

impl ProviderKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "anthropic" => Some(ProviderKind::Anthropic),
            "openai-compat" | "openai" => Some(ProviderKind::OpenaiCompat),
            "ollama" => Some(ProviderKind::Ollama),
            "fixture" => Some(ProviderKind::Fixture),
            _ => None,
        }
    }
}

/// The compiled output of one provider call: the raw policy IR text.
/// The provider NEVER activates anything — it returns bytes for the
/// pipeline to validate (Law 2: LLM output without human approval is inert).
pub struct ProviderOutput {
    /// Raw IR JSON text (schema-constrained by the prompt).
    pub ir_text: String,
    /// The model id used (provenance — policy_versions.compiler_model).
    pub model: String,
}

/// The LLM client seam. Implementations are thin: send the prompt, return
/// the text. Validation/retry/trust live in the pipeline, not the client.
pub trait CompilerProvider: Send + Sync {
    fn kind(&self) -> ProviderKind;

    /// Compile an SOP (or a re-prompt after a validation failure) into raw
    /// policy IR text. The `error_hint` is the previous validation error for
    /// the retry (wall 1: 1 retry, then reject).
    fn compile(&self, sop: &str, error_hint: Option<&str>) -> Result<ProviderOutput, String>;
}

/// The offline fixture provider: returns recorded IR for a known SOP.
/// Zero network — the CI/test path (build-plan: fixture_provider_offline).
pub struct FixtureProvider {
    /// Recorded IR text keyed by an exact SOP fragment match.
    fixture: String,
    model: String,
}

impl FixtureProvider {
    pub fn new(fixture_ir: impl Into<String>) -> Self {
        FixtureProvider {
            fixture: fixture_ir.into(),
            model: "fixture".to_string(),
        }
    }
}

impl CompilerProvider for FixtureProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Fixture
    }

    fn compile(&self, _sop: &str, _error_hint: Option<&str>) -> Result<ProviderOutput, String> {
        Ok(ProviderOutput {
            ir_text: self.fixture.clone(),
            model: self.model.clone(),
        })
    }
}

/// Shared HTTP plumbing for the cloud/local providers. One blocking `ureq`
/// agent (the compile path is offline-batch, not the decision hot path).
fn http_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(120)))
        .build()
        .new_agent()
}

/// Extract the JSON object from a model reply. Local models often wrap the IR
/// in ```json ... ``` fences or a sentence of prose, despite instructions not
/// to. This is a defensive normalizer, NOT a correctness backdoor: the
/// pipeline still strict-parses + validates whatever it extracts (Law 2 — the
/// LLM's raw output is inert until it passes the validation wall).
fn extract_json(reply: &str) -> String {
    let trimmed = reply.trim();
    // Fenced block: ```json ... ``` or ``` ... ```
    if let Some(inner) = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
    {
        let inner = inner.trim_start();
        if let Some(end) = inner.find("```") {
            return inner[..end].trim().to_string();
        }
        return inner.trim().to_string();
    }
    // No fence: find the first '{' and the matching final '}' (a JSON object).
    if let Some(start) = trimmed.find('{')
        && let Some(end) = trimmed.rfind('}')
        && end > start
    {
        return trimmed[start..=end].to_string();
    }
    trimmed.to_string()
}

/// Anthropic native Messages API (structured-output capable; we use the plain
/// completion path and rely on the prompt + strict parse + retry — the
/// `supports_json_schema` capability flag is currently false for all providers,
/// so the pipeline's strict-parse wall applies uniformly).
pub struct AnthropicProvider {
    endpoint: String,
    model: String,
    api_key: String,
}

impl AnthropicProvider {
    /// `api_key` = `x-api-key`; `model` = e.g. `claude-sonnet-4-5`.
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        AnthropicProvider {
            endpoint: std::env::var("ANTHROPIC_BASE_URL")
                .unwrap_or_else(|_| "https://api.anthropic.com".to_string()),
            model: model.into(),
            api_key: api_key.into(),
        }
    }
}

impl CompilerProvider for AnthropicProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Anthropic
    }

    fn compile(&self, sop: &str, error_hint: Option<&str>) -> Result<ProviderOutput, String> {
        let prompt = match error_hint {
            Some(h) => crate::compiler::prompts::retry_prompt(sop, h),
            None => crate::compiler::prompts::compile_prompt(sop),
        };
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": 4096,
            "temperature": 0,
            "messages": [{"role": "user", "content": prompt}],
        });
        let resp = http_agent()
            .post(&format!("{}/v1/messages", self.endpoint))
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .send_json(body)
            .map_err(|e| format!("anthropic request failed: {e}"))?;
        let json: serde_json::Value = resp
            .into_body()
            .read_json()
            .map_err(|e| format!("anthropic response parse failed: {e}"))?;
        let text = json["content"]
            .as_array()
            .and_then(|a| a.iter().find_map(|b| b["text"].as_str()))
            .ok_or_else(|| format!("anthropic: no content text: {json}"))?;
        Ok(ProviderOutput {
            ir_text: extract_json(text),
            model: self.model.clone(),
        })
    }
}

/// OpenAI-compatible chat/completions API: covers OpenAI, Gemini, Mistral,
/// Groq, DeepSeek, vLLM, LM Studio, llama.cpp server (flows/01 adapter table).
pub struct OpenaiCompatProvider {
    endpoint: String,
    model: String,
    api_key: Option<String>,
}

impl OpenaiCompatProvider {
    /// `endpoint` = the base URL (e.g. `https://api.openai.com/v1`); `model` =
    /// the model id; `api_key` optional (local servers need none).
    pub fn new(
        endpoint: impl Into<String>,
        model: impl Into<String>,
        api_key: Option<impl Into<String>>,
    ) -> Self {
        OpenaiCompatProvider {
            endpoint: endpoint.into(),
            model: model.into(),
            api_key: api_key.map(|k| k.into()),
        }
    }
}

impl CompilerProvider for OpenaiCompatProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::OpenaiCompat
    }

    fn compile(&self, sop: &str, error_hint: Option<&str>) -> Result<ProviderOutput, String> {
        let prompt = match error_hint {
            Some(h) => crate::compiler::prompts::retry_prompt(sop, h),
            None => crate::compiler::prompts::compile_prompt(sop),
        };
        let body = serde_json::json!({
            "model": self.model,
            "temperature": 0,
            "messages": [{"role": "user", "content": prompt}],
        });
        let mut req = http_agent().post(&format!("{}/chat/completions", self.endpoint));
        if let Some(k) = &self.api_key {
            req = req.header("authorization", &format!("Bearer {k}"));
        }
        let resp = req
            .send_json(body)
            .map_err(|e| format!("openai-compat request failed: {e}"))?;
        let json: serde_json::Value = resp
            .into_body()
            .read_json()
            .map_err(|e| format!("openai-compat response parse failed: {e}"))?;
        let text = json["choices"][0]["message"]["content"]
            .as_str()
            .ok_or_else(|| format!("openai-compat: no message content: {json}"))?;
        Ok(ProviderOutput {
            ir_text: extract_json(text),
            model: self.model.clone(),
        })
    }
}

/// Build a provider from the environment (the single construction path shared
/// by the CLI `policy compile` and the server `/v1/policies/compile` route).
/// Precedence for `OpenaiCompat`: Groq → Gemini → OpenAI, resolved from
/// `GROQ_API_KEY` / `GEMINI_API_KEY` / `OPENAI_API_KEY` (+ base URLs and
/// `CHAPERONE_*_MODEL` model ids). Ollama is local-first (default
/// `http://127.0.0.1:11434`, model `qwen2.5-coder:7b`). The fixture provider is
/// rejected here — it needs a recorded sibling response and is CLI/CI-only.
pub fn build_provider(kind: ProviderKind) -> Result<Box<dyn CompilerProvider>, String> {
    match kind {
        ProviderKind::Anthropic => {
            let key = env_required("ANTHROPIC_API_KEY")?;
            let model = env_or("CHAPERONE_ANTHROPIC_MODEL", "claude-sonnet-4-5");
            Ok(Box::new(AnthropicProvider::new(key, model)))
        }
        ProviderKind::OpenaiCompat => {
            if let Some(key) = env_opt("GROQ_API_KEY") {
                let endpoint = env_or("GROQ_BASE_URL", "https://api.groq.com/openai/v1");
                let model = env_or("CHAPERONE_GROQ_MODEL", "llama-3.3-70b-versatile");
                return Ok(Box::new(OpenaiCompatProvider::new(
                    endpoint,
                    model,
                    Some(key),
                )));
            }
            if let Some(key) = env_opt("GEMINI_API_KEY") {
                let endpoint = env_or(
                    "GEMINI_BASE_URL",
                    "https://generativelanguage.googleapis.com/v1beta/openai",
                );
                let model = env_or("CHAPERONE_GEMINI_MODEL", "gemini-2.0-flash");
                return Ok(Box::new(OpenaiCompatProvider::new(
                    endpoint,
                    model,
                    Some(key),
                )));
            }
            let endpoint = env_or("OPENAI_BASE_URL", "https://api.openai.com/v1");
            let model = env_or("CHAPERONE_OPENAI_MODEL", "gpt-4.1");
            let key = env_opt("OPENAI_API_KEY");
            Ok(Box::new(OpenaiCompatProvider::new(endpoint, model, key)))
        }
        ProviderKind::Ollama => {
            let endpoint = env_or("OLLAMA_BASE_URL", "http://127.0.0.1:11434");
            let model = env_or("CHAPERONE_OLLAMA_MODEL", "qwen2.5-coder:7b");
            Ok(Box::new(OllamaProvider::new(model, endpoint)))
        }
        ProviderKind::Fixture => {
            Err("fixture provider needs a recorded response and is not available here".to_string())
        }
    }
}

fn env_required(key: &str) -> Result<String, String> {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{key} is required"))
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn env_or(key: &str, default: &str) -> String {
    env_opt(key).unwrap_or_else(|| default.to_string())
}

/// Ollama native /api/chat (local models — the privacy path, flows/01).
pub struct OllamaProvider {
    endpoint: String,
    model: String,
}

impl OllamaProvider {
    /// `endpoint` defaults to `http://127.0.0.1:11434`.
    pub fn new(model: impl Into<String>, endpoint: impl Into<String>) -> Self {
        OllamaProvider {
            endpoint: endpoint.into(),
            model: model.into(),
        }
    }
}

impl CompilerProvider for OllamaProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Ollama
    }

    fn compile(&self, sop: &str, error_hint: Option<&str>) -> Result<ProviderOutput, String> {
        let prompt = match error_hint {
            Some(h) => crate::compiler::prompts::retry_prompt(sop, h),
            None => crate::compiler::prompts::compile_prompt(sop),
        };
        let body = serde_json::json!({
            "model": self.model,
            "stream": false,
            "messages": [{"role": "user", "content": prompt}],
        });
        let resp = http_agent()
            .post(&format!("{}/api/chat", self.endpoint))
            .send_json(body)
            .map_err(|e| format!("ollama request failed: {e}"))?;
        let json: serde_json::Value = resp
            .into_body()
            .read_json()
            .map_err(|e| format!("ollama response parse failed: {e}"))?;
        let text = json["message"]["content"]
            .as_str()
            .ok_or_else(|| format!("ollama: no message content: {json}"))?;
        Ok(ProviderOutput {
            ir_text: extract_json(text),
            model: self.model.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_provider_offline() {
        let p = FixtureProvider::new(r#"{"ir_version":"1"}"#);
        assert_eq!(p.kind(), ProviderKind::Fixture);
        let out = p.compile("some sop", None).expect("offline");
        assert_eq!(out.ir_text, r#"{"ir_version":"1"}"#);
        assert_eq!(out.model, "fixture");
    }

    #[test]
    fn provider_kind_parse() {
        assert_eq!(
            ProviderKind::parse("anthropic"),
            Some(ProviderKind::Anthropic)
        );
        assert_eq!(
            ProviderKind::parse("openai-compat"),
            Some(ProviderKind::OpenaiCompat)
        );
        assert_eq!(ProviderKind::parse("ollama"), Some(ProviderKind::Ollama));
        assert_eq!(ProviderKind::parse("fixture"), Some(ProviderKind::Fixture));
        assert_eq!(ProviderKind::parse("bogus"), None);
    }

    #[test]
    fn extract_json_handles_fences_and_prose() {
        // Fenced.
        assert_eq!(extract_json("```json\n{\"a\":1}\n```"), "{\"a\":1}");
        assert_eq!(extract_json("```\n{\"a\":1}\n```"), "{\"a\":1}");
        // Leading prose.
        assert_eq!(extract_json("Here it is: {\"a\":1} done"), "{\"a\":1}");
        // Plain object passes through.
        assert_eq!(extract_json("{\"a\":1}"), "{\"a\":1}");
        // Nested braces survive.
        assert_eq!(extract_json("{\"a\":{\"b\":2}}"), "{\"a\":{\"b\":2}}");
    }
}
