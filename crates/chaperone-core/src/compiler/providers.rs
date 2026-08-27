//! Compiler providers (flows/01): the LLM client trait + the offline fixture.
//!
//! `anthropic | openai-compat | ollama | fixture` — the fixture provider
//! returns recorded responses (zero network; the offline CI path). The HTTP
//! clients (anthropic / async-openai / ollama) are thin adapters over the
//! trait; their concrete wiring lands with the network stack.

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

/// A stub for the HTTP-backed providers. The concrete HTTP clients
/// (anthropic / async-openai / ollama) are wired here; until the network
/// stack lands they fail loudly (the pipeline is fixture-testable).
pub struct HttpProviderStub {
    kind: ProviderKind,
}

impl HttpProviderStub {
    pub fn new(kind: ProviderKind) -> Self {
        HttpProviderStub { kind }
    }
}

impl CompilerProvider for HttpProviderStub {
    fn kind(&self) -> ProviderKind {
        self.kind
    }

    fn compile(&self, _sop: &str, _error_hint: Option<&str>) -> Result<ProviderOutput, String> {
        Err(format!(
            "{:?} HTTP client not yet wired — use the fixture provider for offline runs",
            self.kind
        ))
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
}
