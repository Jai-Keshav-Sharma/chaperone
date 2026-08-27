//! The OFFLINE NL→Policy-IR compiler (Phase 11, flows/01).
//!
//! The LLM lives ONLY here — never in the decision path (Law 2). The pipeline:
//! provider (anthropic | openai-compat | ollama | fixture) → schema-constrained
//! IR → validation (wall 1, 1 retry) → transpile (wall 2) → lint (conflict
//! report) → HUMAN REVIEW. NEVER auto-activates: activation is a separate,
//! human-gated step (the trust loop).

pub mod pipeline;
pub mod prompts;
pub mod providers;

pub use pipeline::{CompileError, CompileResult, compile_sop};
pub use providers::{CompilerProvider, FixtureProvider, ProviderKind};
