//! DecisionService orchestration (Flow 2 hot path, fail-closed) —
//! docs/repo-layout.md layering: models -> ... -> decision -> server | cli.
//! The service is the only layer that performs I/O (via storage/ledger seams).

pub mod service;
