//! Chaperone core library.
//!
//! The pure decision machinery: models, IR, engine, ledger, storage, cache,
//! escalation, compiler and decision orchestration (docs/repo-layout.md).
//!
//! Layering law: models -> ir | engine | ledger | storage | cache | escalation
//! | compiler | docs -> decision -> server | cli. Nothing imports upward.
//! The pure layers (models, ir, engine) do zero I/O.

pub mod cache;
pub mod canonical;
pub mod clock;
pub mod decision;
pub mod engine;
pub mod escalation;
pub mod ir;
pub mod ledger;
pub mod models;
pub mod storage;
