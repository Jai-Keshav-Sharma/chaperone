//! Policy admin routes (docs/api-contracts.md frozen paths + the UI compile
//! path).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::auth;
use crate::error;
use crate::state::AppState;

/// GET /v1/policies — list policy shells.
#[derive(Serialize)]
pub struct PolicyShell {
    pub policy_id: String,
    pub name: String,
    pub active_version: Option<i64>,
}

async fn auth_ok(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    auth::authenticate(&state.store, auth::bearer_header(headers))
        .await
        .map(|_| ())
}

/// POST /v1/policies/compile — ingest a document (md/txt/pdf/docx/html) and
/// compile it into Policy IR via the configured LLM provider. Returns the
/// validated IR + Cedar + conflict report for human review. NEVER activates
/// (Law 2: LLM output is inert until a separate human-gated activate).
#[derive(serde::Deserialize)]
pub struct CompileBody {
    /// Raw document bytes (the UI uploads the file).
    pub document: Vec<u8>,
    /// File name (drives the DocumentParser format dispatch).
    pub filename: String,
    /// Provider kind: ollama | openai-compat | anthropic.
    #[serde(default = "default_provider")]
    pub provider: String,
}

fn default_provider() -> String {
    "ollama".to_string()
}

#[derive(serde::Serialize)]
pub struct CompileResponse {
    pub policy: chaperone_core::models::ir::Policy,
    pub cedar_text: String,
    pub conflict_report: String,
    pub model: String,
}

pub async fn compile_policy(
    State(_state): State<AppState>,
    headers: HeaderMap,
    body: Json<CompileBody>,
) -> Response {
    if let Err(b) = auth_ok(&_state, &headers).await {
        return *b;
    }
    let kind = match chaperone_core::compiler::ProviderKind::parse(&body.provider) {
        Some(k) => k,
        None => {
            return error::malformed(format!(
                "unknown provider {:?} (ollama|openai-compat|anthropic)",
                body.provider
            ));
        }
    };
    // Ingest the document (DocumentParser dispatches on extension).
    let filename = body.filename.clone();
    let document = body.document.clone();
    let parse = tokio::task::spawn_blocking(move || {
        let parser = chaperone_core::compiler::document::ExtensionParser::for_path(&filename);
        parser.parse(&document)
    })
    .await
    .map_err(|_| {
        error::gate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            chaperone_core::models::errors::ErrorCode::MalformedRequest,
            "document parse task failed",
        )
    });
    let doc = match parse {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => return error::malformed(format!("cannot parse document: {e}")),
        Err(resp) => return resp,
    };

    // Build the provider + compile (blocking ureq on a blocking thread).
    let provider = match chaperone_core::compiler::build_provider(kind) {
        Ok(p) => p,
        Err(e) => {
            return error::gate_error(
                StatusCode::BAD_REQUEST,
                chaperone_core::models::errors::ErrorCode::MalformedRequest,
                e,
            );
        }
    };
    let sop = doc.text;
    let sop_for_storage = sop.clone();
    let result = tokio::task::spawn_blocking(move || {
        chaperone_core::compiler::compile_sop(provider.as_ref(), &sop)
    })
    .await
    .map_err(|_| {
        error::gate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            chaperone_core::models::errors::ErrorCode::MalformedRequest,
            "compile task failed",
        )
    });

    match result {
        Ok(Ok(mut r)) => {
            // Persist as an inert DRAFT (Law 2: LLM output is never active until
            // a separate human-gated activate). Assign the real version number
            // and return it so the UI activates exactly this version.
            let ir_json = serde_json::to_string(&r.policy).unwrap_or_else(|_| "{}".to_string());
            let policy_hash =
                chaperone_core::canonical::sha256_hex(&chaperone_core::canonical::canonical_dumps(
                    &serde_json::from_str::<serde_json::Value>(&ir_json)
                        .unwrap_or(serde_json::Value::Null),
                ));
            let policy_id = r.policy.policy_id.clone();
            let version = _state
                .store
                .list_policy_versions(&policy_id)
                .await
                .map(|rows| rows.iter().map(|v| v.version).max().unwrap_or(0) + 1)
                .unwrap_or(1);
            r.policy.version = version as u32;

            if let Err(e) = _state
                .store
                .upsert_policy(&policy_id, &r.policy.description, None)
                .await
            {
                return error::gate_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    chaperone_core::models::errors::ErrorCode::PolicyNotFound,
                    format!("upsert policy failed: {e}"),
                );
            }
            if let Err(e) = _state
                .store
                .insert_policy_version(&chaperone_core::storage::store::PolicyVersionRow {
                    policy_id: policy_id.clone(),
                    version,
                    status: "draft".into(),
                    raw_sop_text: Some(sop_for_storage.clone()),
                    ir_json,
                    cedar_text: r.cedar_text.clone(),
                    policy_hash,
                    conflict_report: Some(r.conflict_report.clone()),
                    test_report: None,
                    compiler_model: Some(r.model.clone()),
                    created_by: Some("dashboard".into()),
                    approved_by: None, // activation requires approval
                    created_at: chrono::Utc::now().to_rfc3339(),
                    activated_at: None,
                })
                .await
            {
                return error::gate_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    chaperone_core::models::errors::ErrorCode::PolicyNotFound,
                    format!("draft insert failed: {e}"),
                );
            }

            (
                StatusCode::OK,
                Json(CompileResponse {
                    policy: r.policy,
                    cedar_text: r.cedar_text,
                    conflict_report: r.conflict_report,
                    model: r.model,
                }),
            )
                .into_response()
        }
        Ok(Err(e)) => error::gate_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            chaperone_core::models::errors::ErrorCode::MalformedRequest,
            e.to_string(),
        ),
        Err(resp) => resp,
    }
}

pub async fn list_policies(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(b) = auth_ok(&state, &headers).await {
        return *b;
    }
    match state.store.list_policies().await {
        Ok(rows) => {
            let out: Vec<PolicyShell> = rows
                .into_iter()
                .map(|r| PolicyShell {
                    policy_id: r.policy_id,
                    name: r.name,
                    active_version: r.active_version,
                })
                .collect();
            (StatusCode::OK, Json(out)).into_response()
        }
        Err(_) => error::gate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            chaperone_core::models::errors::ErrorCode::PolicyNotFound,
            "list failed",
        ),
    }
}

/// GET /v1/policies/{id} — the active policy.
pub async fn get_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(b) = auth_ok(&state, &headers).await {
        return *b;
    }
    match state.store.get_active_policy(&id).await {
        Ok(Some(row)) => (StatusCode::OK, Json(row)).into_response(),
        _ => error::not_found(format!("policy {id}")),
    }
}

/// GET /v1/policies/{id}/versions — all versions of a policy.
pub async fn list_versions(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(b) = auth_ok(&state, &headers).await {
        return *b;
    }
    match state.store.list_policy_versions(&id).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(_) => error::not_found(format!("policy {id}")),
    }
}

/// GET /v1/policies/{id}/versions/{version}
pub async fn get_version(
    State(state): State<AppState>,
    Path((id, version)): Path<(String, i64)>,
    headers: HeaderMap,
) -> Response {
    if let Err(b) = auth_ok(&state, &headers).await {
        return *b;
    }
    match state.store.get_policy_version(&id, version).await {
        Ok(Some(row)) => (StatusCode::OK, Json(row)).into_response(),
        _ => error::not_found(format!("policy {id} v{version}")),
    }
}

/// POST /v1/policies/{id}/activate {version} — activate a version (admin).
#[derive(serde::Deserialize)]
pub struct ActivateBody {
    pub version: i64,
}

pub async fn activate_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Json<ActivateBody>,
) -> Response {
    let principal = match auth::authenticate(&state.store, auth::bearer_header(&headers)).await {
        Ok(p) => p,
        Err(b) => return *b,
    };
    if !principal.is_admin {
        return error::gate_error(
            StatusCode::FORBIDDEN,
            chaperone_core::models::errors::ErrorCode::AgentKeyUnknown,
            "admin key required",
        );
    }
    match state.store.activate_policy_version(&id, body.version).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"activated": true}))).into_response(),
        Err(_) => error::not_found(format!("policy {id} v{}", body.version)),
    }
}
