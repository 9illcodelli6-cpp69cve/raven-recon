//! RAVEN Policy Bridge — JSON-over-stdin/stdout interface to the Rust Trusted Core.
//!
//! Protocol:
//!   stdin:  one JSON IpcRequest (single line or multi-line, EOF-terminated)
//!   stdout: one JSON IpcResponse (single line)
//!   exit 0: normal (even for DENY decisions)
//!   exit 1: protocol error (malformed input, version mismatch)
//!
//! SECURITY INVARIANTS:
//!   - Stdin bytes are treated as hostile input.
//!   - A parse failure always produces DENY (fail-closed).
//!   - This binary performs NO network access.
//!   - This binary performs NO file writes.
//!   - This binary does NOT execute any subprocess.
//!   - Emergency stop state is per-process; bridged from Python flag in request.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::arithmetic_side_effects)]

use std::io::{self, Read};
use std::process;

use raven_core::action::{Provenance, RiskClass};
use raven_core::{ActionRequest, Capability, CapabilitySet, ResourceBudget, WorkspaceContext};
use raven_ipc::message::{
    EvaluateActionParams, IpcError, IpcPayload, IpcRequest, IpcResponse, IpcResponsePayload,
    IPC_SCHEMA_VERSION,
};
use raven_policy::scope_policy::ScopePolicy;
use raven_policy::{EmergencyStop, PolicyEngine};

fn main() {
    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() {
        emit_protocol_error("Failed to read stdin");
        process::exit(1);
    }

    let req: IpcRequest = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => {
            emit_protocol_error(&format!("Malformed IpcRequest: {e}"));
            process::exit(1);
        }
    };

    if req.schema_version != IPC_SCHEMA_VERSION {
        emit_protocol_error(&format!(
            "Schema version mismatch: got {}, expected {}",
            req.schema_version, IPC_SCHEMA_VERSION
        ));
        process::exit(1);
    }

    let response = handle_request(&req);
    match serde_json::to_string(&response) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            emit_protocol_error(&format!("Failed to serialize response: {e}"));
            process::exit(1);
        }
    }
}

fn handle_request(req: &IpcRequest) -> IpcResponse {
    match &req.payload {
        IpcPayload::HealthCheck => IpcResponse {
            schema_version: IPC_SCHEMA_VERSION,
            request_id: req.message_id,
            payload: IpcResponsePayload::Ok,
        },

        IpcPayload::CheckEmergencyStop => IpcResponse {
            schema_version: IPC_SCHEMA_VERSION,
            request_id: req.message_id,
            payload: IpcResponsePayload::EmergencyStopStatus {
                active: EmergencyStop::is_active(),
            },
        },

        IpcPayload::TriggerEmergencyStop => {
            EmergencyStop::trigger();
            IpcResponse {
                schema_version: IPC_SCHEMA_VERSION,
                request_id: req.message_id,
                payload: IpcResponsePayload::EmergencyStopStatus { active: true },
            }
        }

        IpcPayload::EvaluateAction(params) => evaluate_action(req, params),

        // Non-exhaustive: any future variant is denied fail-closed.
        _ => deny_response(
            req,
            "UNKNOWN_PAYLOAD",
            "Unknown payload type — denied fail-closed",
        ),
    }
}

fn evaluate_action(req: &IpcRequest, params: &EvaluateActionParams) -> IpcResponse {
    let workspace_id = &params.workspace_id;
    let capability_str = params.capability.as_str();
    let destination = params.destination.as_str();
    let method = params.method.as_str();
    let reason = params.reason.as_str();
    let risk_class_str = params.risk_class.as_str();
    let provenance_str = params.provenance.as_str();

    // Parse capability
    let capability = match parse_capability(capability_str) {
        Some(c) => c,
        None => {
            return deny_response(
                req,
                "UNKNOWN_CAPABILITY",
                &format!("Unknown capability: {capability_str:?}"),
            );
        }
    };

    // Parse risk class
    let risk_class = match parse_risk_class(risk_class_str) {
        Some(r) => r,
        None => {
            return deny_response(
                req,
                "MALFORMED_REQUEST",
                &format!("Unknown risk_class: {risk_class_str:?}"),
            );
        }
    };

    // Parse provenance
    let provenance = parse_provenance(provenance_str);

    // Build capability set
    let mut caps = CapabilitySet::new();
    for cap_str in &params.granted_capabilities {
        if let Some(c) = parse_capability(cap_str.as_str()) {
            caps.grant(c);
        }
        // Unknown strings silently ignored — fail-closed (not granted)
    }

    // Build scope policy
    let mut scope = ScopePolicy::new();
    for host in &params.allowed_hosts {
        scope.allowed_hosts.insert(host.clone());
    }

    // Build workspace context (temp_dir placeholder — workspace_root used only for
    // file-path validation, not exercised by HttpRead/HttpStateChange actions)
    let workspace = WorkspaceContext::new(workspace_id.as_str(), std::env::temp_dir());

    let engine = PolicyEngine::new(caps, workspace, scope);

    let action_request = ActionRequest {
        action_id: uuid::Uuid::new_v4(),
        workspace_id: workspace_id.to_owned(),
        required_capability: capability,
        destination: destination.to_owned(),
        method: method.to_owned(),
        reason: reason.to_owned(),
        budget: ResourceBudget::default(),
        provenance,
        risk_class,
    };

    let decision = engine.evaluate(&action_request);

    let (allowed, reason_str, message) = match &decision {
        raven_core::ActionDecision::Allow { reason, .. } => {
            (true, format!("{reason:?}"), String::new())
        }
        raven_core::ActionDecision::Deny {
            reason, message, ..
        } => (false, format!("{reason:?}"), message.clone()),
        raven_core::ActionDecision::RequireApproval {
            reason, message, ..
        } => (
            false,
            format!("RequireApproval:{reason:?}"),
            message.clone(),
        ),
    };

    IpcResponse {
        schema_version: IPC_SCHEMA_VERSION,
        request_id: req.message_id,
        payload: IpcResponsePayload::Decision {
            allowed,
            reason: reason_str,
            message,
        },
    }
}

fn parse_capability(s: &str) -> Option<Capability> {
    match s {
        "HttpRead" => Some(Capability::HttpRead),
        "HttpStateChange" => Some(Capability::HttpStateChange),
        "LocalFixtureConnect" => Some(Capability::LocalFixtureConnect),
        "ProcessAnalyzer" => Some(Capability::ProcessAnalyzer),
        "FileReadWorkspace" => Some(Capability::FileReadWorkspace),
        "FileWriteWorkspace" => Some(Capability::FileWriteWorkspace),
        "CallbackCollector" => Some(Capability::CallbackCollector),
        "ReportExport" => Some(Capability::ReportExport),
        "ScopeRead" => Some(Capability::ScopeRead),
        "ScopeWrite" => Some(Capability::ScopeWrite),
        _ => None,
    }
}

fn parse_risk_class(s: &str) -> Option<RiskClass> {
    match s {
        "SafeReadOnly" => Some(RiskClass::SafeReadOnly),
        "LowRiskStateChange" => Some(RiskClass::LowRiskStateChange),
        "Sensitive" => Some(RiskClass::Sensitive),
        "Destructive" => Some(RiskClass::Destructive),
        "Exfiltrative" => Some(RiskClass::Exfiltrative),
        _ => None,
    }
}

fn parse_provenance(s: &str) -> Provenance {
    match s {
        "Scheduler" => Provenance::Scheduler,
        "MlPlanner" => Provenance::MlPlanner,
        "ResearcherDirect" => Provenance::ResearcherDirect,
        "SafeLab" => Provenance::SafeLab,
        _ => Provenance::TestHarness,
    }
}

fn deny_response(req: &IpcRequest, code: &str, message: &str) -> IpcResponse {
    IpcResponse {
        schema_version: IPC_SCHEMA_VERSION,
        request_id: req.message_id,
        payload: IpcResponsePayload::Error(IpcError {
            code: code.to_owned(),
            message: message.to_owned(),
        }),
    }
}

fn emit_protocol_error(msg: &str) {
    // Write protocol error to stderr; stdout remains clean for the caller.
    eprintln!("RAVEN-BRIDGE PROTOCOL ERROR: {msg}");
}
