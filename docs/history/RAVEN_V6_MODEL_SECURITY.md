# RAVEN V6 — Model Security

## Safe Loading (Gate 8)

- `torch.load(..., weights_only=True)` — never deserializes arbitrary Python objects
- Model reconstructed from state_dict fields (input_dim, hidden_dim, dropout, arch)
- SHA-256 of weights.pt verified against model_card.json before inference
- Models loaded only from trusted RAVEN-controlled paths
- Target/workspace data cannot replace the active model

## Inference Safety (Gate 9)

- `InferenceResult` is a frozen dataclass
- `is_advisory = True` always
- `sets_verification_status = False` always
- ML inference NEVER modifies `finding.verification_status`
- ML probability is advisory — researcher decides verification

## ML Cannot Bypass Policy (Gate 10)

Proven at runtime (Gate 10):
- ML probability=1.0 + DESTRUCTIVE action → DENIED (RiskClassBlocked)
- ML probability=1.0 + out-of-scope destination → DENIED (DestinationOutOfScope)
- ML probability=1.0 + EXFILTRATIVE action → DENIED (RiskClassBlocked)

## Model Status Ladder

Models remain `DEVELOPMENT_ONLY_SYNTHETIC` until:
1. Real human-reviewed labels exist
2. Researcher trains a challenger explicitly
3. Challenger evaluated on held-out real data
4. Researcher explicitly promotes to CANDIDATE, then PRODUCTION

Current model status: `DEVELOPMENT_ONLY_SYNTHETIC` (REAL_HUMAN_LABEL_COUNT=0)

## Training Security (Gate 35)

Training:
- Does NOT contact external AI APIs
- Does NOT upload observations, labels, or evidence
- Remains local to this machine
- Synthetic dev data stays in-process — never sent externally
