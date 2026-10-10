# Deterministic policies

GateShield evaluates validated policy snapshots before provider forwarding and after output inspection. Conditions are typed matches over request and security context fields: application, user, agent, model, environment, provider type, data classification, tool presence, deterministic findings, and semantic risk score. `semantic_risk_min` matches when the collected score is greater than or equal to its threshold. There are no arbitrary expressions or regular expressions in policy definitions. The optional classifier cannot issue an allow decision; the policy engine remains authoritative.

## Modes

- `ENFORCE`: a matching effect contributes to the decision.
- `MONITOR`: records the match and effect in the request event; it does not change the decision.
- `OFF`: skips evaluation for that policy.

Only an explicitly activated version is evaluated. New and revised versions start as `DRAFT`. Activation retires the previous active version, and any retained version can be activated to roll back.

## Decision behavior

An enforced `BLOCK` dominates `REQUIRE_APPROVAL`; both prevent provider forwarding or withhold a model response, depending on the evaluation stage. `ALLOW` does not override either. Within the same effect, lower numeric `priority` wins, then policy ID breaks ties. `REDACT` is implemented for output inspection and returns the sanitized response; on input it remains an unsupported action and the gateway fails closed. `ALLOW_WITH_RESTRICTIONS` remains unsupported and fails closed at either stage.

When no `ENFORCE` policy matches, the request is allowed. Matching monitor-only policies appear in `matched_policies` and `violations`. If no active enforce policy exists for a request, no additional restrictions are inferred.

## Definition example

```python
PolicyDefinition(
    id="restricted-external-provider",
    description="Restricted data cannot use an external provider.",
    effect=Decision.BLOCK,
    mode=PolicyMode.ENFORCE,
    conditions=PolicyConditions(
        data_classification=DataClassification.RESTRICTED,
        provider_type=ProviderType.EXTERNAL,
    ),
)
```

Definitions reject unknown fields and empty conditions. The `PolicyRepository` supports draft creation, revision, activation, retirement, history, and rollback. There is no unauthenticated management endpoint; administrative API access belongs with server-side RBAC.

Example classifier triage policy:

```python
PolicyDefinition(
    id="triage-high-semantic-risk",
    description="Block high semantic risk when classifier enforcement is enabled.",
    effect=Decision.BLOCK,
    mode=PolicyMode.ENFORCE,
    conditions=PolicyConditions(semantic_risk_min=85),
)
```

Policy evaluation is deterministic and does not call an LLM. If loading or validating active policy data fails, request evaluation raises an error and the gateway denies forwarding.
