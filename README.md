# ContainOps

Give security agents authority to contain a specific incident.

Bounded incident containment for security teams. Agents gather evidence and propose containment. A human approves. The tool executes and then verifies its own effect.

No dependencies. Needs Node 18 or later.

```bash
npm test        # 12 tests
npm run demo    # full scenario, prints the case timeline
npm start       # HTTP API on :8080, case timeline UI at /ui
```

## What the MVP contains

| Piece | File |
|---|---|
| Simulated compromised workload (stolen session token replayed, then 25 MB exfil) | `src/simulator.js` |
| Simulated enforcement plane (session store, workload network policy) | `src/env.js` |
| Event ingestion: validation, dedupe, two detection rules, case opening | `src/ingest.js` |
| Tool 1: `session.revoke` | `src/tools/revoke-session.js` |
| Tool 2: `workload.isolate` | `src/tools/isolate-workload.js` |
| Propose, approve, execute, verify lifecycle | `src/containment.js` |
| Case timeline (append-only audit record) and proposals | `src/cases.js`, `src/ui.js` |

## How authority is bounded

- **Scope.** A case's scope is the affected workload and the sessions on it. A proposal that targets anything else is refused with 403.
- **Two roles.** Agents (`agent:*`) can only propose. Approval needs a human identity, and the proposer cannot approve their own proposal.
- **No execution without approval.** Executing a proposal that is not `approved` returns 409. A proposal can be executed once.
- **Two tools only.** Each declares its target, a read-only plan with blast radius, the mutation, and a separate verification step.
- **Verification.** After execution the tool checks the effect: the session no longer authorizes requests, or the workload is isolated and an external egress probe is blocked. A failed check marks the proposal `failed`.
- **Audit.** Every detection, proposal, decision, execution and verification is a timeline entry on the case.

## HTTP API

| Method and path | Purpose |
|---|---|
| `POST /events` | Ingest one event or an array. Required: `id`, `ts`, `source`, `type` |
| `GET /cases`, `GET /cases/:id` | List cases, or fetch one with timeline and proposals |
| `POST /cases/:id/proposals` | `{tool, params, proposer, rationale}` |
| `POST /proposals/:id/approve` | `{approver}` |
| `POST /proposals/:id/reject` | `{approver, reason}` |
| `POST /proposals/:id/execute` | `{actor}` |
| `POST /simulate` | Provision the demo workload and run the compromise |
| `GET /environment` | Current simulated sessions and workloads |
| `GET /ui` | HTML case list with timelines |

## Known limits

- State is in memory. A restart clears cases and the environment.
- The environment is simulated. Real IdP and orchestrator adapters would implement the same `execute` and `verify` contract in `src/tools/`.
- There is no authentication on the API. The approver identity is taken from the request body, so put real authentication in front of it before any non-demo use.
- Detection is two fixed rules. The point of the MVP is the containment loop, not detection quality.
- Repeated detections each add a timeline entry, so a long incident gets noisy.
