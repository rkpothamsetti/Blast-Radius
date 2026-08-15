# Blast Radius — Implementation Plan

## Goal

Build a hackathon-ready web app that simulates the downstream access available after an employee account compromise, scores the resulting blast radius, identifies high-risk attack paths, and recommends the smallest high-leverage permission removals.

## Chosen Frameworks and Services

| Layer | Framework / service | Purpose |
| --- | --- | --- |
| Frontend | React + TypeScript + Vite | Fast, typed single-page application development. |
| Graph visualization | `react-force-graph-2d` | Interactive force-directed access graph with node/edge highlighting. |
| Charts | Recharts | Impact-score breakdown and before/after remediation charts. |
| Styling | Tailwind CSS | Rapid, consistent responsive UI construction. |
| Backend | Python 3.12 + FastAPI + Pydantic | Typed API layer, validation, and OpenAPI documentation. |
| Graph algorithms | NetworkX | Directed reachability, weighted paths, and minimum edge-cut analysis. |
| Persistence for MVP | Validated in-memory JSON/CSV uploads | Dynamic user-provided graphs with no external tenant access. |
| Optional persistence later | Neo4j | Queryable graph storage once graph size or connector volume requires it. |
| AI analysis | OpenAI Python SDK + Responses API | Mandatory executive-readable risk analysis and remediation explanation from computed results. |
| Testing | Pytest; Vitest + React Testing Library; Playwright | Unit, component, API, and end-to-end confidence. |
| Quality | Ruff, mypy, ESLint, Prettier | Formatting, linting, and type checks. |

## Architecture

```text
Uploaded JSON/CSV access graphs
        |
        v
FastAPI ingestion/validation --> NetworkX analysis engine --> API response
                                      |                         |
                                      v                         v
                              mandatory OpenAI analysis   React + TypeScript UI
                                                                |
                                                                v
                                             Force graph, paths, score, what-if controls
```

The graph engine is the source of truth for reachability, score, paths, and minimum cuts. OpenAI is a mandatory stage in each completed simulation: it turns the sanitized calculated result into a structured executive analysis and prioritized analyst-review recommendations. It does not invent graph facts or execute changes.

## Repository Layout

```text
backend/
  app/
    api/routes/             # upload, simulate, remediate, analyze, health
    core/                   # settings, logging, error handling
    domain/                 # Pydantic models and score policy
    services/               # graph analysis and mandatory OpenAI analysis service
    fixtures/               # synthetic test data only; never shown as the data source of record
  tests/
frontend/
  src/
    api/                    # typed HTTP client
    components/             # graph, side panel, remediation checklist
    features/simulation/    # state and transformations
    types/
  tests/
docs/
```

## Delivery Phases

### Phase 0 — Foundation

1. Scaffold `backend` and `frontend` projects.
2. Add environment-based configuration and `.env.example`; do not commit `.env` files or provider keys.
3. Add lint, type-check, test, and build scripts to CI.
4. Add the synthetic-data disclaimer in the UI and README.

**Exit criteria:** both applications start locally; health endpoint, linting, type checks, and empty test suites pass.

### Phase 1 — Graph Domain and Upload Validation

1. Define node types: employee, identity group, application, resource, credential, and cloud resource.
2. Define allowed edge relations and validate that every edge endpoint exists.
3. Define JSON and CSV templates for nodes and edges, then validate uploads for schema, size, relation allowlist, duplicate IDs, and missing endpoints.
4. Keep small synthetic graphs only as automated test fixtures; user uploads are the runtime source of truth.
5. Assign a documented sensitivity scale and deterministic risk boosts for PII and production.

**Exit criteria:** invalid uploads are rejected with actionable errors; test fixtures cover at least one critical access chain and one benign path.

### Phase 2 — Deterministic Analysis Engine

Implement a pure `GraphAnalysisService` with no HTTP or LLM dependencies.

1. Calculate descendants of a selected employee using directed traversal.
2. Compute a normalized 0–100 impact score and LOW/MEDIUM/HIGH/CRITICAL verdict.
3. Return top critical paths, ranked by target sensitivity and cumulative path risk.
4. Create a virtual critical-assets sink and calculate the minimum edge cut from the compromised employee to the selected top-K sensitive assets.
5. Apply a proposed set of revoked edges in memory and compute before/after impact and reduction percentage.

**Exit criteria:** unit tests verify cycles, disconnected nodes, multiple critical targets, no reachable sensitive target, and remediation reduction.

### Phase 3 — API

Implement versioned, typed endpoints:

| Endpoint | Responsibility |
| --- | --- |
| `POST /api/v1/graphs` | Upload and validate a JSON or CSV access graph. |
| `GET /api/v1/simulate/{employee_id}` | Return reachability, score, verdict, and critical paths. |
| `POST /api/v1/remediate` | Preview selected permission revocations; never alter uploaded graph data. |
| `POST /api/v1/analyze` | Call OpenAI and return validated, structured risk analysis based on a simulation result. |
| `GET /health` | Liveness/readiness status without sensitive configuration. |

Use explicit error responses, request-size limits, CORS allowlists for local development, and rate limiting for the OpenAI analysis endpoint. Require `OPENAI_API_KEY` at startup outside development; never send raw uploaded files to OpenAI.

**Exit criteria:** OpenAPI schema is accurate; endpoint tests cover success, malformed identifiers, invalid edges, missing OpenAI configuration, and OpenAI service errors.

### Phase 4 — Frontend Experience

1. Add an organization and employee selector.
2. Render the directed force graph: compromised node red/pulsing, reachable nodes color-coded by depth/risk, all others muted.
3. Add an accessible side panel with verdict badge, impact score, key paths, and narrative.
4. Present minimum-cut permission recommendations as a checklist.
5. On each toggle, call the remediation preview and update graph state, score, and percentage reduction.
6. Make critical information available as text/table content so the experience does not rely solely on color or animation.

**Exit criteria:** the complete demo scenario can be operated by keyboard and works at desktop presentation size.

### Phase 5 — Mandatory OpenAI Analysis

1. Use the official OpenAI Python SDK and Responses API, configured exclusively with `OPENAI_API_KEY`.
2. Send only allowlisted node labels, relation names, computed risk values, and recommended edges; never send the raw upload or unnecessary PII.
3. Require Structured Outputs with a strict JSON schema: verdict, justification, 3–5 attacker steps, and up to three recommendations that reference existing computed edges only.
4. Validate the returned schema and verify every referenced node and edge against the deterministic simulation result before display.
5. Treat unavailable, malformed, refused, or rate-limited OpenAI responses as an explicit failed-analysis state with retry guidance; do not silently substitute a fake AI response.
6. Display the analysis as an analyst-review aid and preserve graph-engine calculations as authoritative.

**Exit criteria:** every successful simulation includes a validated OpenAI analysis; missing configuration or provider failure is visible and test-covered.

### Phase 6 — Polish and Demo Readiness

1. Add loading, empty, error, and no-critical-path states.
2. Add a reset control and a prepared demo script for two different organizations.
3. Run end-to-end tests for selecting an employee, simulating, revoking the suggested permissions, and observing a lower score.
4. Document setup, architecture, scoring assumptions, and known MVP limitations.

**Exit criteria:** a clean checkout can upload a sample graph, run the complete OpenAI-backed simulation, and make no external tenant connection.

## Scoring Policy

Keep the policy visible and deterministic. A recommended MVP formula is:

```text
raw impact = sum(reachable node sensitivity)
             + 2 per reachable PII node
             + 3 per reachable production node
score = clamp(round(100 * raw impact / organization maximum possible impact), 0, 100)
```

Define threshold values in one configuration file, test them, and return the raw components in the API response for explainability.

## Definition of Done

- Synthetic organization data only; no production identities, credentials, tokens, or customer data.
- Graph results are deterministic and tested; every completed user-facing simulation also includes validated OpenAI analysis.
- Suggested revocations are previews only and require an authorized human in the real world.
- The UI shows reach, risk, paths, and measurable remediation impact.
- CI passes formatting, linting, type checking, unit/API tests, and the core end-to-end scenario.
