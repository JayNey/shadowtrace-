# Adversarial agent audit

Independent Mock XDR scenario for **dynamic** evaluation — not registered in
`SCENARIO_REGISTRY` and not used by `make bootstrap`.

## Scenario

**`adversarial_credential_db_staging_exfil`** — multi-stage attack without obvious
keyword labels in the incident title:

1. Service account `svc-analytics-47` VPN login from unusual geo (`198.51.100.44`)
2. Credential tooling (`ntdsutil.exe`) on `WKS-DATA-031`
3. RDP pivot to `SRV-DB-STG-02`, `mysqldump` + `rclone.exe`
4. ~890MB HTTPS upload to `storage-sync-cdn.example`
5. Red herring: legitimate backup job on `BACKUP-SRV-01`

### High-noise layer (added)

Poll ingests **6 incidents** (5 decoy + 1 true positive) and **~600+ telemetry rows**:

| Layer | Count |
|-------|------:|
| Decoy incidents (benign/maintenance) | 5 |
| Alert storm on last decoy | 10 alerts |
| Network noise (`is_noise=true`) | 280 |
| Identity noise | 90 |
| Endpoint noise | 140 |
| DNS noise | 60 |
| Suspicious-looking decoy key events | 6 |
| True-positive key events | 17 |

The test selects the true incident by `true_positive_incident_id=88190001`, simulating
an analyst picking one case from a noisy queue.

Ground truth lives in `scenario_credential_db_staging_exfil.py` (`GROUND_TRUTH`) when the
adversarial pytest suite is present locally.

## Golden packs (in repository)

Scenario-specific Mock LLM goldens ship under:

```text
backend/app/core/llm/golden/*/default.json
backend/app/core/llm/golden/*/insider_data_exfiltration.json
backend/app/core/llm/golden/*/adversarial_credential_db_staging_exfil.json
```

Use `scenario_id=None` for neutral defaults (ISSUE-201) or pass an explicit scenario id
to load the matching pack.

## Run (adversarial pytest — optional / local)

The dynamic audit **pytest modules** (`test_agent_adversarial_audit.py`,
`test_agent_adversarial_full_loop.py`) are maintained outside the default CI path and
may be absent in a minimal checkout. When present locally, they require Postgres +
Redis (same as integration tests):

```bash
cd backend

# Analysis-only audit (→ REPORTING) — only when tests/adversarial/*.py exists
uv run --frozen python -m pytest tests/adversarial/test_agent_adversarial_audit.py -v -s

# Production full loop — only when tests/adversarial/*.py exists
uv run --frozen python -m pytest tests/adversarial/test_agent_adversarial_full_loop.py -v -s
```

When the adversarial pytest tree is **not** checked in, validate golden packs via:

```bash
cd backend
uv run --frozen python -m pytest tests/test_core/test_golden_defaults.py -q
```

## Mock vs Live evaluation boundary

This suite has **two layers**:

| Layer | Role | Pass means |
|-------|------|------------|
| **Plumbing** | Agents run, traces persist, tools/LLM logs exist | Wiring works — not capability proof |
| **Quality gate** (`test_agent_adversarial_full_loop.py`, ISSUE-203) | Hard asserts on terminal status, report, disposition targets, zero shims | Production graph reached `REPORTING`/`CLOSED` with aligned containment plan |

Do **not** claim autonomous investigation quality from Mock plumbing alone. Live LLM runs add reasoning signal but remain non-deterministic.

| Mode | What it measures | What it does **not** measure |
|------|------------------|------------------------------|
| **Mock** (`LLM_MODE=mock`, default) | Deterministic pipeline wiring, agent orchestration, evidence projection, degraded flags, report structure | Real LLM reasoning, novel scenario generalization, or production adjudication quality |
| **Mock + `scenario_id=None`** | Conservative **neutral** default goldens (low risk, ticket-only response, no demo personas) — avoids cross-prompt demo contradictions (ISSUE-201) | Agent capability ceiling; expect **WEAK/PARTIAL** on adversarial scenarios unless scenario-specific goldens or Live LLM is used |
| **Mock + scenario golden** | Regression / demo packs (e.g. `insider_data_exfiltration`, `adversarial_credential_db_staging_exfil`) | Same as Mock — golden content is scripted, not emergent reasoning |
| **Live** (`LLM_MODE=openai_compatible` + API key) | Closer-to-production LLM behavior on unseen narratives | Vendor availability, cost, non-determinism |

**Do not** interpret Mock adversarial audit **PASS** as proof of autonomous investigation quality. Mock results validate plumbing and scripted paths only; Live runs (or human red-team review) are required for capability claims.

Optional — use a real LLM (Volcengine Ark / OpenAI-compatible) instead of Mock golden defaults.

Docker stack with `.env.live` at repo root already sets live LLM for backend/worker.
For **pytest on the host**, export the same vars (or `set -a && source ../.env.live && set +a`):

```bash
set -a && source ../.env.live && set +a
uv run --frozen python -m pytest tests/adversarial/test_agent_adversarial_audit.py -v -s
```

Or inline:

```bash
LLM_MODE=openai_compatible \
LLM_API_BASE_URL=https://ark.cn-beijing.volces.com/api/coding/v3 \
LLM_API_KEY=... \
LLM_PRIMARY_MODEL=glm-5.2 \
  uv run --frozen python -m pytest tests/adversarial/test_agent_adversarial_full_loop.py -v -s
```

Production full-loop test may run **10–20+ minutes** with a live LLM.

Optional — graph-mode SuperAgent instead of analysis-only pipeline: duplicate the
test and call `build_super_agent(scenario_id=None)` from integration fixtures.

## Output

| Test | Artifact | Terminal state |
|------|----------|----------------|
| `test_agent_adversarial_audit.py` | `artifacts/latest_audit.json` | `REPORTING` |
| `test_agent_adversarial_full_loop.py` | `artifacts/latest_full_loop_audit.json` | `REPORTING`/`CLOSED` + writeback `CONFIRMED` + aligned response targets |

Full-loop artifact includes `response_plan_actions`, `shims_used` (must be `[]`), and
`disposition_target_gaps`. Sunset shims removed in ISSUE-203: verify_tail,
writeback_activation seeding, minimum disposition audit seed on this path.

Console prints human verdict + check matrix for each run.

## Interpretation

| Verdict | Meaning |
|---------|---------|
| **PASS** | Reached reporting + `confirmed_threat` + risk ≥ 65 |
| **PARTIAL** | Reached reporting with high risk but type/verdict off |
| **WEAK** | Reached reporting but under-scored |
| **FAIL** | Did not reach reporting or missed critical signals |

The test uses ``scenario_id=None`` so **neutral** Mock LLM default goldens are selected
(not demo insider personas). Regex / evidence paths still run — set ``LLM_MODE=live``
for a stricter evaluation. For scripted Mock coverage of this scenario, pass
``scenario_id=adversarial_credential_db_staging_exfil`` (see
``backend/app/core/llm/golden/*/adversarial_credential_db_staging_exfil.json``).
This is deliberately harder than ``insider_data_exfiltration`` e2e tests when
using neutral defaults.
