# talonctl-demo — Project Instructions

Detection-as-code for Pinnacle Technology's CrowdStrike NGSIEM, powered by talonctl with AI-assisted SOC workflows.

## Overview

This is a [talonctl](https://github.com/willwebster5/talonctl) project — infrastructure as code for CrowdStrike NGSIEM resources. It manages detection rules, saved searches, dashboards, and lookup files for Pinnacle Technology's security program.

**Tools:**
- **talonctl** — IaC CLI (`talonctl plan`, `talonctl apply`, `talonctl validate`)
- **crowdstrike-mcp** — MCP server bridging Claude to the CrowdStrike Falcon API
- **agent-skills** — Claude Code plugins for SOC workflows, detection engineering, and threat hunting

## Commands

### IaC Commands

```bash
talonctl validate                    # Validate all templates (no API calls)
talonctl plan                        # Preview what would change
talonctl apply                       # Deploy changes
talonctl import --plan               # Preview importing existing resources
talonctl sync                        # Reconcile state with live tenant
talonctl drift                       # Detect manual console changes
talonctl show                        # Show current state
talonctl init myproject              # Scaffold a new project
```

### Operational Commands

| Command | Description |
|---------|-------------|
| `talonctl auth setup` | Interactive credential setup wizard |
| `talonctl auth check` | Verify stored credentials |
| `talonctl health` | Detection health check (cross-reference deployed rules with alert data) |
| `talonctl health --format json --output report.json` | Export health report as JSON |
| `talonctl metrics update-detections --report report.json` | Update per-detection weekly CSV |
| `talonctl metrics update-kpis --report report.json` | Update weekly KPI CSV |
| `talonctl backup create` | Create state backup as GitHub Release |
| `talonctl backup list` | List available backups |
| `talonctl backup restore <tag>` | Restore from a backup |

## Agent-Skills Integration

The following skills are available when the [agent-skills](https://github.com/willwebster5/agent-skills) plugins are installed:

| Skill | Description | Status |
|-------|-------------|--------|
| `crowdstrike-soc` | Unified SOC analyst -- triage, investigate, hunt, tune | Battle-tested |
| `crowdstrike-soc-agents` | Agent-delegated architecture with sub-agent decomposition | Experimental |
| `crowdstrike-behavioral-detections` | Attack chain patterns for writing correlation rules | Stable |
| `crowdstrike-cql-patterns` | CQL query pattern library (aggregation, correlation, scoring) | Stable |
| `crowdstrike-logscale-security-queries` | LogScale/NGSIEM query reference and investigation playbooks | Stable |
| `crowdstrike-fusion-workflows` | Falcon Fusion workflow templates and YAML schema | Stable |
| `crowdstrike-detection-tuning` | FP tuning patterns with enrichment function catalog | Stable |
| `crowdstrike-source-threat-modeling` | Threat-model-first detection planning for new data sources | New |
| `crowdstrike-response-playbooks` | Detection-to-response mapping and SOAR playbook design | New |
| `crowdstrike-threat-hunting` | Autonomous PEAK-based threat hunting -- hypothesis, intel, baseline hunts | Experimental |

## AI Workflows

| Command | Description |
|---------|-------------|
| `/soc` | SOC operations -- triage, daily review, hunt, tune |
| `/research` | Deep technical research with web search |
| `/discuss` | Exploratory discussion mode (read-only) |
| `/hunt` | Autonomous threat hunting |

### SOC Subcommands

```
/soc triage <alert-url-or-id>   -- Triage a specific alert
/soc daily [product]             -- Review today's untriaged alerts
/soc tune <detection-name>       -- Tune a detection for FPs
/soc hunt <IOCs-or-hypothesis>   -- Threat hunting mode
```

### Hunt Subcommands

```
/hunt hypothesis "<statement>"   -- Hypothesis-driven hunt
/hunt intel "<context>"          -- Intelligence-driven hunt
/hunt baseline "<entity>"        -- Baseline/anomaly hunt
/hunt                            -- Suggest hunts from coverage gaps
/hunt log                        -- View hunt history
/hunt coverage                   -- View ATT&CK hunt coverage map
```

## Critical Rules

1. **Always plan before apply.** Never blind-deploy.
2. **Never change `resource_id` after deploy.** It destroys and recreates the resource.
3. **Saved search description limit: 2000 characters.** The API silently truncates.
4. **Validate CQL syntax** before committing: `talonctl validate`
5. **Detection tuning requires approval.** The SOC skill presents a diff and waits for confirmation.
6. **Knowledge base files are living documents.** Update `knowledge/` after every triage session.

## Credentials

- **Location:** `~/.config/falcon/credentials.json`
- **Setup:** `talonctl auth setup`
- **Required API scopes (IaC):** Correlation Rules (read/write), NGSIEM (read/write), Workflow (read/write), Real Time Response Admin (write)
- **Required API scopes (SOC skills via MCP):** Alerts (read/write), NGSIEM (read/write), Hosts (read), Cloud Security (read), Cases (read/write)
- **Never commit credentials.**

## Resource Types

| Type | Template Dir | Description |
|------|-------------|-------------|
| Detection | `resources/detections/` | Correlation rules (CQL queries) |
| Saved Search | `resources/saved_searches/` | Reusable CQL functions |
| Dashboard | `resources/dashboards/` | LogScale dashboards |
| Lookup File | `resources/lookup_files/` | CSV lookup tables for enrichment |

## Project Structure

```
talonctl-demo/
├── CLAUDE.md                       # Project instructions (this file)
├── GETTING_STARTED.md              # Onboarding guide
├── README.md                       # Project overview
├── .crowdstrike/                   # State files (deployed_state.json)
├── .github/workflows/              # CI/CD: plan on PR, apply on merge
├── knowledge/                      # Living operational knowledge base
│   ├── INDEX.md                    # Routing table (<150 lines)
│   ├── context/                    # Environmental baselines
│   ├── patterns/                   # Per-platform FP/TP patterns
│   ├── techniques/                 # Investigation query patterns
│   ├── tuning/                     # Tuning backlog + historical log
│   ├── metrics/                    # Per-alert disposition records (JSONL)
│   ├── hunts/                      # Threat hunt reports
│   └── ideas/                      # Detection concepts
├── resources/                      # IaC templates
│   ├── detections/                 # Correlation rules
│   ├── saved_searches/             # Reusable CQL functions
│   ├── dashboards/                 # LogScale dashboards
│   └── lookup_files/               # CSV lookup tables
└── examples/                       # Parser examples
```

## Knowledge Base

The `knowledge/` directory holds living operational documents that compound over time through triage sessions.

### Tiered Loading

| Tier | Load When | Files |
|------|-----------|-------|
| L1 | Every session | `knowledge/INDEX.md`, `knowledge/context/environmental-context.md` |
| L2 | Per-task | `knowledge/patterns/<platform>.md`, `knowledge/techniques/investigation-techniques.md`, `knowledge/tuning/tuning-backlog.md` |
| L3 | On-demand | `knowledge/tuning/tuning-log.md`, `knowledge/metrics/detection-metrics.jsonl`, `knowledge/hunts/*.md`, `knowledge/ideas/detection-ideas.md` |

### Phase Loading Boundaries (Anti-Bias)

| Phase | Loads | Does NOT Load |
|-------|-------|---------------|
| Phase 1 (Intake) | INDEX.md, environmental-context.md | Platform patterns, investigation techniques |
| Phase 2 (Triage) | investigation-techniques.md, relevant playbook | Platform pattern files |
| Phase 3 (Classification) | patterns/\<platform\>.md for relevant platform | -- |
| Phase 4 (Closure) | Writes to: INDEX.md, patterns/\<platform\>.md, detection-metrics.jsonl, tuning-backlog.md | -- |

### ADS Metadata Schema

Detection templates support an optional `ads:` block for Alerting and Detection Strategy documentation. If present, `goal` is required and only known fields are allowed. Unknown keys are rejected by `validate`.

```yaml
ads:
  goal: ""              # Required -- what behavior does this detection identify?
  mitre_attack: []      # Analyst-facing MITRE mappings (can differ from top-level)
  strategy_abstract: "" # How the detection works
  technical_context: "" # Data sources, key fields, enrichment
  blind_spots: []       # Known limitations
  false_positives: []   # Inline FP summaries or references to knowledge/patterns/
  validation: []        # Steps to trigger a true positive
  priority_rationale: ""# Why this severity level?
  response: ""          # Response steps or playbook reference
  ads_created: ""       # ISO date
  ads_updated: ""       # ISO date
  ads_author: ""        # Who wrote/updated
```

The `ads.mitre_attack` field is analyst-facing and can include parent/child categories (e.g., "Defense Evasion / Impair Defenses") that the API doesn't support. The top-level `mitre_attack` field is what deploys via the CrowdStrike API. Both coexist.

### Detection Metrics

Append one JSONL line to `knowledge/metrics/detection-metrics.jsonl` per alert disposition:

```json
{"date":"2026-04-14","detection":"AWS - CloudTrail - EC2 SG Anomaly","resource_id":"aws_cloudtrail_ec2_sg_anomaly","disposition":"false_positive","fp_reason":"ci_cd_automation","tier":"pattern_match","est_minutes":3,"alert_count":1,"case_created":false,"composite_id":"ngsiem:bf7f...:abc123"}
```

Dispositions: `true_positive`, `false_positive`, `tuning_needed`, `inconclusive`.

### Tuning Log Format

Structured entries in `knowledge/tuning/tuning-log.md`:

```markdown
## YYYY-MM-DD -- resource_id

**Trigger:** What prompted the tuning
**Change:** Summary of what was modified
**Before:** `<before CQL snippet>`
**After:** `<after CQL snippet>`
**Alerts:** [composite_ids that triggered this]
**Validation:** validate-query result
**PR:** #number
```

## CI/CD

- **PR opened:** Runs `plan` and posts summary as PR comment
- **Merge to main:** Runs `apply --auto-approve`
- **Secrets required:** `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_BASE_URL`
