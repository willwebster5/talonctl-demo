# talonctl-demo — Project Instructions

Detection-as-code for Pinnacle Technology's CrowdStrike NGSIEM, powered by talonctl with AI-assisted SOC workflows.

## Overview

This is a [talonctl](https://github.com/willwebster5/talonctl) project — infrastructure as code for CrowdStrike NGSIEM resources. It manages detection rules, saved searches, and dashboards for Pinnacle Technology's security program.

**Tools:**
- **talonctl** — IaC CLI (`talonctl plan`, `talonctl apply`, `talonctl validate`)
- **crowdstrike-mcp** — MCP server bridging Claude to the CrowdStrike Falcon API
- **agent-skills** — Claude Code plugins for SOC workflows, detection engineering, and threat hunting

## Commands

```bash
talonctl validate                    # Validate all templates (no API calls)
talonctl plan                        # Preview what would change
talonctl apply                       # Deploy changes
talonctl import --plan               # Preview importing existing resources
talonctl sync                        # Reconcile state with live tenant
talonctl drift                       # Detect manual console changes
talonctl show                        # Show current state
```

## AI Workflows

| Command | Description |
|---------|-------------|
| `/soc` | SOC operations — triage, daily review, hunt, tune |
| `/research` | Deep technical research with web search |
| `/discuss` | Exploratory discussion mode (read-only) |
| `/hunt` | Autonomous threat hunting |

### SOC Subcommands

```
/soc triage <alert-url-or-id>   — Triage a specific alert
/soc daily [product]             — Review today's untriaged alerts
/soc tune <detection-name>       — Tune a detection for FPs
/soc hunt <IOCs-or-hypothesis>   — Threat hunting mode
```

## Critical Rules

1. **Always plan before apply.** Never blind-deploy.
2. **Never change `resource_id` after deploy.** It destroys and recreates the resource.
3. **Saved search description limit: 2000 characters.** The API silently truncates.
4. **Validate CQL syntax** before committing: `talonctl validate`
5. **Detection tuning requires approval.** The SOC skill presents a diff and waits for confirmation.
6. **Knowledge base files are living documents.** Update `knowledge/` after every triage session.

## Knowledge Base

The `knowledge/` directory holds operational context that compounds over time.

### Tiered Loading

| Tier | Load When | Files |
|------|-----------|-------|
| L1 | Every session | `INDEX.md`, `context/environmental-context.md` |
| L2 | Per-task | `patterns/<platform>.md`, `techniques/investigation-techniques.md`, `tuning/tuning-backlog.md` |
| L3 | On-demand | `tuning/tuning-log.md`, `metrics/detection-metrics.jsonl`, `hunts/*.md`, `ideas/detection-ideas.md` |

### ADS Metadata

Detection templates support an optional `ads:` block for Alerting and Detection Strategy documentation:

```yaml
ads:
  goal: ""              # Required — what behavior does this detect?
  mitre_attack: []      # Analyst-facing MITRE mappings
  strategy_abstract: "" # How the detection works
  technical_context: "" # Data sources, key fields
  blind_spots: []       # Known limitations
  false_positives: []   # FP summaries
  validation: []        # Steps to trigger a TP
  priority_rationale: ""# Why this severity?
  response: ""          # Response steps
```

## Credentials

- **Location:** `~/.config/falcon/credentials.json`
- **Setup:** See talonctl documentation
- **Never commit credentials.**

## Resource Types

| Type | Template Dir | Description |
|------|-------------|-------------|
| Detection | `resources/detections/` | Correlation rules (CQL queries) |
| Saved Search | `resources/saved_searches/` | Reusable CQL functions |
| Dashboard | `resources/dashboards/` | LogScale dashboards |
