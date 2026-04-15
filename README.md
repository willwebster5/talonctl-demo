# talonctl-demo

A working example of AI-assisted detection-as-code for CrowdStrike NGSIEM.

This repo demonstrates the full detection engineering lifecycle — from writing detection rules as YAML templates to deploying them via CI/CD — augmented with AI-powered SOC workflows for triage, tuning, and threat hunting.

## The Tools

| Tool | What it does | Repo |
|------|-------------|------|
| [talonctl](https://github.com/willwebster5/talonctl) | Terraform-like IaC CLI for CrowdStrike NGSIEM | `pip install talonctl` |
| [crowdstrike-mcp](https://github.com/willwebster5/crowdstrike-mcp) | MCP server bridging AI assistants to the Falcon API | `pip install crowdstrike-mcp` |
| [agent-skills](https://github.com/willwebster5/agent-skills) | Claude Code plugins for SOC and detection engineering | Plugin marketplace |

## The Environment

This demo uses a fictional company, **Pinnacle Technology**, a cloud-native SaaS startup with:
- AWS (CloudTrail, VPC Flow Logs)
- EntraID (SSO, Conditional Access)
- GitHub (organization audit logs)
- Google Workspace
- CrowdStrike Falcon (endpoint + NGSIEM)

The `knowledge/` directory contains Pinnacle's environmental context, known FP/TP patterns, and investigation techniques — all fictional but realistic.

## Prerequisites

- CrowdStrike Falcon tenant with NGSIEM
- Python 3.11+
- [Claude Code](https://claude.ai/download)
- API credentials with required scopes (see [talonctl docs](https://github.com/willwebster5/talonctl#api-scopes))

## Quick Start

1. **Install the tools:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install talonctl crowdstrike-mcp
   ```

2. **Install Claude Code plugins:**
   ```
   /install-plugin willwebster5/agent-skills
   ```

3. **Clone this demo:**
   ```bash
   git clone https://github.com/willwebster5/talonctl-demo.git
   cd talonctl-demo
   ```

4. **Configure credentials:**
   ```bash
   talonctl auth setup
   ```

5. **Validate and plan:**
   ```bash
   talonctl validate    # Check templates are valid
   talonctl plan        # See what would deploy
   ```

See [GETTING_STARTED.md](GETTING_STARTED.md) for detailed onboarding instructions.

## Operational Commands

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

## Detection-as-Code Lifecycle

```
Write YAML template → talonctl validate → talonctl plan → Review diff → talonctl apply
                                                              ↑
                                                    AI triage/hunting feeds back
                                                    detection ideas and tuning
```

## AI Workflows

With Claude Code and the agent-skills plugins installed, you get:

- **`/soc triage <alert>`** — AI-assisted alert triage with evidence collection
- **`/soc daily`** — Review today's untriaged alerts
- **`/soc tune <detection>`** — Tune a detection for false positives
- **`/hunt hypothesis "<statement>"`** — Autonomous PEAK-framework threat hunting

Each workflow reads from and writes to the `knowledge/` directory, building institutional memory over time.

## Adding Detections

Detection rules in `resources/detections/` must be:
- **Generic** — not tied to a specific customer environment
- **Non-proprietary** — no customer names, internal IPs, or proprietary tool names
- **Complete** — valid CQL, full ADS metadata, MITRE ATT&CK mapping

See the [TOR traffic detection](resources/detections/generic_network_tor_traffic.yaml) for a complete example.

## License

MIT
