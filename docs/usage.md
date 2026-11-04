# Command Reference

## Synopsis

```
falcon <command> <subcommand> [flags]
```

## Commands

| Command | Description |
|---------|-------------|
| `falcon auth` | Authenticate with the CrowdStrike Falcon API |
| `falcon hosts` | Query and manage hosts (devices) |
| `falcon detections` | Query and inspect detections (alerts) |
| `falcon intel` | Query CrowdStrike threat intelligence |
| `falcon ioc` | Query and manage custom indicators of compromise (IOCs) |
| `falcon spotlight` | Query Falcon Spotlight vulnerabilities |
| `falcon rtr` | Real Time Response (read-only triage) |
| `falcon netscan` | Manage Network Vulnerability Assessment (NVA) resources |
| `falcon fcs` | Manage Falcon Cloud Security resources |
| `falcon version` | Display the CLI version |

## Authentication (`auth`)

| Subcommand | Description |
|------------|-------------|
| `auth config [profile]` | Configure API credentials (aliases: `login`, `init`) |

## Hosts (`hosts`)

| Subcommand | Description | Scope |
|------------|-------------|-------|
| `hosts list` | List hosts | Hosts: Read |
| `hosts get` | Get host details | Hosts: Read |
| `hosts contain` | Network-contain hosts | Hosts: Write |
| `hosts lift-containment` | Lift network containment | Hosts: Write |
| `hosts hide` | Hide hosts | Hosts: Write |
| `hosts unhide` | Unhide hosts | Hosts: Write |

## Detections (`detections`)

| Subcommand | Description | Scope |
|------------|-------------|-------|
| `detections list` | List detections (alerts) | Alerts: Read |
| `detections get` | Get detection details | Alerts: Read |
| `detections aggregate` | Aggregate detections | Alerts: Read |

Updating detection status requires Alerts: Write.

## Threat Intelligence (`intel`)

| Subcommand | Description |
|------------|-------------|
| `intel actors list` | List intel actors (adversaries) |
| `intel indicators list` | List intelligence indicators |
| `intel reports list` | List intelligence reports |

Scopes: Actors (Falcon Intelligence): Read; Indicators: Read; Reports: Read.

## Custom IOCs (`ioc`)

| Subcommand | Description | Scope |
|------------|-------------|-------|
| `ioc list` | List custom IOCs | IOC Manager: Read |
| `ioc get` | Get an IOC | IOC Manager: Read |
| `ioc create` | Create a custom IOC | IOC Manager: Write |
| `ioc delete` | Delete a custom IOC | IOC Manager: Write |

## Spotlight (`spotlight`)

| Subcommand | Description | Scope |
|------------|-------------|-------|
| `spotlight vulnerabilities list` | List Spotlight vulnerabilities | Vulnerabilities (Spotlight): Read |

`spotlight vulnerabilities list` **requires** a `--filter` — the Spotlight API does
not allow listing all vulnerabilities unscoped (e.g. `--filter "status:'open'"`).

## Real Time Response (`rtr`)

| Subcommand | Description | Scope |
|------------|-------------|-------|
| `rtr sessions list` | List RTR session IDs | Real Time Response: Read |

Without the Real Time Response scope, `rtr sessions list` returns
`403 scope not permitted`.

## Network Vulnerability Assessment (`netscan`)

| Subcommand | Actions | Scope |
|------------|---------|-------|
| `netscan networks` | `list` `get` `create` `update` `delete` | Network scanning: Read / Write |
| `netscan scans` | `list` `get` `create` `update` `delete` | Network scanning: Read / Write |
| `netscan zones` | `list` `get` `create` `update` `delete` | Network scanning: Read / Write |
| `netscan templates` | `list` `get` `create` `update` `delete` | Network scanning: Read / Write |
| `netscan scanners` | `list` `get` | Network scanning: Read |
| `netscan scan-runs` | `list` `get` | Network scanning: Read |

## Falcon Cloud Security (`fcs`)

| Subcommand | Description |
|------------|-------------|
| `fcs assets list` | List cloud assets |
| `fcs risks list` | List cloud security risks |
| `fcs iom list` | List Indicators of Misconfiguration |
| `fcs vulnerabilities list` | List vulnerabilities |
| `fcs iac list` | List IaC scan results |
| `fcs image-assessment list` | List container image assessments |
| `fcs compliance frameworks` / `fcs compliance rules` | List compliance frameworks / rules |
| `fcs kubernetes clusters` / `containers` / `detections` / `images` | View Kubernetes resources |
| `fcs groups list\|create\|update\|delete` | Manage cloud groups |
| `fcs suppression list\|create\|delete` | Manage suppression rules |
| `fcs policies ...` | Manage cloud security policies |
| `fcs registration ...` | Cloud account registration |
| `fcs doctor` | Check which FCS command groups your API scopes allow |

## Write safety: the `--confirm` gate

Mutating commands — `hosts contain`/`lift-containment`/`hide`/`unhide`,
`ioc create`/`delete`, detection status updates, the `netscan` create/update/delete
actions, and the `fcs groups`/`suppression` writes — are **dry-run by default**.
Without `--confirm` the command prints the exact request it would send and exits
without calling the API. Re-run the identical command with `--confirm` to execute.

```bash
# Dry run — prints the plan, calls nothing
falcon hosts contain --ids <aid>

# Execute
falcon hosts contain --ids <aid> --confirm
```

## Output and filtering flags

These apply to `list`-style commands:

```
      --output string       Output format: table, json, jsonl, or toon (default "table")
      --filter string       FQL filter expression (e.g. "severity:'HIGH'")
      --limit int           Maximum number of results to return (default 100)
      --offset int          Starting offset for results
      --sort string         FQL sort expression (e.g. "severity|desc")
      --sort-by string      Sort by column name (prefix - for descending, e.g. -region)
      --columns string      Comma-separated list of columns to display (e.g. id,name,provider)
      --grep string         Case-insensitive substring match across all columns
      --no-headers          Suppress the table header row
      --no-truncate         Disable column value truncation
      --max-col-width int   Maximum column width before truncation (0 = unlimited) (default 50)
```

## Global flags

```
      --config string          Path to config file (default "~/.falcon/config.yaml")
  -p, --profile string         Named credential profile to use (default "default")
  -r, --cloud string           Falcon cloud region (default "autodiscover")
  -f, --cid string             CrowdStrike Customer ID
  -u, --client-id string       OAuth2 Client ID (overrides config)
  -s, --client-secret string   OAuth2 Client Secret (overrides config)
  -m, --member-cid string      Member CID for MSSP / Flight Control
      --base-url string        Override the API base URL (e.g. https://api.us-2.crowdstrike.com)
      --verbose                Enable verbose logging
      --version                Show version
```

## Authentication

The CLI uses CrowdStrike API credentials (OAuth2 client ID and secret). Configure
them interactively:

```bash
falcon auth config
```

Or pass them directly:

```bash
falcon auth config --client-id <YOUR_CLIENT_ID> --client-secret <YOUR_CLIENT_SECRET>
```

Credentials are stored in `~/.falcon/config.yaml`. You can also use environment
variables:

```bash
export FALCON_CLIENT_ID=<YOUR_CLIENT_ID>
export FALCON_CLIENT_SECRET=<YOUR_CLIENT_SECRET>
```

Run `falcon fcs doctor` to see which FCS command groups your API scopes allow. If a
non-FCS command returns `403 scope not permitted`, add the matching scope to your
API client in the Falcon console under **Support and resources → API clients and
keys**.

## Examples

```bash
# Configure credentials interactively
falcon auth config

# List hosts, token-efficient output
falcon hosts list --limit 50 --output toon

# Open detections, newest first
falcon detections list --filter "status:'new'" --sort "created_timestamp|desc"

# Open Spotlight vulnerabilities (filter is required)
falcon spotlight vulnerabilities list --filter "status:'open'"

# Create a custom IOC (dry run, then execute)
falcon ioc create --value evil.example.com --type domain --action detect --severity high
falcon ioc create --value evil.example.com --type domain --action detect --severity high --confirm

# List cloud assets and risks
falcon fcs assets list --filter "cloud_provider:'aws'"
falcon fcs risks list

# List Kubernetes clusters
falcon fcs kubernetes clusters

# List NVA scanners
falcon netscan scanners list

# Check API client permissions
falcon fcs doctor
```
