# Kubernetes Security Lab

`k8sSecurityLab` is a deliberately vulnerable Go-based Kubernetes lab for demonstrating common attack paths against weak multi-tenant clusters.

The lab creates a small environment with:

- `tenant-a`
- `tenant-b`
- a `ServiceAccount` named `tenant-sa`
- weak RBAC in `tenant-a`
- a secret named `db-credentials`

It includes a CLI that can:

- deploy the lab
- reset it
- destroy it
- scan for a basic RBAC weakness
- build an in-memory attack graph
- rank attack paths from a starting pod or service account
- explain why a path exists
- export the reachable graph as Mermaid
- export the reachable graph as DOT
- serve a lightweight browser UI for graph exploration
- compare graph snapshots over time
- run attack scenarios that exercise the vulnerable setup

This project is intended for local, disposable environments such as `kind`. Do not deploy it into a shared or production cluster.

## What The Lab Teaches

The lab focuses on Kubernetes attack primitives that are routinely underestimated:

- weak RBAC
- token abuse
- secret exposure
- pod creation as code execution
- `pods/exec` as remote code execution inside workloads
- scheduled job persistence
- configuration integrity abuse
- network reachability across tenant boundaries
- privileged pod and `hostPath` abuse

The scenarios are intentionally small. The goal is to make each weakness easy to understand and easy to reproduce.

## Current Scenarios

The lab currently supports these attack scenarios:

1. `rbac`
2. `token`
3. `token-request`
4. `secrets`
5. `pod-create`
6. `exec`
7. `cronjob`
8. `configmap-poison`
9. `lateral`
10. `escape`

### Scenario Summary

| Scenario | Main weakness | What it demonstrates |
| --- | --- | --- |
| `rbac` | `create` on `rolebindings` | Escalation to admin-equivalent rights inside `tenant-a` |
| `token` | ServiceAccount token mounted in a pod | Theft and reuse of a pod's API credential |
| `token-request` | `create` on `serviceaccounts/token` | Minting fresh JWTs for a ServiceAccount |
| `secrets` | Secret read exposure | Reading application credentials from Kubernetes Secrets |
| `pod-create` | `create` on `pods` | Creating a pod that mounts and leaks secrets |
| `exec` | `create` on `pods/exec` plus `get` on `pods` | Running commands inside an existing workload |
| `cronjob` | `create` on `cronjobs` | Establishing scheduled persistence in a namespace |
| `configmap-poison` | `update` or `patch` on `configmaps` | Tampering with workload startup behavior |
| `lateral` | Missing network isolation | Reaching services across tenant boundaries |
| `escape` | Privileged pod plus `hostPath: /` | Accessing the node filesystem from a container |

## Lab Design

### Namespaces

- `tenant-a`: the intentionally weak tenant
- `tenant-b`: a second tenant used for lateral movement demos

### Base Assets Created By `start`

When you run `lab-cli start`, the lab creates:

- `Namespace/tenant-a`
- `Namespace/tenant-b`
- `ServiceAccount/tenant-sa` in `tenant-a`
- `Secret/db-credentials` in `tenant-a`
- several weak roles in `tenant-a`
- role bindings attaching those roles to `tenant-sa`

### Vulnerable RBAC

The vulnerable roles are created in [internal/cluster/rbac.go](/internal/cluster/rbac.go:12):

- `rbac-manager`
  - allows `create` on `rolebindings`
- `token-requestor`
  - allows `create` on `serviceaccounts/token`
- `pod-creator`
  - allows `create` on `pods`
- `exec-operator`
  - allows `get` on `pods`
  - allows `create` on `pods/exec`
- `cronjob-creator`
  - allows `create` on `cronjobs`
- `configmap-editor`
  - allows `get`, `update`, and `patch` on `configmaps`

These are bound to `tenant-sa` in `tenant-a`.

### Seeded Secret

The lab seeds one secret in `tenant-a`:

- `db-credentials`
  - `username=admin`
  - `password=SuperSecretPassword123`

This is created in [internal/cluster/secrets.go](/internal/cluster/secrets.go:11).

## Repository Layout

- [cmd/lab-cli/main.go](/cmd/lab-cli/main.go:1): CLI entrypoint
- [internal/commands](/internal/commands): command dispatch and subcommands
- [internal/cluster](/internal/cluster): cluster bootstrap, reset, destroy, client helpers
- [internal/scenarios](/internal/scenarios): attack scenario implementations
- [internal/scanner/rbac.go](/internal/scanner/rbac.go:1): simple RBAC scanner
- [manifests/tenants.yaml](/manifests/tenants.yaml:1): static namespace manifest
- [manifests/vulnerable-rbac.yaml](/manifests/vulnerable-rbac.yaml:1): static RBAC reference manifest
- [cluster/kind-config.yaml](/cluster/kind-config.yaml:1): sample `kind` cluster config

## Prerequisites

- Go `1.25` or compatible with [go.mod](/go.mod:1)
- a running Kubernetes cluster
- `kubectl` configured to point at that cluster
- enough privileges from your normal kubeconfig to create namespaces, service accounts, roles, role bindings, pods, secrets, and services

Recommended:

- `kind`
- a fresh local cluster dedicated to this lab

## Quick Start

### 1. Create A Local Cluster

Example with `kind`:

```bash
kind create cluster --name k8s-security-lab --config cluster/kind-config.yaml
kubectl cluster-info
```

### 2. Build The CLI

```bash
go build -o lab-cli ./cmd/lab-cli
```

### 3. Start The Lab

```bash
./lab-cli start
```

### 4. Run The Scanner

```bash
./lab-cli scan
```

### 5. Discover Attack Paths

```bash
./lab-cli graph paths
./lab-cli graph export --format mermaid
./lab-cli graph export --format dot
./lab-cli graph export --format json
./lab-cli graph explain --goal node
./lab-cli graph serve --addr 127.0.0.1:8080
```

By default, the graph starts from `sa:tenant-a/tenant-sa`.

You can override the start node:

```bash
./lab-cli graph paths --from sa:tenant-a/tenant-sa
./lab-cli graph paths --from pod:tenant-a/token-attacker
./lab-cli graph paths --from sa:tenant-a/tenant-sa --goal node-compromise
./lab-cli graph paths --goal node
./lab-cli graph paths --namespace tenant-a --top 3
./lab-cli graph paths --format json
./lab-cli graph explain --goal secret
```

### 6. Run A Scenario

Examples:

```bash
./lab-cli attack rbac
./lab-cli attack token-request
./lab-cli attack pod-create
./lab-cli attack exec
./lab-cli attack cronjob
./lab-cli attack configmap-poison
```

### 7. Reset Or Destroy

```bash
./lab-cli reset
./lab-cli destroy
```

## CLI Reference

### `start`

Deploys the lab:

```bash
./lab-cli start
```

### `scan`

Runs a basic RBAC check that flags roles with `create` permissions:

```bash
./lab-cli scan
```

Implementation: [internal/scanner/rbac.go](/internal/scanner/rbac.go:1)

### `attack`

Runs a named attack scenario:

```bash
./lab-cli attack <scenario>
```

Supported values:

- `rbac`
- `token`
- `token-request`
- `secrets`
- `pod-create`
- `exec`
- `cronjob`
- `configmap-poison`
- `lateral`
- `escape`

Dispatch logic: [internal/commands/attack.go](/internal/commands/attack.go:8)

### `graph`

Builds a workload-aware attack graph from live cluster state and either prints ranked attack paths or exports graph data.

Examples:

```bash
./lab-cli graph paths
./lab-cli graph paths --from sa:tenant-a/tenant-sa
./lab-cli graph paths --from sa:tenant-a/tenant-sa --goal node-compromise
./lab-cli graph paths --goal node
./lab-cli graph paths --namespace tenant-a --top 5
./lab-cli graph paths --format json
./lab-cli graph explain --goal secret
./lab-cli graph explain --goal node --format json
./lab-cli graph export --format mermaid
./lab-cli graph export --format dot
./lab-cli graph export --format json
./lab-cli graph diff --before before.json
./lab-cli graph diff --before before.json --after after.json --format json
./lab-cli graph serve --addr 127.0.0.1:8080
```

Current subcommands:

- `graph paths`
- `graph explain`
- `graph export --format mermaid`
- `graph export --format dot`
- `graph export --format json`
- `graph diff`
- `graph serve`

`graph serve` starts a lightweight browser UI backed by the same attack graph engine. The UI supports:

- live graph rendering
- zoom in, zoom out, and reset zoom controls
- ranked path discovery
- explanation output with scenario recommendations
- graph snapshot download
- diffing a saved snapshot against the live cluster graph

Implementation:

- [internal/commands/graph.go](/internal/commands/graph.go:1)
- [internal/webapp/server.go](/internal/webapp/server.go:1)
- [internal/webapp/static/index.html](/internal/webapp/static/index.html:1)
- [internal/webapp/static/app.js](/internal/webapp/static/app.js:1)

Implementation entrypoint: [internal/commands/graph.go](/internal/commands/graph.go:10)

### `reset`

Deletes scenario-created artifacts and restores the vulnerable seed state:

```bash
./lab-cli reset
```

Implementation: [internal/cluster/reset.go](/internal/cluster/reset.go:10)

### `destroy`

Deletes the lab namespaces:

```bash
./lab-cli destroy
```

## Scenario Details

### `rbac`

File: [internal/scenarios/rbac_attack.go](/internal/scenarios/rbac_attack.go:12)

The scenario creates a `RoleBinding` in `tenant-a` that binds `tenant-sa` to the built-in `cluster-admin` `ClusterRole`.

Important detail:

- the binding created by this scenario is a namespaced `RoleBinding`
- that means the effect is admin-equivalent access inside `tenant-a`
- it is not a cluster-wide `ClusterRoleBinding`

What it shows:

- `rolebindings/create` is enough to self-escalate
- binding a powerful `ClusterRole` with a namespaced `RoleBinding` still gives overwhelming control inside that namespace

### `token`

File: [internal/scenarios/token_attack.go](/internal/scenarios/token_attack.go:20)

The scenario creates a pod running as `tenant-sa`, then reads the mounted ServiceAccount token from inside the pod and uses it against the Kubernetes API.

What it shows:

- a pod compromise often becomes an API credential compromise
- mounted ServiceAccount tokens are high-value credentials

### `token-request`

File: [internal/scenarios/token_request_attack.go](/internal/scenarios/token_request_attack.go:16)

The scenario simulates a compromised `tenant-sa` identity, uses it to call the TokenRequest API, and prints a fresh JWT plus the effective permissions of that token.

What it shows:

- attackers do not need file-system token theft if they can mint new tokens directly
- short-lived ServiceAccount credentials can still be abused repeatedly

### `secrets`

File: [internal/scenarios/secrets_attack.go](/internal/scenarios/secrets_attack.go:12)

The scenario lists secrets from `tenant-a` and prints their contents.

What it shows:

- secrets are one of the first post-compromise targets
- database passwords and API keys are often stored here

Practical note:

- secret access is best understood as a follow-on objective after another permission abuse path
- for example, after `rbac` escalation inside `tenant-a`

### `pod-create`

File: [internal/scenarios/pod_create_attack.go](/internal/scenarios/pod_create_attack.go:16)

The scenario uses compromised `tenant-sa` credentials to create a pod that mounts `db-credentials` and prints the secret values to its logs.

What it shows:

- `pods/create` is a code-execution permission
- an attacker can often read secrets indirectly even without direct `secrets/get`

### `exec`

File: [internal/scenarios/exec_attack.go](/internal/scenarios/exec_attack.go:17)

The scenario deploys a victim pod whose environment variables come from `db-credentials`, then uses compromised `tenant-sa` credentials to exec into that pod and print the values.

What it shows:

- `pods/exec` is interactive command execution inside another workload
- credentials stored in env vars or mounted files become reachable

### `cronjob`

File: [internal/scenarios/cronjob_attack.go](/internal/scenarios/cronjob_attack.go:15)

The scenario uses compromised `tenant-sa` credentials to create a CronJob in `tenant-a`. It then triggers one run immediately to show that the scheduled workload can repeatedly access the seeded secret.

What it shows:

- scheduled workloads are a clean persistence mechanism
- recurring jobs can re-establish access after cleanup attempts
- `cronjobs/create` is more dangerous than it first appears

### `configmap-poison`

File: [internal/scenarios/configmap_poison_attack.go](/internal/scenarios/configmap_poison_attack.go:15)

The scenario creates a victim pod that executes a script from a `ConfigMap`, then uses compromised `tenant-sa` credentials to modify that `ConfigMap` and reruns the victim workload to show the changed behavior.

What it shows:

- configuration writes are an integrity problem, not just an availability problem
- bootstrap scripts and mounted config can become a code execution path after restart
- `configmaps/update` and `configmaps/patch` should be treated as sensitive rights

### `lateral`

File: [internal/scenarios/lateral_attack.go](/internal/scenarios/lateral_attack.go:14)

The scenario creates a service in `tenant-b` and demonstrates that a pod in `tenant-a` can reach it.

What it shows:

- namespaces are not network isolation by themselves
- without `NetworkPolicy`, cross-namespace service access is often allowed

### `escape`

File: [internal/scenarios/escape_attack.go](/internal/scenarios/escape_attack.go:14)

The scenario deploys a privileged pod with `hostPath: /` mounted to `/host`.

What it shows:

- privileged pods are effectively node access
- mounting the host root filesystem breaks container isolation

## Manual Exploitation Guide

Step-by-step manual exploitation flows are in [manualtests.md](/manualtests.md:1).

That file shows how to reproduce each scenario with `kubectl` and shell commands instead of the Go CLI.

## Attack Graph

The attack graph is intentionally explicit and rule-based.

- Phase 1 added RBAC-driven capability derivation
- Phase 2 added workload-context refinement and Graphviz DOT export
- Phase 3 adds improved scoring, goal aliases, namespace filtering, top-N selection, and JSON output
- Phase 4 adds path explanations, lab-scenario mapping, and graph diffs

### What It Collects

- Pods
- ServiceAccounts
- Roles
- RoleBindings
- ClusterRoles
- ClusterRoleBindings
- Secrets
- ConfigMaps
- CronJobs

Inventory collection starts in [internal/attackgraph/inventory.go](/internal/attackgraph/inventory.go:13).

### What It Collects From Workloads

Phase 2 refines workload context by distinguishing:

- secrets injected through environment variables
- secrets mounted as volumes
- ConfigMaps injected through environment variables
- ConfigMaps mounted as files

This improves path quality for `pods/exec` and ConfigMap poisoning cases.

### What It Derives

For the current lab, the graph engine derives these attack capabilities from RBAC:

- bind powerful role
- mint fresh ServiceAccount token
- create arbitrary pod
- create privileged hostPath pod
- exec into existing pod
- establish persistence
- modify workload behavior

From those capabilities and workload relationships it derives impact nodes such as:

- namespace admin-equivalent
- fresh ServiceAccount token
- workload command execution
- secret exposure
- persistence
- config integrity compromise
- node compromise

### Phase 3 Query Features

Phase 3 adds query usability features:

- goal aliases such as `node`, `secret`, `admin`, `exec`, `config`, and `token`
- `--namespace <ns>` to keep paths and exports focused on a tenant
- `--top <n>` to return only the highest-ranked paths
- JSON output for both path results and full graph exports

Examples:

```bash
./lab-cli graph paths --goal node
./lab-cli graph paths --goal secret --namespace tenant-a --top 3
./lab-cli graph paths --format json
./lab-cli graph export --format json --namespace tenant-a
```

### Phase 4 Explanation And Diff

Phase 4 adds two operator-facing workflows:

1. Explain a path in human terms and map it back to the lab’s concrete attack scenarios.
2. Diff graph snapshots before and after an operation such as `start`, `attack`, or `reset`.

Examples:

```bash
./lab-cli graph explain --goal node
./lab-cli graph explain --goal secret --format json
./lab-cli graph export --format json > before.json
./lab-cli attack exec
./lab-cli graph diff --before before.json
```

The explanation output is built from the actual path edges and includes related `lab-cli attack ...` commands when a path matches one of the implemented scenarios.

Snapshot diffing works against the JSON export format. This is intended for before/after comparisons of live cluster state.

Rule construction starts in [internal/attackgraph/build.go](/internal/attackgraph/build.go:18).

### Example Path Shape

Typical paths look like:

```text
ServiceAccount tenant-a/tenant-sa
  -> Permission create pods
  -> Capability Create arbitrary pod
  -> Capability Create privileged hostPath pod
  -> Impact Node compromise
```

### Current Scope

The current implementation is deliberately bounded:

- in-memory only
- no persistent graph storage
- explicit rules for the lab’s known abuse cases
- workload-aware secret and ConfigMap consumer detection
- improved path scoring and goal aliases
- terminal output plus Mermaid, DOT, and JSON export
- explanation output and snapshot diffs
- default starting point is `tenant-sa`

Search and ranking logic starts in [internal/attackgraph/search.go](/internal/attackgraph/search.go:8).

## Development Notes

### Build

```bash
go build ./...
```

### Format

```bash
gofmt -w ./cmd ./internal
```

### Main Entry Points

- lab bootstrap: [internal/cluster/start.go](/internal/cluster/start.go:5)
- scenario dispatch: [internal/commands/attack.go](/internal/commands/attack.go:8)
- token simulation helper: [internal/cluster/serviceaccount_tokens.go](/internal/cluster/serviceaccount_tokens.go:12)

## Limitations

- the scanner is intentionally basic and only checks one RBAC smell
- some scenarios create their own victim workloads at runtime rather than deploying a full multi-service application stack
- the lab is optimized for clarity, not realism at scale
- several scenarios are independent demonstrations rather than a single chained kill chain

## Safety

- use a disposable cluster
- do not point this tool at production
- expect secrets, RBAC, and workloads in `tenant-a` and `tenant-b` to be modified or deleted during testing

## Suggested Workflow

1. Create a local cluster.
2. Run `./lab-cli start`.
3. Run `./lab-cli scan`.
4. Execute one scenario at a time.
5. Use `./lab-cli reset` between scenarios.
6. Use [manualtests.md](/manualtests.md:1) to reproduce the same exploit path manually.
7. Run `./lab-cli destroy` when finished.
