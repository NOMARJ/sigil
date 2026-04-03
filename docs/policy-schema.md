# Sigil Policy Schema

Sigil sandbox policies are defined in YAML and control what an AI agent can access at runtime. Policies are organized into four sections, each governing a different resource type.

## Policy Sections

| Section | Purpose | Mutability |
|---------|---------|------------|
| `filesystem` | Controls read/write access to paths | Immutable at sandbox creation |
| `network` | Controls outbound network connections | Hot-reloadable at runtime |
| `process` | Controls user identity and syscalls | Immutable at sandbox creation |
| `credentials` | Controls environment variable exposure | Configurable |

> **Immutable** sections are locked when the sandbox starts and cannot be changed without recreating it. The **network** section can be updated while the sandbox is running.

## Minimal Example

```yaml
version: "1.0"
name: my-policy
```

All sections default to safe values when omitted.

## Preset Policies

Sigil ships three built-in presets that can be used directly or as a starting point for custom policies.

### Strict

No network access, minimal filesystem, all credentials denied.

```yaml
version: "1.0"
name: strict
description: "No network access, minimal filesystem, no credentials"
filesystem:
  read_only:
    - /usr
    - /lib
    - /etc
  read_write:
    - /tmp
  include_workdir: true
network:
  default_action: deny
  rules: []
process:
  run_as_user: sandbox
  run_as_group: sandbox
  deny_syscall_categories:
    - privilege_escalation
credentials:
  allowed_env: []
  denied_env:
    - "*"
  providers: []
```

### Standard

Common package registries and GitHub allowed, working credentials for typical CI workflows.

```yaml
version: "1.0"
name: standard
description: "Common endpoints allowed, working credentials"
filesystem:
  read_only:
    - /usr
    - /lib
    - /etc
    - /proc
  read_write:
    - /tmp
  include_workdir: true
network:
  default_action: deny
  rules:
    - name: github
      host: api.github.com
      port: 443
      access: read-write
      enforcement: enforce
    - name: pypi
      host: pypi.org
      port: 443
      access: read-only
      enforcement: enforce
    - name: npm
      host: registry.npmjs.org
      port: 443
      access: read-only
      enforcement: enforce
process:
  run_as_user: sandbox
  run_as_group: sandbox
  deny_syscall_categories:
    - privilege_escalation
credentials:
  allowed_env:
    - GITHUB_TOKEN
    - GH_TOKEN
  denied_env: []
  providers: []
```

### Permissive

Log-only mode with no enforcement. Useful for auditing what an agent actually accesses before writing a tighter policy.

```yaml
version: "1.0"
name: permissive
description: "Log-only mode, no enforcement — for auditing"
filesystem:
  read_only: []
  read_write: []
  include_workdir: true
network:
  default_action: log
  rules: []
process:
  run_as_user: null
  run_as_group: null
  deny_syscall_categories: []
credentials:
  allowed_env:
    - "*"
  denied_env: []
  providers: []
```

## Field Reference

### Top-level

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Policy format version. Must be `"1.0"`. |
| `name` | string | Yes | Human-readable policy name. Cannot be empty. |
| `description` | string | No | Optional description of the policy's purpose. |
| `filesystem` | object | No | Filesystem access controls. Defaults to workdir-only. |
| `network` | object | No | Network egress controls. Defaults to deny-all. |
| `process` | object | No | Process identity and syscall restrictions. |
| `credentials` | object | No | Environment variable exposure controls. |

### `filesystem`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `read_only` | string[] | `[]` | Paths mounted as read-only inside the sandbox. |
| `read_write` | string[] | `[]` | Paths mounted as read-write inside the sandbox. |
| `include_workdir` | bool | `true` | Automatically include the working directory as read-write. |

### `network`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `default_action` | string | `"deny"` | Action when no rule matches: `"deny"` or `"log"`. |
| `rules` | NetworkRule[] | `[]` | List of allowed endpoint rules. |

### `network.rules[]` (NetworkRule)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | Required | Human-readable rule name. |
| `host` | string | Required | Allowed hostname or IP address. Cannot be empty. |
| `port` | u16 | `443` | Allowed port number. |
| `access` | string | `"read-only"` | `"read-only"` (GET/HEAD/OPTIONS only) or `"read-write"` (all methods). |
| `enforcement` | string | `"enforce"` | `"enforce"` (block violations) or `"log"` (allow but record). |

### `process`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `run_as_user` | string | `null` | User identity inside the sandbox. |
| `run_as_group` | string | `null` | Group identity inside the sandbox. |
| `deny_syscall_categories` | string[] | `[]` | Syscall categories to block (e.g., `"privilege_escalation"`, `"dangerous_io"`). |

### `credentials`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_env` | string[] | `[]` | Environment variable names/patterns to expose. Use `"*"` to allow all. |
| `denied_env` | string[] | `[]` | Environment variable patterns to block. Use `"*"` to deny all. |
| `providers` | string[] | `[]` | Named credential provider bundles to include. |

## Validation Rules

When a policy is loaded, Sigil validates:

1. `version` must be `"1.0"`
2. `name` must not be empty
3. Every network rule must have a non-empty `host`
4. Network rule `access` must be `"read-only"` or `"read-write"`
5. Network rule `enforcement` must be `"enforce"` or `"log"`
