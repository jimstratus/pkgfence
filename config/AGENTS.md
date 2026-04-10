<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-10 | Updated: 2026-04-10 -->

# config

## Purpose
Configuration files that define the registry schema, scanning defaults, and exclusion rules. These are shipped with the package (not gitignored). The actual runtime registry (`state/registry.yaml`) is gitignored and lives in the state directory.

## Key Files

| File | Description |
|------|-------------|
| `registry.schema.yaml` | JSON Schema (Draft-07) defining valid registry structure: roots, projects, ssh, github, publish sections |
| `registry.example.yaml` | Example registry with annotated entries — used as reference in README |
| `defaults.yaml` | Default scan configuration (tier defaults, timeouts) |
| `exclusions.yaml` | Global exclusion rules — patterns to filter from findings |

## For AI Agents

### Working In This Directory
- **Schema is authoritative:** `registry.schema.yaml` defines all valid registry fields. If adding new registry features, update the schema FIRST
- **Schema validated by `jsonschema`:** `scripts/lib/registry.py` loads and validates against this schema
- **`registry.example.yaml`** must stay in sync with the schema — update both together
- **SSH section properties:** `host`, `user`, `name` (required), `key_file`, `port`, `tier`, `scanner_user`, `use_sudo`, `acl_groups`, `bootstrap_method`, `discover_paths`, `note` (optional)
- **Publish section:** Currently only `type: scp` with `destination`, `key_file`, `remote_base`, `include`

### Testing Requirements
- `tests/test_registry_validation.py` validates schema loading and registry conformance
- After schema changes, run the full test suite — many tests construct registry dicts

### Common Patterns
- YAML files use `ruamel.yaml` with `typ="safe"` for schema loading (order doesn't matter)
- Schema uses `additionalProperties: false` on every object — new fields must be explicitly added

## Dependencies

### Internal
- Consumed by `scripts/lib/registry.py` (schema), `scripts/scan_command.py` (exclusions, defaults)

<!-- MANUAL: -->
