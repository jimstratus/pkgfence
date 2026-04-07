# osv-scanner reference

Google's [osv-scanner](https://github.com/google/osv-scanner) is pkgfence Phase 1's primary local scanner. v2.0.0+ is required.

## Install on Windows (recommended: scoop)

```bash
scoop install osv-scanner
```

This pins the binary to a known scoop manifest hash and installs to `C:/Users/<user>/scoop/apps/osv-scanner/current/osv-scanner.exe`. The scoop shim wraps it at `C:/Users/<user>/scoop/shims/osv-scanner`.

Verify:

```bash
osv-scanner --version
# osv-scanner version 2.3.3
# Engine: osv-scalibr 0.4.2
```

## Pkgfence integration

`scripts/scan_local.py` invokes osv-scanner via subprocess:

```python
subprocess.run(
    ["osv-scanner", "-L", lockfile_path, "--format", "json"],
    capture_output=True, text=True, timeout=300, check=False,
)
```

The `-L <path>` flag scans a single lockfile in detached mode. The `--format json` flag emits machine-parseable output.

## Exit code semantics (CRITICAL)

osv-scanner v2.3.3 uses exit codes that DIFFER from common subprocess conventions:

| Exit | Meaning | pkgfence handling |
|---|---|---|
| `0` | Scan completed, **no vulnerabilities found** | Success — parse JSON |
| `1` | Scan completed, **vulnerabilities FOUND** | **SUCCESS, NOT ERROR** — parse JSON |
| `2` | Scanner internal error | Raise `ScannerError` |
| `127` | Binary not found in PATH | Raise `ScannerError` |
| `128` | "No package sources found" — empty/malformed lockfile | Raise `EmptyLockfileError`, Task 8.5 emits SCAN_ERROR Finding |

The `OSV_SUCCESS_EXIT_CODES = {0, 1}` constant in `scripts/scan_local.py` is load-bearing. **Without exit-1 handling, every successful scan with findings would falsely report as a scanner error.**

## JSON output shape

```json
{
  "results": [
    {
      "source": {
        "path": "/path/to/package-lock.json",
        "type": "lockfile"
      },
      "packages": [
        {
          "package": {
            "name": "lodash",
            "version": "4.17.10",
            "ecosystem": "npm"
          },
          "vulnerabilities": [
            {
              "id": "GHSA-jf85-cpcp-j695",
              "summary": "Prototype Pollution in lodash",
              "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
              ],
              "aliases": ["CVE-2019-10744"],
              "affected": [...]
            }
          ]
        }
      ]
    }
  ]
}
```

`scripts/scan_local.py::parse_osv_output(raw_json, manifest_path, target)` walks this shape and produces a list of normalized Finding records using `scripts.lib.types.new_finding()`.

## Severity extraction

osv-scanner emits `severity[].score` as either a CVSS vector string or a numeric string. `_extract_severity()` parses the first numeric value found and maps:

- `≥9.0` → `critical`
- `≥7.0` → `high`
- `≥4.0` → `medium`
- `>0` → `low`
- else → `info`

If no severity is provided, defaults to `medium`.

## Empty lockfile gotcha

osv-scanner v2.3.3 returns exit 128 with stderr `"No package sources found"` (and empty stdout) when given a lockfile that has zero packages or invalid JSON. This is NOT exit 0, NOT exit 1, NOT exit 2. Pkgfence catches this with `EmptyLockfileError` (subclass of `ScannerError`) and `scan_manifest_safely()` converts it into a `SCAN_ERROR` Finding so the orchestrator can continue with other targets.

## OSV API fallback

When osv-scanner is not installed (`detect_scanner() returns None`), `scan_manifest()` falls back to direct OSV API queries via `OSVClient.querybatch()`. The MVP fallback only handles npm — `_parse_npm_lockfile_packages()` parses `package-lock.json` and produces `(name, version, ecosystem=npm)` query tuples.

Other ecosystems without an installed scanner raise `ScannerError`, which `scan_manifest_safely()` converts to a SCAN_ERROR Finding.

## Pinned hash (G9 soft guard)

`assets/scanner-hashes.json` records the SHA256 hash of the installed osv-scanner binary at install time (Task 1.5). Future runs MAY verify the binary against this hash before running it. Phase 1 does not enforce verification yet — the hash is recorded for documentation and for future Phase 2+ enforcement.
