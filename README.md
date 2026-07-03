# IntegrityGap

Static binary analysis framework for ELF, PE, and Mach-O executables. Written in Zig 0.13.0 with no external dependencies.

## Build

Requires Zig 0.13.0 (https://ziglang.org/download/).

```bash
zig build
zig build -Doptimize=ReleaseFast
zig build -Doptimize=ReleaseSmall
```

The compiled binary is at `zig-out/bin/integritygap`.

### Tests

```bash
zig build test              # embedded test blocks in each source file
cd tests && bash run_tests.sh   # ~700 shell-based tests
```

## Source Organization

```

├── build.zig
├── LICENSE
├── README.md
├── src/
│   ├── main.zig                 # CLI entry point, argument parsing, orchestration (621 lines)
│   ├── types.zig                # Central type definitions, structs, enums, constants (565 lines)
│   ├── core/                    # Core analysis pipeline
│   │   ├── parser.zig           # ELF/PE/Mach-O binary parser (1148 lines)
│   │   ├── decoder.zig          # x86/x86_64/ARM64 instruction decoder (989 lines)
│   │   ├── analyzer.zig         # 10-dimension integrity gap scoring engine (888 lines)
│   │   ├── signatures.zig       # Known API import signatures and call categorization (192 lines)
│   │   └── utils.zig            # Integer reading, string utilities, hashing, entropy (228 lines)
│   ├── analysis/                # Specialized analysis engines
│   │   ├── concurrency_analyzer.zig   # Data races, lock analysis, deadlock detection (560 lines)
│   │   ├── taint_analyzer.zig         # Taint propagation from sources to sinks (505 lines)
│   │   ├── firmware_integrity.zig     # Firmware image format analysis (541 lines)
│   │   ├── crypto_auditor.zig         # Cryptographic algorithm and key analysis (562 lines)
│   │   ├── privacy_analyzer.zig       # PII detection, consent, data flow (439 lines)
│   │   ├── compliance_engine.zig      # PCI DSS, HIPAA, SOC2, ISO 27001 checks (530 lines)
│   │   ├── memory_safety.zig          # Buffer overflow, use-after-free, format string (447 lines)
│   │   ├── dependency_checker.zig     # CVE matching, license detection (352 lines)
│   │   └── config_auditor.zig         # Hardcoded credentials, insecure defaults (376 lines)
│   ├── output/
│   │   ├── reporter.zig          # JSON, plain text, DOT, CSV, diff output (529 lines)
│   │   └── report_engine.zig     # HTML, Markdown, SARIF, JUnit XML reports (1209 lines)
│   ├── postproc/
│   │   ├── false_positive_reducer.zig  # Context-based FP reduction (262 lines)
│   │   ├── cvss_scorer.zig             # CVSS v3.1/v3.0/v2.0 scoring (282 lines)
│   │   ├── threat_model.zig            # STRIDE classification, attack trees (203 lines)
│   │   └── remediation_engine.zig      # Remediation suggestion generation (234 lines)
│   └── infra/
│       ├── logging.zig            # Thread-safe file-rotating logger (171 lines)
│       ├── batch_analyzer.zig     # Multi-target batch processing (185 lines)
│       ├── result_cache.zig       # TTL-based analysis result cache (213 lines)
│       ├── config_file.zig        # Configuration file parser (198 lines)
│       └── plugin_system.zig      # Dynamic plugin loading with 8 hook points (192 lines)
├── tests/
│   └── run_tests.sh
├── examples/
│   └── sample_config.conf
```

## CLI Usage

### Synopsis

```
integritygap --target <binary> [mode] [output flags] [options]
integritygap --target <binary> --diff <other>
integritygap --target <binary> --baseline <known_clean>
integritygap --help
integritygap --version
```

### Modes

| Flag | Default pipeline additions |
|---|---|
| `--all` | All enabled engines (default) |
| `--integrity-gap` | 10-dimension core scoring only |
| `--concurrency` | Concurrency analysis engine |
| `--taint` | Taint propagation analysis |
| `--firmware` | Firmware image analysis |
| `--crypto` | Cryptographic audit |
| `--privacy` | Privacy compliance analysis |
| `--compliance` | Regulatory compliance checks |
| `--memory` | Memory safety analysis |
| `--dependencies` | Dependency/CVE scanning |
| `--config` | Configuration audit |

### Output Flags

| Flag | Format |
|---|---|
| `--json <path>` | JSON |
| `--plain` | Plain text to stdout |
| `--dot <path>` | Graphviz DOT |
| `--html <path>` | HTML |
| `--markdown <path>` | Markdown |
| `--sarif <path>` | SARIF v2.1.0 |
| `--csv <path>` | CSV |

### Options

| Flag | Effect |
|---|---|
| `--diff <path>` | Compare against another binary |
| `--baseline <path>` | Compare against known-clean baseline |
| `--batch <path>` | Process multiple targets from a batch file |
| `--firmware` | Enable firmware-specific analysis mode |
| `--max-bytes <N>` | Maximum bytes to read per target (default: 268435456) |
| `--verbose`, `-v` | Print progress to stderr |
| `--report-only` | Generate report from cached data, skip analysis |
| `--cache-enabled` | Enable result caching (default: enabled) |
| `--cache-directory <path>` | Cache storage directory |
| `--min-severity <level>` | Minimum severity threshold |
| `--max-findings <N>` | Maximum findings to report |
| `--fp-reduction` | Enable false positive reduction |
| `--enable-remediation` | Enable remediation suggestions |
| `--enable-cvss` | Enable CVSS scoring |
| `--config-file <path>` | Load configuration from file |

## Analysis Pipeline

The pipeline executes in this order:

1. **main.zig** — reads file, parses CLI flags, selects modes
2. **core/parser.zig** — detects format by magic bytes, parses headers/sections/symbols/imports
3. **core/decoder.zig** — decodes executable sections into instructions, detects function boundaries, builds call graph
4. **core/analyzer.zig** — profiles each function across 10 dimensions (error_handling, resource_lifecycle, input_validation, cryptographic, logging_auditability, cleanup, concurrency, memory_safety, configuration, supply_chain), collects evidence, classifies threat
5. **analysis/*.zig** — optional specialized engines (selected by mode flag)
6. **postproc/*.zig** — optional post-processing (FP reduction, CVSS, STRIDE, remediation, caching)
7. **output/reporter.zig** or **output/report_engine.zig** — serializes results to requested format

## Scoring System

The system produces scoring dimensions at two levels: per-function category scores (10 dimensions from CategoryScores aggregated into a single function gap) and engine-level scores (from each specialized analyzer).

### Per-Function Category Scores (CategoryScores in types.zig:323)

Every function receives a score from 0 to 100 per category. All 10 categories contribute to the function's aggregate gap via fixed weights:

| Category | Weight | What it measures |
|---|---|---|
| error_handling | 15% | Fraction of critical calls without return-value validation |
| resource_lifecycle | 12% | Fraction of resource acquires without matching release |
| cryptographic | 13% | Missing init/finalize/destroy, hardcoded IV, unchecked crypto calls |
| input_validation | 10% | Pointer dereference before validation, memcpy without bounds check |
| cleanup | 10% | Exit paths with unreleased resources |
| concurrency | 10% | Unsynchronized shared access, lock violations, deadlock patterns |
| memory_safety | 10% | Unbounded copies, format strings, use-after-free, buffer overflows |
| logging_auditability | 8% | High-risk operations without corresponding logging |
| configuration | 6% | Hardcoded credentials, insecure defaults, disabled security |
| supply_chain | 6% | Known CVEs in linked dependencies, unsigned libraries, license risk |

The aggregate gap per function is: `clamp100(Σ(category_score × weight))`.

### Local Normalization

If 4+ functions exist, scores are normalized against the local population:
- Functions near the average are penalized (35% retention)
- Functions significantly above average retain 28% of raw score plus up to 22 per z-score unit

### Engine-Level Scores

Each specialized analysis engine outputs its own score (0–100 or 0–100%). These engine-level scores also feed back into the corresponding per-function category scores at a reduced weight (8–10%) to ensure that engine-level findings influence the core aggregate gap, anomaly confidence, and threat classification:

| Engine | Score field | Range | Meaning |
|---|---|---|---|
| concurrency_analyzer | concurrency_gap_score | 0–100 | Severity of data races, lock violations, unguarded shared data |
| concurrency_analyzer | deadlock_potential | 0–100% | Likelihood of circular wait conditions from lock ordering |
| taint_analyzer | taint_gap_score | 0–100 | Severity of unvalidated taint propagation paths |
| crypto_auditor | crypto_gap_score | 0–100 | Weak ciphers, hardcoded keys, static IVs, missing auth |
| firmware_integrity | integrity_score | 0–100 | Hash mismatches, missing signatures, rollback risk |
| memory_safety | safety_gap_score | 0–100 | Buffer overflows, use-after-free, format string, integer errors |
| privacy_analyzer | privacy_gap_score | 0–100 | PII collection without consent, third-party sharing |
| privacy_analyzer | gdpr_compliance_score | 0–100% | GDPR technical control coverage |
| privacy_analyzer | ccpa_compliance_score | 0–100% | CCPA technical control coverage |
| privacy_analyzer | hipaa_compliance_score | 0–100% | HIPAA technical safeguard coverage |
| compliance_engine | overall_score | 0–100% | Average pass rate across all checked frameworks |
| compliance_engine | pci_dss/hipaa/soc2/iso_27001 score | 0–100% | Per-framework requirement pass rate (ComplianceReport.score) |
| dependency_checker | supply_chain_score | 0–100% | CVE-free dependency ratio, signature validity |
| config_auditor | config_security_score | 0–100% | Security control implementation rate across 12 controls |

### Threat Classification

The summary threat is decided by a rule-based decision tree in `classifyThreat()`:

1. If `aggregate < 15*scale` AND `max_conf < 35*scale` AND `material_ratio < 0.03` → `No_Material_Gap`
2. If binary has >1000 functions AND `aggregate < 5.0` AND `material_ratio < 0.01` → `No_Material_Gap`
3. If cryptographic > 40*scale AND resource > 30*scale AND error > 25*scale → `Ransomware`
4. If logging > 40*scale AND error > 40*scale → `RAT`
5. If resource > 50*scale AND error < 35*scale → `Dropper`
6. If max_conf > 70*scale AND aggregate < 35*scale AND material < 0.06 → `Implant`
7. If aggregate < 10 AND max_conf < 50 → `No_Material_Gap`
8. Default → `Legitimate_Anomalous`

`scale` is `adaptiveThreatScale(function_count) * systemic_boost`. The adaptive scale decreases for large binaries:
- >5000 functions: 0.78x
- >1000 functions: 0.88x
- <8 functions: 1.45x

### Confidence

`anomaly_confidence = clamp100(aggregate_gap * 1.25)` — derived from the mean aggregate across all functions, capped at 100.

## Input Formats

| Format | Variants |
|---|---|
| ELF | ELF32, ELF64 (little-endian and big-endian) |
| PE | PE32 (0x10b), PE32+ (0x20b) |
| Mach-O | 32-bit, 64-bit, fat/universal |

## Output Formats

### Plain Text (stdout)

```
IntegrityGap: ./target.bin
Format: elf64/x86_64  Entry: 0x401000
Classification: No_Material_Gap  Gap: 0.91  Confidence: 1.13
Scores: error=0.0 resource=0.0 input=9.0 crypto=0.0 logging=0.0 cleanup=0.0
Functions identified/analyzed: 16083/16083  Instructions: 449828  Evidences: 2727

Functions with material gap:
  0x11b6ba0-0x11b6c60 gap=20.50 conf=22.32 critical=2/2 resources=0/0 cleanup_dirty=0/0
    -> error_handling: Syscall/sysenter without visible return validation (sev=80)
    -> input_validation: Argument pointer deref before observable local validation (sev=55)

=== Concurrency Analysis ===
  Detected Races: 0 | Threading Issues: 0 | Concurrency Risk Score: 55.00
```

### JSON

Full structured output with tool metadata, binary metadata, per-function profiles, evidence items with CWE IDs, call graph edges, summary scores, threat classification, and engine-specific sections.

### HTML

Self-contained report with inline CSS, collapsible sections, severity color coding.

### Markdown

GitHub-flavored markdown report.

### CSV

Tabular output with function, finding type, severity, and score columns.

### SARIF

OASIS SARIF v2.1.0 format.

### JUnit XML

CI/CD integration format.

### DOT

Graphviz directed graph with function nodes and call edges.

## What Each Engine Detects

### concurrency_analyzer.zig
- Data races: unsynchronized shared memory access across threads
- Lock ordering violations: inconsistent lock acquisition order
- Double lock / lock leak: redundant or missing lock release
- Deadlock patterns: circular wait conditions
- Thread-unsafe APIs: calls from multi-threaded context
- Unguarded shared data access: writes without synchronization

### taint_analyzer.zig
Tracks data flow from 12 source types (network, file, user input, env var, registry, etc.) to 13 sink types (exec, file write, network send, SQL query, etc.). Reports unvalidated propagation paths.

### firmware_integrity.zig
Detects firmware format (UEFI FV, Intel ME, U-Boot, Android bootimg, cpio, initramfs). Checks: hash mismatches, missing signatures, certificate validation, rollback detection, backdoor strings.

When invoked with `--firmware` alone (without `--html`/`--md`/`--sarif`), firmware analysis runs standalone and produces its own output. When combined with `--html`/`--md`/`--sarif` in `--all` mode, firmware results are included in the comprehensive report alongside all other engines.

### crypto_auditor.zig
Identifies cipher algorithms (AES, DES, 3DES, RC4, ChaCha20, etc.). Detects: weak ciphers, hardcoded keys, static IVs, ECB mode, weak randomness, deprecated hashes, missing authentication, certificate validation bypass.

### privacy_analyzer.zig
Detects PII-related function patterns (email, SSN, credit card, health data, biometric, location, etc.). Checks: data collection/sharing functions, consent mechanisms, third-party SDK sharing (Google Analytics, Firebase, Facebook, etc.). Maps to GDPR, CCPA, HIPAA, LGPD, PIPEDA.

### compliance_engine.zig
Evaluates against framework requirements: PCI DSS (6 checks), HIPAA (6 checks), SOC2 (5 checks), ISO 27001 (4 checks). Checks: encryption usage, logging, access control, network security, configuration management.

### memory_safety.zig
Detects: unbounded string copies (strcpy, sprintf, gets), format string vulnerabilities, use-after-free (access within 10 instructions of free), double free, null pointer dereference, integer overflow in allocation size, stack buffer overflow (frame >512 bytes without canary).

### dependency_checker.zig
Matches dependency names against 30+ embedded CVE records (OpenSSL: CVE-2014-0160 Heartbleed, CVE-2022-3602; log4j: CVE-2021-44228; curl, zlib, libpng, libssh2, sqlite3, etc.). Detects dependency types by filename pattern. Identifies SPDX licenses.

**Note:** The CVE database is statically compiled into the binary at build time. It reflects known vulnerabilities up to the release date of this version (v2.1.0). There is no live update mechanism — the database is a snapshot, not a live feed. To update, rebuild the binary against the latest source.

### config_auditor.zig
Searches binary sections for hardcoded credential patterns (password, secret, api_key, token, connection_string). Detects insecure defaults (admin, root, default, debug), disabled security, verbose errors, permissive permissions. Produces security control inventory (12 controls).

## Post-Processing Modules

### false_positive_reducer.zig
Evaluates 10 context factors per evidence item: surrounding validation, compiler-optimized patterns, known library signatures, framework boilerplate, sanitizer checks, assertion guards, exception handling, indirect return use, RAII wrappers, FP signature matches. Adjusts confidence scores.

### cvss_scorer.zig
Computes CVSS v3.1 base, temporal, and environmental scores per finding. Supports v3.0 and v2.0. Produces vector strings and severity labels (none/low/medium/high/critical).

### threat_model.zig
Classifies findings into STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). Builds AND/OR attack trees. Performs PASTA risk analysis.

### remediation_engine.zig
Generates per-finding suggestions with priority (immediate/short-term/medium-term/long-term/informational), category (code change, config change, dependency update, etc.), and effort hour estimates.

## Infrastructure

### logging.zig
Thread-safe logger with 6 severity levels (debug/critical). File rotation at 10 MB, up to 5 backups. Mutex-based thread safety.

### batch_analyzer.zig
Processes multiple targets from a batch file. Modes: full, quick, integrity-only, compliance-only. Progress callbacks and per-target timing.

### result_cache.zig
TTL-based cache keyed by file content hash. Get, set, invalidate, clear operations. Configurable storage directory and entry lifetime.

### config_file.zig
Parses `.conf` files: comments (# or ;), key=value (prefixed with --), default target as bare value. Supports all CLI flags as keys.

### plugin_system.zig
Loads shared libraries (.so, .dylib, .dll) via `std.DynLib`. 8 hook points: pre/post analysis, pre/post function-profile, pre/post report, pre/post filter. Plugin manifest with name, version, author.

## Differences from v1.0.0

**Preserved:**
- 10-dimension per-function scoring methodology (6 original + 4 new: concurrency, memory_safety, configuration, supply_chain)
- 9 engine-level scores (taint, crypto, firmware, memory, privacy ×4, compliance, dependency, config)
- Threat classification decision tree (with adjusted thresholds)
- Call categorization and return-value checking
- CFG-based cleanup path analysis
- Known API signature database

**Added in v2.0.0:**
- 9 specialized analysis engines (concurrency, taint, firmware, crypto, privacy, compliance, memory, dependencies, config)
- 6 additional output formats (HTML, Markdown, CSV, SARIF, JUnit XML, DOT)
- 4 post-processing modules (FP reduction, CVSS, STRIDE, remediation)
- Plugin system, config file support, batch processing, result caching
- Modular file structure (27 files vs 1 file)
- All scores and thresholds adjusted for large binaries

## CVE Database

The dependency checker includes 29 hardcoded CVE entries (e.g., OpenSSL 1.1.1 → CVE-2022-3602)
compiled into the binary at build time. This is a static snapshot and is **not** dynamically updated.
The database was last reviewed for the v2.1.0 release. Rebuild the binary to refresh from source.

## License

Apache 2.0 — see LICENSE.
