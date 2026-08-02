# IntegrityGap v2.1.0

Static binary analysis framework for ELF, PE, and Mach-O executables that detects **missing security behaviors** (not just known vulnerabilities). Written in Zig 0.13.0 with zero external dependencies.

## What Makes This Different

Traditional binary analyzers look for **known bad patterns**.  
IntegrityGap looks for **what's missing** — gaps in error handling, resource cleanup, input validation, etc.

Uses a **10-dimension scoring system** evaluated across 12 specialized analysis engines.

## Build

Requires Zig 0.13.0 (https://ziglang.org/download/).

```bash
zig build
zig build -Doptimize=ReleaseFast
zig build -Doptimize=ReleaseSmall
```

Compiled binary: `zig-out/bin/integritygap`

### Tests

```bash
zig build test                      # embedded test blocks
cd tests && bash run_tests.sh       # ~700 integration tests
```

---

## CLI Usage

### Basic Syntax

```
integritygap --target <binary> [mode] [output] [options]
integritygap --target <binary> --diff <other>
integritygap --help
integritygap --version
```

### Modes

| Flag | What it adds |
|------|-------------|
| `--all` | All engines (default) |
| `--integrity-gap` | 10-dimension scoring only |
| `--concurrency` | Data race & lock analysis |
| `--taint` | Taint propagation tracking |
| `--firmware` | Firmware integrity checks |
| `--crypto` | Cryptographic audit |
| `--privacy` | PII & compliance detection |
| `--compliance` | PCI DSS, HIPAA, SOC2, ISO27001 |
| `--memory` | Buffer overflow, use-after-free |
| `--dependencies` | CVE & license scanning |
| `--config` | Hardcoded credentials |
| `--strings` | String extraction & classification |

### Output Formats

| Flag | Format |
|------|--------|
| `--json <path>` | JSON |
| `--html <path>` | Self-contained HTML report |
| `--markdown <path>` | GitHub-flavored markdown |
| `--sarif <path>` | OASIS SARIF v2.1.0 |
| `--csv <path>` | Tabular CSV |
| `--dot <path>` | Graphviz DOT (call graph) |
| `--plain` | Plain text to stdout |

### Options

| Flag | Effect |
|------|--------|
| `--diff <path>` | Compare against another binary |
| `--batch <path>` | Analyze multiple targets |
| `--verbose`, `-v` | Print progress |
| `--cache-enabled` | Enable result caching (default: on) |
| `--cache-directory <path>` | Cache storage location |
| `--fp-reduction` | Reduce false positives |
| `--enable-cvss` | CVSS v3.1/v3.0/v2.0 scoring |
| `--enable-remediation` | Remediation suggestions |
| `--config-file <path>` | Load settings from file |
| `--min-severity <level>` | Filter by severity |
| `--max-findings <N>` | Limit findings |

---

## 10-Dimension Scoring

Every function is scored 0-100 on these dimensions (fixed weights):

| Dimension | Weight | Measures |
|-----------|--------|----------|
| error_handling | 15% | Unchecked return values |
| resource_lifecycle | 12% | Acquire/release matching |
| cryptographic | 13% | Init/finalize, key handling |
| input_validation | 10% | Bounds checking, validation |
| cleanup | 10% | Exit path resource release |
| concurrency | 10% | Lock ordering, data races |
| memory_safety | 10% | Buffers, use-after-free |
| logging_auditability | 8% | High-risk operations logged |
| configuration | 6% | Hardcoded creds, defaults |
| supply_chain | 6% | CVE dependencies, licenses |

**Local Normalization:** Scores adjusted based on function population within binary. Functions significantly above/below average penalized/preserved accordingly.

**Aggregate Gap:** Sum of (dimension_score × weight), clamped 0-100.

**Threat Classification:** Decision tree produces: `No_Material_Gap`, `Legitimate_Anomalous`, `Ransomware`, `RAT`, `Dropper`, `Implant`.

---

## 12 Analysis Engines

### 1. Concurrency Analyzer (560 lines)
Detects:
- Data races (unsynchronized shared memory)
- Lock ordering violations
- Double locks, lock leaks
- Deadlock patterns
- Thread-unsafe API usage
- Unguarded shared data

### 2. Taint Analyzer (505 lines)
Tracks data flow:
- **12 source types:** network, file, user input, env var, registry, shared memory, pipe, socket, cmdline, untrusted pointer, stdin
- **13 sink types:** code exec, SQL injection, buffer write, format string, file write, network send, privilege elevation, etc.
- Reports unvalidated propagation paths with severity

### 3. Firmware Integrity (541 lines)
Analyzes firmware images:
- Format detection (UEFI FV, Intel ME, U-Boot, Android, cpio, initramfs)
- Hash mismatches
- Missing signatures
- Certificate validation
- Rollback detection
- Backdoor string detection

### 4. Crypto Auditor (562 lines)
Detects:
- Cipher algorithms (AES, DES, 3DES, RC4, ChaCha20, etc.)
- Weak ciphers
- Hardcoded keys
- Static IVs
- ECB mode usage
- Weak randomness
- Deprecated hashes
- Missing authentication
- Certificate bypass

### 5. Privacy Analyzer (439 lines)
Finds PII-related patterns:
- Email, SSN, credit card, health data, biometric, location
- Data collection/sharing functions
- Consent mechanisms
- Third-party SDK sharing (Google Analytics, Firebase, Facebook, etc.)
- Maps to: GDPR, CCPA, HIPAA, LGPD, PIPEDA

### 6. Compliance Engine (530 lines)
Evaluates regulatory frameworks:
- **PCI DSS** (6 checks)
- **HIPAA** (6 checks)
- **SOC2** (5 checks)
- **ISO 27001** (4 checks)
- Checks: encryption, logging, access control, network security, configuration management

### 7. Memory Safety (447 lines)
Detects:
- Unbounded string copies (strcpy, sprintf, gets)
- Format string vulnerabilities
- Use-after-free (access within 10 instructions of free)
- Double free
- Null pointer dereference
- Integer overflow in allocation size
- Stack buffer overflow (frame >512 bytes without canary)

### 8. Dependency Checker (352 lines)
Scans for:
- 29+ hardcoded CVE records (OpenSSL, log4j, curl, zlib, etc.)
- Dependency type detection (by filename)
- SPDX license identification

**Note:** CVE database is static (compiled at build time). No live updates. Rebuild to refresh.

### 9. Config Auditor (376 lines)
Finds:
- Hardcoded credentials (password, secret, api_key, token, connection_string)
- Insecure defaults (admin, root, default, debug)
- Disabled security
- Verbose error messages
- Permissive permissions
- 12-control security inventory

### 10. String Analyzer (514 lines)
Extracts and classifies strings:
- **12 string types:** URL, IPv4, IPv6, Email, Unix Path, Windows Path, Registry Key, Shell Command, Crypto Key, JWT, Hex, Base64
- Regex-free deterministic matching
- Severity scoring per type
- Interesting ratio calculation

### 11. False Positive Reducer (262 lines)
Context analysis:
- Surrounding validation checks
- Compiler-optimized patterns
- Known library signatures
- Framework boilerplate
- Sanitizer checks
- Assertion guards
- Exception handling
- RAII wrappers
- Known FP signatures

### 12. CVSS Scorer (282 lines)
Produces scores for v3.1, v3.0, v2.0:
- Base, temporal, environmental scores
- Vector strings
- Severity labels (none/low/medium/high/critical)

---

## Post-Processing

### Threat Model (STRIDE)
Classifies findings into:
- **Spoofing** — Identity spoofing
- **Tampering** — Data modification
- **Repudiation** — Action denial
- **Information Disclosure** — Data leakage
- **Denial of Service** — Service unavailability
- **Elevation of Privilege** — Unauthorized access

Builds AND/OR attack trees. Performs PASTA risk analysis.

### Remediation Engine
Per-finding suggestions with:
- Priority (immediate/short-term/medium-term/long-term/informational)
- Category (code change, config change, dependency update, etc.)
- Effort hour estimates

---

## Infrastructure

### Logging
- 6 severity levels (debug/critical)
- File rotation at 10 MB
- 5 backup files
- Thread-safe (mutex-based)

### Batch Processing
- Multiple target analysis
- Modes: full, quick, integrity-only, compliance-only
- Progress callbacks
- Per-target timing

### Result Caching
- TTL-based cache
- Keyed by file content hash
- Configurable TTL & storage
- Get, set, invalidate, clear operations

### Config Files
- Comments: `#` or `;`
- Key=value format: `--flag value`
- Supports all CLI flags
- Default target as bare value

### Plugin System
- Load `.so`, `.dylib`, `.dll` shared libraries
- 8 hook points:
  - pre_analysis, post_analysis
  - pre_function, post_function
  - pre_report, post_report
  - pre_filter, post_filter
- Plugin manifest: name, version, author
- Extensible architecture

---

## Binary Diffing

Compare two binaries to detect regressions:

```bash
integritygap --target old.bin --diff new.bin --json report.json
```

Output shows:
- Gap score changes per function
- Dimensions that improved/degraded
- Functions with material changes
- Security regression warnings

Useful for:
- Verifying patch effectiveness
- Detecting unintended security regressions
- Release candidate validation
- Security regression testing in CI/CD

---

## Analysis Quality

### Accuracy by Binary Type

| Binary Type | FP Rate | FN Rate | TP Rate |
|-------------|---------|---------|---------|
| Simple C (-O0) | 8-15% | 10-20% | 70-80% |
| Modern C++ | 15-25% | 20-35% | 55-70% |
| Optimized (-O3) | 20-35% | 30-50% | 45-65% |
| Obfuscated/Malware | 25-40% | 35-60% | 40-55% |

### Known Limitations

⚠️ **Function boundary detection** — Relies on prologue patterns; misses optimized leaf functions  
⚠️ **Interprocedural analysis** — Limited; tracks direct call chains only  
⚠️ **Exception handling** — C++ exceptions not fully modeled  
⚠️ **RAII patterns** — Zig/Rust cleanup not always visible  
⚠️ **Indirect calls** — Virtual methods and function pointers not resolved  
⚠️ **Compiler optimizations** — Inlining and dead code removal reduce accuracy  

### Best Used For

✅ **Exploratory binary analysis** — First-pass screening  
✅ **Malware classification** — Threat categorization  
✅ **Security audits** — With manual verification  
✅ **Binary diffing** — Regression detection  
✅ **Research** — Behavioral analysis  

### Not Recommended For

❌ **Automated gating** — Without human review  
❌ **Compliance evidence** — Unverified findings  
❌ **Legal proceedings** — Insufficient confidence  

---

## Source Organization

```
src/
├── main.zig                    # CLI entry, orchestration (621 lines)
├── types.zig                   # Type definitions (565 lines)
├── core/
│   ├── parser.zig              # Binary parsing (1148 lines)
│   ├── decoder.zig             # Instruction decoding (989 lines)
│   ├── analyzer.zig            # 10-dim scoring (888 lines)
│   ├── signatures.zig          # API signatures (192 lines)
│   └── utils.zig               # Utilities (228 lines)
├── analysis/                   # 10 specialized engines
│   ├── concurrency_analyzer.zig
│   ├── taint_analyzer.zig
│   ├── firmware_integrity.zig
│   ├── crypto_auditor.zig
│   ├── privacy_analyzer.zig
│   ├── compliance_engine.zig
│   ├── memory_safety.zig
│   ├── dependency_checker.zig
│   ├── config_auditor.zig
│   └── string_analyzer.zig
├── output/
│   ├── reporter.zig            # JSON, CSV, DOT (529 lines)
│   └── report_engine.zig       # HTML, Markdown, SARIF, JUnit (1209 lines)
├── postproc/
│   ├── false_positive_reducer.zig
│   ├── cvss_scorer.zig
│   ├── threat_model.zig
│   └── remediation_engine.zig
└── infra/
    ├── logging.zig
    ├── batch_analyzer.zig
    ├── result_cache.zig
    ├── config_file.zig
    └── plugin_system.zig
```

**Total:** 12,083 lines of Zig code, 27 files

---

## Output Examples

### Plain Text
```
IntegrityGap: ./target.bin
Format: elf64/x86_64  Entry: 0x401000
Classification: Legitimate_Anomalous  Gap: 42.1  Confidence: 67.3

Dimension Scores:
  error_handling: 35  resource_lifecycle: 28  cryptographic: 12  ...

Functions with material gap:
  0x11b6ba0-0x11b6c60 gap=52.3 severity=high
    → error_handling: Syscall without return validation (sev=80)
    → input_validation: Pointer deref before checks (sev=75)
```

### JSON
Full structured output with metadata, per-function profiles, evidence items (CWE IDs), call graph, summary scores, threat classification, engine-specific sections.

### HTML
Self-contained report with inline CSS, collapsible sections, severity color coding, interactive diagrams.

### SARIF
OASIS SARIF v2.1.0 format for CI/CD integration and tooling compatibility.

---

## Threat Classification

Decision tree produces one of:

- **No_Material_Gap** — Aggregate <15, confidence <35, <3% material functions
- **Legitimate_Anomalous** — Code with minor gaps, no clear exploit path
- **Ransomware** — High crypto + resource scoring + error handling gaps
- **RAT** — Logging gaps + error handling issues (command & control)
- **Dropper** — Resource handling + low error handling (payload delivery)
- **Implant** — High confidence anomalies + low aggregate (sophisticated attacker)

Thresholds adapt for binary size (penalty at 5000+ functions, bonus at <8 functions).

---

## What Changed from v2.0.0

**Preserved:**
- 10-dimension scoring methodology
- 9 engine-level scores
- Threat classification tree
- Call categorization
- CFG-based cleanup analysis
- API signature database

**Added in v2.0.0:**
- 9 specialized analysis engines

**Added in v2.1.0:**
- String extraction & classification (12 types)
- 6 output formats (HTML, Markdown, CSV, SARIF, JUnit, DOT)
- 4 post-processing modules (FP reduction, CVSS, STRIDE, remediation)
- Plugin system (8 hook points)
- Config file support
- Batch processing
- Result caching
- Modular file structure (27 files vs 1 file)
- Adjusted scoring for large binaries (>5000 functions)

---

## Known Issues

**v2.1.0 limitations to fix in v3.0.0:**

- ⚠️ Interprocedural dataflow — currently basic (direct call chains only)
- ⚠️ Exception handling — flags exist, `.eh_frame` parsing not implemented
- ⚠️ Compiler optimization detection — not yet implemented
- ⚠️ Symbolic execution — not implemented
- ⚠️ Incremental analysis — basic caching only
- ⚠️ Machine learning scoring — planned for v3.1

---

## License

Apache 2.0 — see LICENSE file

---

## Quick Start

```bash
# Analyze a binary with all engines
integritygap --target /bin/ls --all --html report.html

# Check for compliance issues
integritygap --target app.exe --compliance --json findings.json

# Compare two versions
integritygap --target old.bin --diff new.bin --markdown diff.md

# Batch analysis
integritygap --batch binaries.txt --all --json results.json

# Enable caching for repeated runs
integritygap --target binary.bin --cache-enabled --cache-directory ./cache
```

---

**Version:** 2.1.0  
**Build Date:** July 2026  
**Language:** Zig 0.13.0  
**Dependencies:** Zero external  
**License:** Apache 2.0
