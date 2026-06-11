# IntegrityGap

**Static binary analyzer that detects behavioral integrity gaps in PE and ELF executables.**

Unlike traditional vulnerability scanners that look for known bad patterns, IntegrityGap analyzes what's *missing* — the error checks that were never written, the resources that were never freed, the cryptographic sequences left incomplete, the input validation that was skipped. It builds a per-function profile of behavioral completeness and produces an aggregate threat classification.

## Concept

IntegrityGap treats a binary as a behavioral artifact. Every function is scored across six dimensions of integrity:

| Dimension | What it measures |
|---|---|
| **Error handling** | Calls to critical APIs (network, file, crypto, process, memory) whose return values are never checked before the next relevant operation |
| **Resource lifecycle** | Imbalance between resource acquisition (`malloc`, `CreateFile`, `socket`, etc.) and release (`free`, `CloseHandle`, `closesocket`) within a function |
| **Input validation** | Pointer dereferencing before observable null/validity checks; memory copy operations without bounds checks |
| **Cryptographic** | Incomplete crypto sequences (init without final, operations without destroy, hardcoded IV patterns) |
| **Logging / auditability** | High-risk operations that lack corresponding logging calls in a binary that otherwise uses logging |
| **Cleanup** | Exit paths that leave acquired resources unreleased, especially on error branches |

Each function gets a **gap score** (0–100) per dimension. Scores are locally normalized against the binary's own function population to surface anomalous functions.

The aggregate produces a **threat classification**:

| Class | Meaning |
|---|---|
| `No_Material_Gap` | No meaningful integrity gaps detected |
| `Implant` | Sparse, high-confidence anomalies consistent with targeted implants |
| `Dropper` | Resource lifecycle imbalances suggestive of payload extraction |
| `RAT` | High-risk operations with poor error handling and no audit trail |
| `Ransomware` | Crypto + resource lifecycle + error handling anomalies |
| `Legitimate_Anomalous` | Deviations from local norms but no clear threat profile |

## Build

Requires [Zig 0.13.0](https://ziglang.org/download/).

```bash
zig build
```



## Usage

```
IntegrityGap --target <binary> [--json out.json] [--plain] [--dot out.dot]
IntegrityGap --target <binary> --diff <other> [--json diff.json]
IntegrityGap --target <binary> --baseline <known_clean> [--json diff.json]
```

### Options

| Flag | Description |
|---|---|
| `--target <path>` | PE/ELF binary to analyze |
| `--json <path>` | Structured JSON output |
| `--plain` | Human-readable summary |
| `--dot <path>` | Graphviz DOT graph of functions and gaps |
| `--diff <path>` | Compare against another binary |
| `--baseline <path>` | Compare target against a known-clean baseline |
| `--max-bytes <N>` | Maximum bytes to read (default: 256 MB) |
| `--verbose`, `-v` | Progress logs to stderr |
| `--help`, `-h` | Print usage |

### Examples

```bash
# Analyze a binary, default JSON output to stdout
./integritygap --target /bin/ls

# Analyze and save structured JSON
./integritygap --target sample.exe --json report.json

# Human-readable summary
./integritygap --target sample.exe --plain

# Compare against a known-clean baseline
./integritygap --target suspicious.bin --baseline clean.bin --json diff.json
```

## Output

JSON output contains per-function profiles with:

- **Function span** (start/end VA, instruction count)
- **Scores** for each of the six integrity dimensions
- **Aggregate gap** score and **anomaly confidence**
- **Evidence** list with specific addresses, categories, severity levels, and descriptions
- **Call graph** edges for cross-reference analysis
- **Summary** with threat classification

## License

CC BY-NC-ND 4.0 — see [LICENSE](LICENSE).
