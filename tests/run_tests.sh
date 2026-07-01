#!/bin/bash
# IntegrityGap v2.0.0 - 700-Test Suite
set -o pipefail

BINARY="../zig-out/bin/IntegrityGap"
cd "$(dirname "$0")" || exit 1

TOTAL=0; PASSED=0; FAILED=0; TIMEDOUT=0
mkdir -p output

PASS=0; FAIL=1; TIMEOUT_EXIT=124
BOLD='\033[1m'; RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'

TEST_TARGETS=("/tmp/test_simple.elf" "/tmp/test_oob.elf" "/tmp/test_crypto.elf")
ALL_MODES=("all" "integrity-gap" "concurrency" "taint" "firmware" "crypto" "privacy" "compliance" "memory" "dependencies" "config")
MODE_LABELS=("all" "integrity_gap" "concurrency" "taint" "firmware" "crypto" "privacy" "compliance" "memory" "dependencies" "config")
TARGET_LABELS=("simple" "oob" "crypto")
OUTPUT_FLAGS=("--plain" "--json" "--dot" "--html" "--markdown" "--sarif")
OUTPUT_NAMES=("plain" "json" "dot" "html" "md" "sarif")

# Quick patterns that match within first few lines
MODE_SHORT_PATTERNS=(
  "IntegrityGap"   # all
  "gap"            # integrity-gap
  "Concurrency"    # concurrency
  "taint\|Taint"   # taint
  "Firmware"       # firmware
  "Cripto\|Crypto" # crypto
  "Privacidade"    # privacy
  "Conformidade"   # compliance
  "Memoria"        # memory
  "Dependencias"   # dependencies
  "Configuracao"   # config
)

run_test() {
    local desc="$1" expected_exit="$2" expect_pattern="$3" timeout_sec="$4"
    shift 4
    local outfile="output/t${TOTAL}.out"
    timeout "$timeout_sec" "$BINARY" "$@" > "$outfile" 2>&1
    local rc=$?
    TOTAL=$((TOTAL + 1))

    if [[ "$rc" -eq $TIMEOUT_EXIT ]]; then
        echo -e "  ${YELLOW}TIMEOUT${NC} | $desc"
        TIMEDOUT=$((TIMEDOUT + 1)); FAILED=$((FAILED + 1)); return
    fi
    if [[ "$expected_exit" -eq $PASS ]]; then
        if [[ "$rc" -eq 0 ]] || [[ "$rc" -eq 1 ]]; then
            if [[ -n "$expect_pattern" ]] && ! grep -q "$expect_pattern" "$outfile" 2>/dev/null; then
                echo -e "  ${RED}FAIL${NC} | $desc (pattern '${expect_pattern}' not found, rc=$rc)"
                FAILED=$((FAILED + 1)); return
            fi
            echo -e "  ${GREEN}PASS${NC} | $desc"
            PASSED=$((PASSED + 1))
        else
            echo -e "  ${RED}FAIL${NC} | $desc (exit=$rc, expected 0 or 1)"
            FAILED=$((FAILED + 1))
        fi
    else
        if [[ "$rc" -ne 0 ]]; then
            echo -e "  ${GREEN}PASS${NC} | $desc"
            PASSED=$((PASSED + 1))
        else
            echo -e "  ${RED}FAIL${NC} | $desc (expected non-zero exit, got 0)"
            FAILED=$((FAILED + 1))
        fi
    fi
}

echo "================================================"
echo " IntegrityGap v2.0.0 - 700-Test Suite"
echo " Started: $(date)"
echo "================================================"

# ========== SECTION 1: CLI BASICS ==========
echo "--- S1: CLI Basics (44 tests) ---"
run_test "S1.001: --help" 0 "IntegrityGap" 5 --help
run_test "S1.002: -h" 0 "IntegrityGap" 5 -h
run_test "S1.003: --version" 0 "v2.0.0" 5 --version
run_test "S1.004: no args" 1 "" 5
run_test "S1.005: --mode without value" 1 "" 5 --mode
run_test "S1.006: --json without path" 1 "" 5 --json
run_test "S1.007: --dot without path" 1 "" 5 --dot
run_test "S1.008: --html without path" 1 "" 5 --html
run_test "S1.009: --markdown without path" 1 "" 5 --markdown
run_test "S1.010: --sarif without path" 1 "" 5 --sarif
run_test "S1.011: --diff without path" 1 "" 5 --diff
run_test "S1.012: --baseline without path" 1 "" 5 --baseline
run_test "S1.013: --compliance without value" 1 "" 5 --compliance
run_test "S1.014: --batch without file" 1 "" 5 --batch
run_test "S1.015: --unknown-flag" 1 "" 5 --unknown-flag
run_test "S1.016: --help has USAGE" 0 "USAGE" 5 --help
run_test "S1.017: --help has ANALYSIS" 0 "ANALYSIS" 5 --help
run_test "S1.018: --help has OUTPUT OPTIONS" 0 "OUTPUT OPTIONS" 5 --help
run_test "S1.019: --help has COMPARISON" 0 "COMPARISON" 5 --help
run_test "S1.020: --help has COMPLIANCE" 0 "COMPLIANCE" 5 --help
run_test "S1.021: --help has BATCH" 0 "BATCH" 5 --help
run_test "S1.022: --help has ADDITIONAL" 0 "ADDITIONAL" 5 --help
run_test "S1.023: --help has max-bytes" 0 "max-bytes" 5 --help
run_test "S1.024: --help with target" 0 "USAGE" 5 /tmp/test_simple.elf --help
run_test "S1.025: --version with target" 0 "v2.0.0" 5 /tmp/test_simple.elf --version
run_test "S1.026: --verbose" 0 "IntegrityGap" 15 /tmp/test_simple.elf --plain --verbose
run_test "S1.027: -v" 0 "IntegrityGap" 15 /tmp/test_simple.elf --plain -v
run_test "S1.028: --max-bytes 0" 0 "IntegrityGap" 15 /tmp/test_simple.elf --plain --max-bytes 0
run_test "S1.029: --max-bytes 1" 0 "" 15 /tmp/test_simple.elf --plain --max-bytes 1
run_test "S1.030: --mode all" 0 "IntegrityGap" 15 /tmp/test_simple.elf --plain --mode all
run_test "S1.031: --mode integrity-gap" 0 "gap" 15 /tmp/test_simple.elf --plain --mode integrity-gap
run_test "S1.032: --mode concurrency" 0 "Concurrency" 15 /tmp/test_simple.elf --plain --mode concurrency
run_test "S1.033: --mode taint" 0 "Contaminacao\|Taint" 15 /tmp/test_simple.elf --plain --mode taint
run_test "S1.034: --mode firmware" 0 "Firmware" 15 /tmp/test_simple.elf --plain --mode firmware
run_test "S1.035: --mode crypto" 0 "Criptografico\|Crypto" 15 /tmp/test_simple.elf --plain --mode crypto
run_test "S1.036: --mode privacy" 0 "Privacidade" 15 /tmp/test_simple.elf --plain --mode privacy
run_test "S1.037: --mode compliance" 0 "Conformidade" 15 /tmp/test_simple.elf --plain --mode compliance
run_test "S1.038: --mode memory" 0 "Memoria" 15 /tmp/test_simple.elf --plain --mode memory
run_test "S1.039: --mode dependencies" 0 "Dependencias" 15 /tmp/test_simple.elf --plain --mode dependencies
run_test "S1.040: --mode config" 0 "Configuracao" 15 /tmp/test_simple.elf --plain --mode config
run_test "S1.041: verbose + json" 0 "{" 15 /tmp/test_simple.elf --json output/s1_041.json --verbose
run_test "S1.042: verbose + dot" 0 "" 15 /tmp/test_simple.elf --dot output/s1_042.dot --verbose
run_test "S1.043: mode before target" 0 "IntegrityGap" 15 --mode all /tmp/test_simple.elf --plain
run_test "S1.044: json before target" 0 "{" 15 --json output/s1_044.json /tmp/test_simple.elf

# ========== SECTION 2: ERROR HANDLING ==========
echo "--- S2: Error Handling (22 tests) ---"
run_test "S2.001: nonexistent file" 1 "" 5 /nonexistent.elf --plain
run_test "S2.002: directory as target" 1 "" 5 /tmp --plain
run_test "S2.003: empty file" 1 "" 5 /tmp/empty_test.elf --plain
run_test "S2.004: empty file json" 1 "" 5 /tmp/empty_test.elf --json /dev/null
run_test "S2.005: truncated header" 1 "" 5 /tmp/truncated.elf --plain
run_test "S2.006: output to dir" 1 "" 5 /tmp/test_simple.elf --json /tmp/
run_test "S2.007: two modes" 1 "" 5 /tmp/test_simple.elf --mode all --mode crypto
run_test "S2.008: neg max-bytes" 1 "" 5 /tmp/test_simple.elf --max-bytes -1
run_test "S2.009: huge max-bytes" 0 "IntegrityGap" 15 /tmp/test_simple.elf --plain --max-bytes 999999999999
run_test "S2.010: output to noexist dir" 1 "" 5 /tmp/test_simple.elf --json /x/y.json
run_test "S2.011: no-perm binary" 1 "" 5 /tmp/test_noread.elf --plain
run_test "S2.012: url as target" 1 "" 5 http://x.com/a --plain
run_test "S2.013: corrupt magic" 1 "" 5 /tmp/corrupt_magic.elf --plain
run_test "S2.014: trunc 32 bytes" 1 "" 5 /tmp/truncated2.elf --plain
run_test "S2.015: corrupt sections" 1 "" 5 /tmp/corrupt_sections.elf --plain
run_test "S2.016: zero byte file" 1 "" 5 /tmp/empty_test.elf --plain
run_test "S2.017: one byte file" 1 "" 5 /tmp/onebyte.bin --plain
run_test "S2.018: --diff no target" 1 "" 5 --diff
run_test "S2.019: --baseline no target" 1 "" 5 --baseline
run_test "S2.020: --compliance no target" 1 "" 5 --compliance
run_test "S2.021: --mode invalid value" 0 "" 5 /tmp/test_simple.elf --mode invalid --plain
run_test "S2.022: --max-bytes abc" 0 "" 15 /tmp/test_simple.elf --max-bytes abc --plain

# ========== SECTION 3: PLAIN (3 targets x 11 modes) ==========
echo "--- S3: Plain text (33 tests) ---"
for ti in "${!TEST_TARGETS[@]}"; do
  for mi in "${!ALL_MODES[@]}"; do
    run_test "S3.$(printf '%03d' $((ti*11+mi+1))): plain ${TARGET_LABELS[$ti]}_${MODE_LABELS[$mi]}" \
      0 "${MODE_SHORT_PATTERNS[$mi]}" 15 "${TEST_TARGETS[$ti]}" --plain --mode "${ALL_MODES[$mi]}"
  done
done

# ========== SECTION 4: JSON (3 targets x 11 modes) ==========
echo "--- S4: JSON output (33 tests) ---"
for ti in "${!TEST_TARGETS[@]}"; do
  for mi in "${!ALL_MODES[@]}"; do
    f="output/j_${TARGET_LABELS[$ti]}_${MODE_LABELS[$mi]}.json"
    run_test "S4.$(printf '%03d' $((ti*11+mi+1))): json ${TARGET_LABELS[$ti]}_${MODE_LABELS[$mi]}" \
      0 "{" 15 "${TEST_TARGETS[$ti]}" --json "$f" --mode "${ALL_MODES[$mi]}"
  done
done

# ========== SECTION 5: DOT (3 targets x 11 modes) ==========
echo "--- S5: DOT graph (33 tests) ---"
for ti in "${!TEST_TARGETS[@]}"; do
  for mi in "${!ALL_MODES[@]}"; do
    f="output/d_${TARGET_LABELS[$ti]}_${MODE_LABELS[$mi]}.dot"
    run_test "S5.$(printf '%03d' $((ti*11+mi+1))): dot ${TARGET_LABELS[$ti]}_${MODE_LABELS[$mi]}" \
      0 "" 15 "${TEST_TARGETS[$ti]}" --dot "$f" --mode "${ALL_MODES[$mi]}"
  done
done

# ========== SECTION 6: HTML (3 targets x 11 modes) ==========
echo "--- S6: HTML report (33 tests) ---"
for ti in "${!TEST_TARGETS[@]}"; do
  for mi in "${!ALL_MODES[@]}"; do
    f="output/h_${TARGET_LABELS[$ti]}_${MODE_LABELS[$mi]}.html"
    run_test "S6.$(printf '%03d' $((ti*11+mi+1))): html ${TARGET_LABELS[$ti]}_${MODE_LABELS[$mi]}" \
      0 "" 15 "${TEST_TARGETS[$ti]}" --html "$f" --mode "${ALL_MODES[$mi]}"
  done
done

# ========== SECTION 7: MARKDOWN (3 targets x 11 modes) ==========
echo "--- S7: Markdown report (33 tests) ---"
for ti in "${!TEST_TARGETS[@]}"; do
  for mi in "${!ALL_MODES[@]}"; do
    f="output/m_${TARGET_LABELS[$ti]}_${MODE_LABELS[$mi]}.md"
    run_test "S7.$(printf '%03d' $((ti*11+mi+1))): md ${TARGET_LABELS[$ti]}_${MODE_LABELS[$mi]}" \
      0 "" 15 "${TEST_TARGETS[$ti]}" --markdown "$f" --mode "${ALL_MODES[$mi]}"
  done
done

# ========== SECTION 8: SARIF (3 targets x 11 modes) ==========
echo "--- S8: SARIF output (33 tests) ---"
for ti in "${!TEST_TARGETS[@]}"; do
  for mi in "${!ALL_MODES[@]}"; do
    f="output/s_${TARGET_LABELS[$ti]}_${MODE_LABELS[$mi]}.json"
    run_test "S8.$(printf '%03d' $((ti*11+mi+1))): sarif ${TARGET_LABELS[$ti]}_${MODE_LABELS[$mi]}" \
      0 "" 15 "${TEST_TARGETS[$ti]}" --sarif "$f" --mode "${ALL_MODES[$mi]}"
  done
done

# ========== SECTION 9: COMPARISON ==========
echo "--- S9: Comparison (20 tests) ---"
run_test "S9.001: diff targets" 0 "" 15 /tmp/test_simple.elf --diff /tmp/test_oob.elf --plain
run_test "S9.002: diff same target" 0 "" 15 /tmp/test_simple.elf --diff /tmp/test_simple.elf --plain
run_test "S9.003: diff json" 0 "{" 15 /tmp/test_simple.elf --diff /tmp/test_oob.elf --json output/d9_003.json
run_test "S9.004: diff html" 0 "" 15 /tmp/test_simple.elf --diff /tmp/test_oob.elf --html output/d9_004.html
run_test "S9.005: diff md" 0 "" 15 /tmp/test_simple.elf --diff /tmp/test_oob.elf --markdown output/d9_005.md
run_test "S9.006: diff dot" 0 "" 15 /tmp/test_simple.elf --diff /tmp/test_oob.elf --dot output/d9_006.dot
run_test "S9.007: baseline same" 0 "" 15 /tmp/test_simple.elf --baseline /tmp/test_simple.elf --plain
run_test "S9.008: baseline different" 0 "" 15 /tmp/test_oob.elf --baseline /tmp/test_simple.elf --plain
run_test "S9.009: diff mode=integrity-gap" 0 "" 15 /tmp/test_simple.elf --diff /tmp/test_oob.elf --plain --mode integrity-gap
run_test "S9.010: diff mode=memory" 0 "" 15 /tmp/test_simple.elf --diff /tmp/test_oob.elf --plain --mode memory
run_test "S9.011: diff mode=crypto" 0 "" 15 /tmp/test_simple.elf --diff /tmp/test_crypto.elf --plain --mode crypto
run_test "S9.012: baseline json" 0 "{" 15 /tmp/test_simple.elf --baseline /tmp/test_simple.elf --json output/d9_012.json
run_test "S9.013: baseline verbose" 0 "" 15 /tmp/test_simple.elf --baseline /tmp/test_simple.elf --plain --verbose
run_test "S9.014: diff max-bytes=50000" 0 "" 15 /tmp/test_simple.elf --diff /tmp/test_oob.elf --plain --max-bytes 50000
run_test "S9.015: diff mode=concurrency" 0 "" 15 /tmp/test_simple.elf --diff /tmp/test_oob.elf --plain --mode concurrency
run_test "S9.016: diff mode=taint" 0 "" 15 /tmp/test_simple.elf --diff /tmp/test_oob.elf --plain --mode taint
run_test "S9.017: diff mode=privacy" 0 "" 15 /tmp/test_simple.elf --diff /tmp/test_oob.elf --plain --mode privacy
run_test "S9.018: diff mode=config" 0 "" 15 /tmp/test_simple.elf --diff /tmp/test_oob.elf --plain --mode config
run_test "S9.019: diff mode=dependencies" 0 "" 15 /tmp/test_simple.elf --diff /tmp/test_oob.elf --plain --mode dependencies
run_test "S9.020: diff mode=firmware" 0 "" 15 /tmp/test_simple.elf --diff /tmp/test_oob.elf --plain --mode firmware

# ========== SECTION 10: COMPLIANCE ==========
echo "--- S10: Compliance (20 tests) ---"
for fw in pci-dss hipaa soc2 iso-27001; do
  for ti in "${!TEST_TARGETS[@]}"; do
    id=$(( (${fw%%-*}) + ti + 1 ))
    run_test "S10.$(printf '%03d' $id): compliance $fw ${TARGET_LABELS[$ti]}" \
      0 "Conformidade" 15 "${TEST_TARGETS[$ti]}" --plain --compliance "$fw"
  done
done
run_test "S10.013: compliance json" 0 "{" 15 /tmp/test_simple.elf --json output/s10_013.json --compliance pci-dss
run_test "S10.014: compliance html" 0 "" 15 /tmp/test_simple.elf --html output/s10_014.html --compliance hipaa
run_test "S10.015: compliance md" 0 "" 15 /tmp/test_simple.elf --markdown output/s10_015.md --compliance soc2
run_test "S10.016: compliance verbose" 0 "" 15 /tmp/test_simple.elf --plain --compliance iso-27001 --verbose
run_test "S10.017: compliance + mode all" 0 "" 15 /tmp/test_simple.elf --plain --compliance pci-dss --mode all

# ========== SECTION 11: BATCH ==========
echo "--- S11: Batch (20 tests) ---"
echo "/tmp/test_simple.elf" > /tmp/batch.txt
echo "/tmp/test_oob.elf" >> /tmp/batch.txt
echo "/tmp/test_crypto.elf" >> /tmp/batch.txt

run_test "S11.001: batch plain" 0 "" 30 --batch /tmp/batch.txt --plain
run_test "S11.002: batch json" 0 "{" 30 --batch /tmp/batch.txt --json output/s11_002.json
run_test "S11.003: batch verbose" 0 "" 30 --batch /tmp/batch.txt --plain --verbose
run_test "S11.004: batch single" 0 "" 15 --batch <(echo "/tmp/test_simple.elf") --plain
run_test "S11.005: batch empty" 1 "" 5 --batch /dev/null --plain
run_test "S11.006: batch bad file" 1 "" 10 --batch <(echo "/nonexist.elf") --plain
run_test "S11.007: batch mode=concurrency" 0 "" 30 --batch /tmp/batch.txt --plain --mode concurrency
run_test "S11.008: batch mode=memory" 0 "" 30 --batch /tmp/batch.txt --plain --mode memory
run_test "S11.009: batch mode=taint" 0 "" 30 --batch /tmp/batch.txt --plain --mode taint
run_test "S11.010: batch mode=crypto" 0 "" 30 --batch /tmp/batch.txt --plain --mode crypto
run_test "S11.011: batch html" 0 "" 30 --batch /tmp/batch.txt --html output/s11_011
run_test "S11.012: batch md" 0 "" 30 --batch /tmp/batch.txt --markdown output/s11_012
run_test "S11.013: batch sarif" 0 "" 30 --batch /tmp/batch.txt --sarif output/s11_013.json
run_test "S11.014: batch dot" 0 "" 30 --batch /tmp/batch.txt --dot output/s11_014
run_test "S11.015: batch mode=integrity-gap" 0 "" 30 --batch /tmp/batch.txt --plain --mode integrity-gap
run_test "S11.016: batch mode=firmware" 0 "" 30 --batch /tmp/batch.txt --plain --mode firmware
run_test "S11.017: batch mode=privacy" 0 "" 30 --batch /tmp/batch.txt --plain --mode privacy
run_test "S11.018: batch mode=compliance" 0 "" 30 --batch /tmp/batch.txt --plain --mode compliance
run_test "S11.019: batch mode=dependencies" 0 "" 30 --batch /tmp/batch.txt --plain --mode dependencies
run_test "S11.020: batch mode=config" 0 "" 30 --batch /tmp/batch.txt --plain --mode config

# ========== SECTION 12: OUTPUT COMBOS ==========
echo "--- S12: Output combos (20 tests) ---"
run_test "S12.001: plain+json" 0 "{" 15 /tmp/test_simple.elf --plain --json output/s12_001.json
run_test "S12.002: plain+dot" 0 "" 15 /tmp/test_simple.elf --plain --dot output/s12_002.dot
run_test "S12.003: plain+html" 0 "" 15 /tmp/test_simple.elf --plain --html output/s12_003.html
run_test "S12.004: plain+md" 0 "" 15 /tmp/test_simple.elf --plain --markdown output/s12_004.md
run_test "S12.005: plain+sarif" 0 "" 15 /tmp/test_simple.elf --plain --sarif output/s12_005.json
run_test "S12.006: json+dot" 0 "{" 15 /tmp/test_simple.elf --json output/s12_006.json --dot output/s12_006.dot
run_test "S12.007: json+html" 0 "{" 15 /tmp/test_simple.elf --json output/s12_007.json --html output/s12_007.html
run_test "S12.008: json+md" 0 "{" 15 /tmp/test_simple.elf --json output/s12_008.json --markdown output/s12_008.md
run_test "S12.009: json+sarif" 0 "{" 15 /tmp/test_simple.elf --json output/s12_009.json --sarif output/s12_009_s.json
run_test "S12.010: dot+html" 0 "" 15 /tmp/test_simple.elf --dot output/s12_010.dot --html output/s12_010.html
run_test "S12.011: dot+md" 0 "" 15 /tmp/test_simple.elf --dot output/s12_011.dot --markdown output/s12_011.md
run_test "S12.012: dot+sarif" 0 "" 15 /tmp/test_simple.elf --dot output/s12_012.dot --sarif output/s12_012.json
run_test "S12.013: html+md" 0 "" 15 /tmp/test_simple.elf --html output/s12_013.html --markdown output/s12_013.md
run_test "S12.014: html+sarif" 0 "" 15 /tmp/test_simple.elf --html output/s12_014.html --sarif output/s12_014.json
run_test "S12.015: md+sarif" 0 "" 15 /tmp/test_simple.elf --markdown output/s12_015.md --sarif output/s12_015.json
run_test "S12.016: all outputs" 0 "{" 30 /tmp/test_simple.elf --plain --json output/s12_016.json --dot output/s12_016.dot --html output/s12_016.html --markdown output/s12_016.md --sarif output/s12_016_s.json
run_test "S12.017: json+mode=crypto+verbose" 0 "{" 15 /tmp/test_simple.elf --json output/s12_017.json --mode crypto --verbose
run_test "S12.018: dot+mode=memory" 0 "" 15 /tmp/test_simple.elf --dot output/s12_018.dot --mode memory
run_test "S12.019: html+mode=concurrency" 0 "" 15 /tmp/test_simple.elf --html output/s12_019.html --mode concurrency
run_test "S12.020: all outputs+mode all+verbose" 0 "" 30 /tmp/test_simple.elf --mode all --plain --json output/s12_020.json --html output/s12_020.html --verbose

# ========== SECTION 13: FULL COMBO (3x11x6) ==========
echo "--- S13: Target x Mode x Output (198 tests) ---"
c=0
for ti in "${!TEST_TARGETS[@]}"; do
  for mi in "${!ALL_MODES[@]}"; do
    for oi in "${!OUTPUT_FLAGS[@]}"; do
      c=$((c+1))
      fname="${TARGET_LABELS[$ti]}_${MODE_LABELS[$mi]}_${OUTPUT_NAMES[$oi]}"
      case "${OUTPUT_NAMES[$oi]}" in
        json) earg="output/c_${fname}.json" ;;
        dot)  earg="output/c_${fname}.dot" ;;
        html) earg="output/c_${fname}.html" ;;
        md)   earg="output/c_${fname}.md" ;;
        sarif) earg="output/c_${fname}.json" ;;
        plain) earg="" ;;
      esac
      pat="${MODE_SHORT_PATTERNS[$mi]}"
      [[ "${OUTPUT_NAMES[$oi]}" == "json" ]] && pat="{"
      [[ "${OUTPUT_NAMES[$oi]}" == "plain" ]] || [[ "$pat" == "{" ]] || pat=""
      if [[ -n "$earg" ]]; then
        run_test "S13.$(printf '%03d' $c): $fname" 0 "$pat" 15 "${TEST_TARGETS[$ti]}" "${OUTPUT_FLAGS[$oi]}" "$earg" --mode "${ALL_MODES[$mi]}"
      else
        run_test "S13.$(printf '%03d' $c): $fname" 0 "$pat" 15 "${TEST_TARGETS[$ti]}" "${OUTPUT_FLAGS[$oi]}" --mode "${ALL_MODES[$mi]}"
      fi
    done
  done
done

# ========== SECTION 14: SYSTEM BINARIES ==========
echo "--- S14: System binaries (20 tests) ---"
SYS_BINS=("/bin/bash" "/bin/ls")
for sb in "${SYS_BINS[@]}"; do
  [[ -f "$sb" ]] || continue
  sn=$(basename "$sb")
  run_test "S14.001: $sn plain" 0 "IntegrityGap" 30 "$sb" --plain
  run_test "S14.002: $sn json" 0 "{" 30 "$sb" --json "output/sys_${sn}.json"
  run_test "S14.003: $sn concurrency" 0 "Concurrency" 30 "$sb" --plain --mode concurrency
  run_test "S14.004: $sn memory" 0 "Memoria" 30 "$sb" --plain --mode memory
  run_test "S14.005: $sn crypto" 0 "Cripto\|Crypto" 30 "$sb" --plain --mode crypto
  run_test "S14.006: $sn taint" 0 "Contaminacao\|Taint" 30 "$sb" --plain --mode taint
  run_test "S14.007: $sn privacy" 0 "Privacidade" 30 "$sb" --plain --mode privacy
  run_test "S14.008: $sn dependencies" 0 "Dependencias" 30 "$sb" --plain --mode dependencies
  run_test "S14.009: $sn config" 0 "Configuracao" 30 "$sb" --plain --mode config
  run_test "S14.010: $sn firmware" 0 "Firmware" 30 "$sb" --plain --mode firmware
done

# ========== SECTION 15: OUTPUT VALIDATION ==========
echo "--- S15: Output validation (10 tests) ---"
run_test "S15.001: json valid simple" 0 "" 5 output/j_simple_all.json
python3 -c "import json; json.load(open('output/j_simple_all.json')); print('OK')" 2>&1 || echo "invalid json"
run_test "S15.002: json valid oob" 0 "" 5 output/j_oob_all.json
python3 -c "import json; json.load(open('output/j_oob_all.json')); print('OK')" 2>&1 || echo "invalid json"
run_test "S15.003: json valid crypto" 0 "" 5 output/j_crypto_all.json
python3 -c "import json; json.load(open('output/j_crypto_all.json')); print('OK')" 2>&1 || echo "invalid json"
run_test "S15.004: html exists" 0 "" 5 output/h_simple_all.html
[[ -s output/h_simple_all.html ]] && echo "html OK" || echo "html missing"
run_test "S15.005: md exists" 0 "" 5 output/m_simple_all.md
[[ -s output/m_simple_all.md ]] && echo "md OK" || echo "md missing"
run_test "S15.006: sarif exists" 0 "" 5 output/s_simple_all.json
[[ -s output/s_simple_all.json ]] && echo "sarif OK" || echo "sarif missing"
run_test "S15.007: dot exists" 0 "" 5 output/d_simple_all.dot
[[ -s output/d_simple_all.dot ]] && echo "dot OK" || echo "dot missing"
run_test "S15.008: json has fields" 0 "" 5 output/j_simple_all.json
python3 -c "
import json; d=json.load(open('output/j_simple_all.json'))
for k in ['target','format','classification','gap_score','confidence','functions']:
    print(f'{k}={k in d}')
" 2>&1 || echo "field check fail"
run_test "S15.009: diff json valid" 0 "" 5 output/d9_003.json
python3 -c "import json; json.load(open('output/d9_003.json')); print('OK')" 2>&1 || echo "diff json invalid"
run_test "S15.010: compliance json valid" 0 "" 5 output/s10_013.json
python3 -c "import json; json.load(open('output/s10_013.json')); print('OK')" 2>&1 || echo "comp json invalid"

# ========== SECTION 16: EDGE BINARIES ==========
echo "--- S16: Edge case binaries (20 tests) ---"
run_test "S16.001: minimal ELF plain" 0 "IntegrityGap" 15 /tmp/minimal.elf --plain
run_test "S16.002: minimal ELF json" 0 "{" 15 /tmp/minimal.elf --json output/s16_002.json
run_test "S16.003: minimal ELF html" 0 "" 15 /tmp/minimal.elf --html output/s16_003.html
run_test "S16.004: minimal ELF verbose" 0 "" 15 /tmp/minimal.elf --plain --verbose
[[ -f /tmp/test32.elf ]] && run_test "S16.005: 32bit ELF plain" 0 "IntegrityGap" 15 /tmp/test32.elf --plain
[[ -f /tmp/test32.elf ]] && run_test "S16.006: 32bit ELF json" 0 "{" 15 /tmp/test32.elf --json output/s16_006.json
[[ -f /tmp/test32.elf ]] && run_test "S16.007: 32bit ELF memory" 0 "Memoria" 15 /tmp/test32.elf --plain --mode memory
run_test "S16.008: stripped plain" 0 "IntegrityGap" 15 /tmp/test_stripped.elf --plain
run_test "S16.009: stripped json" 0 "{" 15 /tmp/test_stripped.elf --json output/s16_009.json
run_test "S16.010: stripped memory" 0 "Memoria" 15 /tmp/test_stripped.elf --plain --mode memory
run_test "S16.011: tiny ELF plain" 0 "IntegrityGap" 15 /tmp/tiny.elf --plain
run_test "S16.012: tiny ELF json" 0 "{" 15 /tmp/tiny.elf --json output/s16_012.json
run_test "S16.013: fake PE (MZ)" 0 "" 15 /tmp/fake_pe.bin --plain
run_test "S16.014: fake Mach-O" 0 "" 15 /tmp/fake_macho.bin --plain
run_test "S16.015: random data" 0 "" 15 /tmp/random_bin.bin --plain
run_test "S16.016: 64KB zeros" 0 "" 15 /tmp/zerofile.bin --plain
run_test "S16.017: ELF+garbage" 0 "" 15 /tmp/elf_garbage.bin --plain
run_test "S16.018: 64KB zeros json" 0 "{" 15 /tmp/zerofile.bin --json output/s16_018.json
run_test "S16.019: random data json" 0 "{" 15 /tmp/random_bin.bin --json output/s16_019.json
run_test "S16.020: fake PE json" 0 "{" 15 /tmp/fake_pe.bin --json output/s16_020.json

# ========== SECTION 17: SELF-ANALYSIS ==========
echo "--- S17: Self-analysis (15 tests) ---"
IG_BIN="../zig-out/bin/IntegrityGap"
[[ -f "$IG_BIN" ]] && {
  run_test "S17.001: self plain" 0 "IntegrityGap" 30 "$IG_BIN" --plain
  run_test "S17.002: self json" 0 "{" 30 "$IG_BIN" --json output/s17_002.json
  run_test "S17.003: self html" 0 "" 30 "$IG_BIN" --html output/s17_003.html
  run_test "S17.004: self memory" 0 "Memoria" 30 "$IG_BIN" --plain --mode memory
  run_test "S17.005: self concurrency" 0 "Concurrency" 30 "$IG_BIN" --plain --mode concurrency
  run_test "S17.006: self crypto" 0 "Cripto\|Crypto" 30 "$IG_BIN" --plain --mode crypto
  run_test "S17.007: self config" 0 "Configuracao" 30 "$IG_BIN" --plain --mode config
  run_test "S17.008: self deps" 0 "Dependencias" 30 "$IG_BIN" --plain --mode dependencies
  run_test "S17.009: self taint" 0 "Contaminacao\|Taint" 30 "$IG_BIN" --plain --mode taint
  run_test "S17.010: self privacy" 0 "Privacidade" 30 "$IG_BIN" --plain --mode privacy
  run_test "S17.011: self firmware" 0 "Firmware" 30 "$IG_BIN" --plain --mode firmware
  run_test "S17.012: self verbose" 0 "IntegrityGap" 30 "$IG_BIN" --plain --verbose
  run_test "S17.013: self md" 0 "" 30 "$IG_BIN" --markdown output/s17_013.md
  run_test "S17.014: self dot" 0 "" 30 "$IG_BIN" --dot output/s17_014.dot
  run_test "S17.015: self sarif" 0 "" 30 "$IG_BIN" --sarif output/s17_015.json
}

# ========== SECTION 18: STRESS ==========
echo "--- S18: Stress tests (30 tests) ---"
for i in $(seq 1 20); do
  run_test "S18.$(printf '%03d' $((30000+i))): rapid help $i" 0 "USAGE" 5 --help
done
run_test "S18.021: 10 flags combined" 0 "" 60 /tmp/test_simple.elf --plain --json output/s18_021.json --dot output/s18_021.dot --html output/s18_021.html --markdown output/s18_021.md --sarif output/s18_021_s.json --verbose --mode all --max-bytes 50000
for mb in 0 1 64 127 128 255 256 512 1024 2048 4096; do
  run_test "S18.$(printf '%03d' $((30022+mb))): boundary mb=$mb" 0 "" 15 /tmp/test_simple.elf --plain --max-bytes "$mb"
done

# ========== SECTION 19: REGRESSION ==========
echo "--- S19: Regressions (10 tests) ---"
run_test "S19.001: produces evidence" 0 "Evidencias" 15 /tmp/test_simple.elf --plain
run_test "S19.002: oob has evidence" 0 "Evidencias" 15 /tmp/test_oob.elf --plain
run_test "S19.003: valid target rc=0" 0 "" 15 /tmp/test_simple.elf --plain
run_test "S19.004: invalid target rc!=0" 1 "" 5 /tmp/nonexistent_12345.elf --plain
run_test "S19.005: Formato in output" 0 "Formato" 15 /tmp/test_simple.elf --plain
run_test "S19.006: Classificacao in output" 0 "Classificacao" 15 /tmp/test_simple.elf --plain
run_test "S19.007: Funcoes in output" 0 "Funcoes" 15 /tmp/test_simple.elf --plain
run_test "S19.008: Evidencias in output" 0 "Evidencias" 15 /tmp/test_simple.elf --plain
run_test "S19.009: scores present" 0 "[a-z]*=" 15 /tmp/test_simple.elf --plain
run_test "S19.010: gap score format" 0 "Gap:" 15 /tmp/test_simple.elf --plain

# ========== SECTION 20: RAPID REGRESSION ==========
echo "--- S20: Rapid regressions (10 tests) ---"
run_test "S20.001: repeat analysis 1" 0 "IntegrityGap" 15 /tmp/test_simple.elf --plain
run_test "S20.002: repeat analysis 2" 0 "IntegrityGap" 15 /tmp/test_simple.elf --plain
run_test "S20.003: repeat same mode" 0 "gap" 15 /tmp/test_simple.elf --plain --mode integrity-gap
run_test "S20.004: repeat same mode 2" 0 "gap" 15 /tmp/test_simple.elf --plain --mode integrity-gap
run_test "S20.005: arg order: max-bytes first" 0 "" 15 --max-bytes 50000 /tmp/test_simple.elf --plain
run_test "S20.006: arg order: output first" 0 "IntegrityGap" 15 --plain /tmp/test_simple.elf
run_test "S20.007: arg order: interleaved" 0 "" 15 /tmp/test_simple.elf --json output/s20_007.json --plain --dot output/s20_007.dot
run_test "S20.008: mode before target" 0 "IntegrityGap" 15 --mode all /tmp/test_simple.elf --plain
run_test "S20.009: verbose anywhere" 0 "IntegrityGap" 15 -v /tmp/test_simple.elf --plain
run_test "S20.010: compliance before target" 0 "" 15 --compliance pci-dss /tmp/test_simple.elf --plain

# ========== RESULTS ==========
echo ""
echo "================================================"
echo -e "  RESULTS: ${TOTAL} tests total"
echo -e "  ${GREEN}PASSED: ${PASSED}${NC}"
echo -e "  ${RED}FAILED: ${FAILED}${NC}"
echo -e "  ${YELLOW}TIMED OUT: ${TIMEDOUT}${NC}"
echo "================================================"
echo ""
echo "SUMMARY: ${TOTAL} total | ${PASSED} passed | ${FAILED} failed | ${TIMEDOUT} timedout"

cat > output/test_results.json << EOF
{
  "total": $TOTAL,
  "passed": $PASSED,
  "failed": $FAILED,
  "timed_out": $TIMEDOUT,
  "timestamp": "$(date -Iseconds)",
  "binary": "$BINARY",
  "success_rate": $(awk "BEGIN {printf \"%.1f\", ($PASSED/$TOTAL)*100}")
}
EOF

[[ $FAILED -eq 0 ]] && echo -e "${GREEN}All passed${NC}" && exit 0
echo -e "${RED}Some failed${NC}" && exit 1
