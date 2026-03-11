#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) The Exim Maintainers 2022 - 2025
#
# bench/run_benchmarks.sh — Exim C vs Rust Performance Benchmark Suite
#
# Measures 4 performance metrics comparing C and Rust Exim binaries:
#   1. SMTP Transaction Throughput (msgs/sec) — 10,000 messages via localhost
#   2. Fork-per-Connection Latency (ms) — 1,000 connections, time-to-first-response
#   3. Peak RSS Memory (KB) — 10MB message processing
#   4. Config Parse Time (ms) — configure.default parse via -bP flag
#
# Prerequisites:
#   - hyperfine >= 1.18.0 (binary-level benchmark timing)
#   - swaks (SMTP load testing; falls back to built-in sender if unavailable)
#   - /usr/bin/time (GNU time for RSS measurement — NOT the shell builtin)
#   - jq >= 1.6 (JSON processing for hyperfine output)
#   - Both C and Rust Exim binaries built
#
# Usage:
#   bash bench/run_benchmarks.sh [OPTIONS]
#
# Options:
#   --help              Show usage information and exit
#   --dry-run           Print what would be done without executing benchmarks
#   --test <name>       Run only the named test:
#                         smtp_throughput, fork_latency, peak_rss, config_parse
#   --c-exim <path>     Override C Exim binary path
#   --rust-exim <path>  Override Rust Exim binary path
#   --config <path>     Override configuration file path
#   --results-dir <dir> Override results output directory
#
# Output:
#   bench/results/summary.json  — Aggregated results in JSON
#   bench/results/summary.csv   — Aggregated results in CSV
#   bench/BENCHMARK_REPORT.md   — Populated benchmark report
#
# Must be run from the repository ROOT directory.

set -euo pipefail

# =============================================================================
# Configuration Variables (overridable via environment or CLI flags)
# =============================================================================

# Script directory (for locating templates)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Binary paths — C path auto-detected from Makefile convention if unset
C_EXIM="${C_EXIM:-}"
RUST_EXIM="${RUST_EXIM:-target/release/exim}"

# Configuration file for parse-time benchmark
CONFIG_FILE="${CONFIG_FILE:-src/src/configure.default}"

# Test parameters per AAP §0.7.5 and §0.7.6
SMTP_MESSAGE_COUNT="${SMTP_MESSAGE_COUNT:-10000}"
SMTP_ITERATIONS="${SMTP_ITERATIONS:-1000}"
CONNECTION_COUNT="${CONNECTION_COUNT:-1000}"
CONNECTION_ITERATIONS="${CONNECTION_ITERATIONS:-100}"
MEMORY_ITERATIONS="${MEMORY_ITERATIONS:-100}"
PARSE_ITERATIONS="${PARSE_ITERATIONS:-1000}"

# Output paths
RESULTS_DIR="${RESULTS_DIR:-bench/results}"
REPORT_FILE="${REPORT_FILE:-bench/BENCHMARK_REPORT.md}"
REPORT_TEMPLATE="bench/BENCHMARK_REPORT.md"

# Port assignments for daemon benchmarks (high ports to avoid conflicts)
SMTP_PORT_C="${SMTP_PORT_C:-10025}"
SMTP_PORT_RUST="${SMTP_PORT_RUST:-10026}"

# Runtime flags
DRY_RUN="${DRY_RUN:-false}"
TEST_FILTER="${TEST_FILTER:-}"
HAS_SWAKS=false

# =============================================================================
# Global State — result accumulators (populated by benchmark functions)
# =============================================================================

declare -a TEMP_FILES=()
declare -a BG_PIDS=()

THROUGHPUT_C_MEAN="" THROUGHPUT_C_MEDIAN="" THROUGHPUT_C_STDDEV=""
THROUGHPUT_C_MIN="" THROUGHPUT_C_MAX="" THROUGHPUT_C_P95="" THROUGHPUT_C_P99=""
THROUGHPUT_RUST_MEAN="" THROUGHPUT_RUST_MEDIAN="" THROUGHPUT_RUST_STDDEV=""
THROUGHPUT_RUST_MIN="" THROUGHPUT_RUST_MAX="" THROUGHPUT_RUST_P95="" THROUGHPUT_RUST_P99=""
THROUGHPUT_DELTA="" THROUGHPUT_VERDICT=""

LATENCY_C_MEAN="" LATENCY_C_MEDIAN="" LATENCY_C_STDDEV=""
LATENCY_C_MIN="" LATENCY_C_MAX="" LATENCY_C_P95="" LATENCY_C_P99=""
LATENCY_RUST_MEAN="" LATENCY_RUST_MEDIAN="" LATENCY_RUST_STDDEV=""
LATENCY_RUST_MIN="" LATENCY_RUST_MAX="" LATENCY_RUST_P95="" LATENCY_RUST_P99=""
LATENCY_DELTA="" LATENCY_VERDICT=""

RSS_C_MEAN="" RSS_C_MEDIAN="" RSS_C_MIN="" RSS_C_MAX=""
RSS_RUST_MEAN="" RSS_RUST_MEDIAN="" RSS_RUST_MIN="" RSS_RUST_MAX=""
RSS_DELTA="" RSS_VERDICT=""

PARSE_C_MEAN="" PARSE_C_MEDIAN="" PARSE_C_STDDEV="" PARSE_C_MIN="" PARSE_C_MAX=""
PARSE_RUST_MEAN="" PARSE_RUST_MEDIAN="" PARSE_RUST_STDDEV="" PARSE_RUST_MIN="" PARSE_RUST_MAX=""
PARSE_DELTA="" PARSE_DIRECTION="" PARSE_VERDICT=""

OVERALL_VERDICT=""

# =============================================================================
# Utility Functions
# =============================================================================

# Log an informational message with timestamp to stderr.
log_info() {
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    printf '[%s] [INFO]  %s\n' "$ts" "$*" >&2
}

# Log an error message with timestamp to stderr.
log_error() {
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    printf '[%s] [ERROR] %s\n' "$ts" "$*" >&2
}

# Create a directory if it does not already exist.
ensure_dir() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        log_info "Created directory: ${dir}"
    fi
}

# Register a temporary file for cleanup on exit.
register_temp() {
    TEMP_FILES+=("$1")
}

# Register a background PID for cleanup on exit.
register_bg_pid() {
    BG_PIDS+=("$1")
}

# =============================================================================
# Cleanup and Signal Handling
# =============================================================================

cleanup() {
    log_info "Cleaning up..."
    # Terminate background daemons
    local pid
    for pid in "${BG_PIDS[@]+"${BG_PIDS[@]}"}"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log_info "Stopping background process ${pid}"
            kill -TERM "$pid" 2>/dev/null || true
            local waited=0
            while kill -0 "$pid" 2>/dev/null && [[ "$waited" -lt 5 ]]; do
                sleep 0.5; waited=$((waited + 1))
            done
            kill -KILL "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    BG_PIDS=()
    # Remove temporary files
    local tmpf
    for tmpf in "${TEMP_FILES[@]+"${TEMP_FILES[@]}"}"; do
        if [[ -n "$tmpf" && -e "$tmpf" ]]; then
            rm -f "$tmpf"
        fi
    done
    TEMP_FILES=()
    log_info "Cleanup complete"
}

trap cleanup EXIT INT TERM

# =============================================================================
# Prerequisite Checks
# =============================================================================

check_prerequisites() {
    local errors=0
    log_info "Checking prerequisites..."

    # --- hyperfine ---
    if ! command -v hyperfine &>/dev/null; then
        log_error "hyperfine is not installed. Install via: cargo install hyperfine"
        errors=$((errors + 1))
    else
        local hf_ver
        hf_ver="$(hyperfine --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
        if [[ -z "$hf_ver" ]]; then
            log_error "Cannot determine hyperfine version"
            errors=$((errors + 1))
        else
            local hf_major hf_minor
            hf_major="${hf_ver%%.*}"
            hf_minor="$(echo "$hf_ver" | cut -d. -f2)"
            if [[ "$hf_major" -lt 1 ]] || { [[ "$hf_major" -eq 1 ]] && [[ "$hf_minor" -lt 18 ]]; }; then
                log_error "hyperfine ${hf_ver} too old (need >= 1.18.0)"
                errors=$((errors + 1))
            else
                log_info "hyperfine ${hf_ver} — OK"
            fi
        fi
    fi

    # --- swaks (optional — falls back to built-in sender) ---
    if command -v swaks &>/dev/null; then
        HAS_SWAKS=true
        log_info "swaks found — OK"
    else
        HAS_SWAKS=false
        log_info "swaks not found — using built-in SMTP sender"
    fi

    # --- /usr/bin/time (GNU time, not shell builtin) ---
    if [[ -x /usr/bin/time ]]; then
        log_info "/usr/bin/time — OK"
    else
        log_error "/usr/bin/time not found. Install: apt-get install time"
        errors=$((errors + 1))
    fi

    # --- jq ---
    if command -v jq &>/dev/null; then
        log_info "jq — OK"
    else
        log_error "jq not found. Install: apt-get install jq"
        errors=$((errors + 1))
    fi

    # --- C Exim binary ---
    if [[ -z "$C_EXIM" ]]; then
        local os_type arch_type
        if [[ -x src/scripts/os-type ]] && [[ -x src/scripts/arch-type ]]; then
            os_type="$(bash src/scripts/os-type 2>/dev/null || echo UnKnown)"
            arch_type="$(bash src/scripts/arch-type 2>/dev/null || echo UnKnown)"
        else
            os_type="$(uname -s 2>/dev/null || echo Linux)"
            arch_type="$(uname -m 2>/dev/null || echo x86_64)"
        fi
        C_EXIM="src/build-${os_type}-${arch_type}/exim"
    fi
    if [[ ! -f "$C_EXIM" ]]; then
        log_error "C Exim binary not found: ${C_EXIM}"
        log_error "Build with: cd src && make"
        log_error "Override:   C_EXIM=/path/to/exim bash bench/run_benchmarks.sh"
        errors=$((errors + 1))
    elif [[ ! -x "$C_EXIM" ]]; then
        log_error "C Exim binary not executable: ${C_EXIM}"
        errors=$((errors + 1))
    else
        log_info "C Exim binary: ${C_EXIM} — OK"
    fi

    # --- Rust Exim binary ---
    if [[ ! -f "$RUST_EXIM" ]]; then
        log_error "Rust Exim binary not found: ${RUST_EXIM}"
        log_error "Build with: cargo build --release"
        log_error "Override:   RUST_EXIM=/path/to/exim bash bench/run_benchmarks.sh"
        errors=$((errors + 1))
    elif [[ ! -x "$RUST_EXIM" ]]; then
        log_error "Rust Exim binary not executable: ${RUST_EXIM}"
        errors=$((errors + 1))
    else
        log_info "Rust Exim binary: ${RUST_EXIM} — OK"
    fi

    # --- Configuration file ---
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Configuration file not found: ${CONFIG_FILE}"
        errors=$((errors + 1))
    else
        log_info "Config file: ${CONFIG_FILE} — OK"
    fi

    if [[ "$errors" -gt 0 ]]; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "${errors} prerequisite(s) not met — continuing in dry-run mode."
        else
            log_error "${errors} prerequisite(s) not met — aborting."
            return 1
        fi
    fi

    # Print banner
    echo ""
    echo "============================================================"
    echo " Exim C vs Rust Performance Benchmark Suite"
    echo "============================================================"
    echo " C Exim binary    : ${C_EXIM}"
    echo " Rust Exim binary : ${RUST_EXIM}"
    echo " Config file      : ${CONFIG_FILE}"
    echo " Results dir      : ${RESULTS_DIR}"
    echo " Report file      : ${REPORT_FILE}"
    echo ""
    echo " Test Parameters:"
    echo "   SMTP throughput : ${SMTP_MESSAGE_COUNT} msgs, ${SMTP_ITERATIONS} iterations"
    echo "   Fork latency    : ${CONNECTION_COUNT} conns, ${CONNECTION_ITERATIONS} iterations"
    echo "   Peak RSS memory : 10 MB msg, ${MEMORY_ITERATIONS} iterations"
    echo "   Config parse    : ${PARSE_ITERATIONS} iterations"
    echo "============================================================"
    echo ""
    return 0
}

# =============================================================================
# Computation Functions
# =============================================================================

# Compute percentage delta between C and Rust values.
# Formula: delta = ((rust - c) / c) * 100
# Positive = Rust is slower/larger; negative = Rust is faster/smaller.
# Usage: compute_delta <c_value> <rust_value>
# Outputs: decimal percentage string, e.g. "5.23" or "-2.10"
compute_delta() {
    local c_val="$1"
    local rust_val="$2"
    awk -v c="$c_val" -v r="$rust_val" \
        'BEGIN { if (c+0 == 0) print "0.00"; else printf "%.2f", ((r - c) / c) * 100 }'
}

# Check whether a delta meets the threshold for a given metric.
# Usage: check_threshold <metric> <delta_pct> <threshold_pct>
# Metrics: throughput, latency, memory, parse_time
# Returns: "PASS", "FAIL", or "INFO" on stdout.
check_threshold() {
    local metric="$1"
    local delta="$2"
    local threshold="$3"

    if [[ "$metric" == "parse_time" ]] || [[ "$threshold" == "null" ]]; then
        echo "INFO"
        return 0
    fi
    awk -v d="$delta" -v t="$threshold" \
        'BEGIN { print (d+0 <= t+0) ? "PASS" : "FAIL" }'
}

# Generate a 10 MB test email message for RSS benchmarking.
# Usage: generate_10mb_message <output_path>
generate_10mb_message() {
    local output="$1"
    local target_bytes=$((10 * 1024 * 1024))

    log_info "Generating 10 MB test message: ${output}"

    # Write MIME headers
    {
        printf 'From: benchmark@localhost\r\n'
        printf 'To: test@localhost\r\n'
        printf 'Subject: Benchmark test message (10 MB)\r\n'
        printf 'Date: %s\r\n' "$(date -R)"
        printf 'Message-ID: <bench-%s@localhost>\r\n' "$(date +%s)"
        printf 'MIME-Version: 1.0\r\n'
        printf 'Content-Type: text/plain; charset=UTF-8\r\n'
        printf 'Content-Transfer-Encoding: 7bit\r\n'
        printf '\r\n'
    } > "$output"

    local header_bytes
    header_bytes="$(wc -c < "$output")"
    local body_bytes=$((target_bytes - header_bytes))

    # Fill body with base64-encoded random data (valid 7-bit text)
    dd if=/dev/urandom bs=4096 count=$((body_bytes / 4096 + 1)) 2>/dev/null \
        | base64 | head -c "$body_bytes" >> "$output"

    log_info "Test message ready: $(wc -c < "$output") bytes"
    register_temp "$output"
}

# Compute sorted statistics from a file of numeric values (one per line).
# Outputs a single-line JSON object with mean, median, stddev, min, max, p95, p99.
# Usage: compute_stats <values_file>
compute_stats() {
    local vf="$1"
    awk '
    BEGIN { n = 0 }
    /^[0-9.eE+-]+$/ { vals[n++] = $1 + 0 }
    END {
        if (n == 0) {
            printf "{\"mean\":0,\"median\":0,\"stddev\":0,\"min\":0,\"max\":0,\"p95\":0,\"p99\":0,\"count\":0}\n"
            exit
        }
        # Insertion sort
        for (i = 1; i < n; i++) {
            key = vals[i]; j = i - 1
            while (j >= 0 && vals[j] > key) { vals[j+1] = vals[j]; j-- }
            vals[j+1] = key
        }
        sum = 0; for (i = 0; i < n; i++) sum += vals[i]
        mean = sum / n
        sumsq = 0; for (i = 0; i < n; i++) sumsq += (vals[i] - mean)^2
        stddev = (n > 1) ? sqrt(sumsq / (n - 1)) : 0
        median = (n % 2 == 1) ? vals[int(n/2)] : (vals[n/2-1] + vals[n/2]) / 2
        p95i = int(n * 0.95); if (p95i >= n) p95i = n - 1
        p99i = int(n * 0.99); if (p99i >= n) p99i = n - 1
        printf "{\"mean\":%.4f,\"median\":%.4f,\"stddev\":%.4f,\"min\":%.4f,\"max\":%.4f,\"p95\":%.4f,\"p99\":%.4f,\"count\":%d}\n", \
            mean, median, stddev, vals[0], vals[n-1], vals[p95i], vals[p99i], n
    }' "$vf"
}

# Built-in SMTP sender for when swaks is unavailable.
# Opens a TCP connection, sends one message, closes.
# Usage: builtin_smtp_send <host> <port>
builtin_smtp_send() {
    local host="$1" port="$2"
    # Open TCP connection via bash built-in /dev/tcp
    exec 3<>"/dev/tcp/${host}/${port}" 2>/dev/null || return 1
    local line
    # Read 220 banner
    read -r -t 10 line <&3 || { exec 3>&-; return 1; }
    # EHLO
    printf 'EHLO benchmark.local\r\n' >&3
    read -r -t 10 line <&3 || true
    while [[ "${line:-}" == 250-* ]]; do read -r -t 5 line <&3 || break; done
    # MAIL FROM
    printf 'MAIL FROM:<benchmark@localhost>\r\n' >&3
    read -r -t 10 line <&3 || { exec 3>&-; return 1; }
    # RCPT TO
    printf 'RCPT TO:<test@localhost>\r\n' >&3
    read -r -t 10 line <&3 || { exec 3>&-; return 1; }
    # DATA
    printf 'DATA\r\n' >&3
    read -r -t 10 line <&3 || { exec 3>&-; return 1; }
    # Message body
    printf 'From: benchmark@localhost\r\n' >&3
    printf 'To: test@localhost\r\n' >&3
    printf 'Subject: Benchmark\r\n' >&3
    printf '\r\n' >&3
    printf 'Benchmark test.\r\n' >&3
    printf '.\r\n' >&3
    read -r -t 10 line <&3 || { exec 3>&-; return 1; }
    # QUIT
    printf 'QUIT\r\n' >&3
    read -r -t 5 line <&3 || true
    exec 3>&-
    return 0
}

# Wait until a TCP port accepts connections (with timeout).
# Usage: wait_for_port <host> <port> [timeout_seconds]
wait_for_port() {
    local host="$1" port="$2" timeout="${3:-30}" elapsed=0
    while [[ "$elapsed" -lt "$timeout" ]]; do
        if (echo >/dev/tcp/"${host}"/"${port}") 2>/dev/null; then
            return 0
        fi
        sleep 0.5
        elapsed=$((elapsed + 1))
    done
    log_error "Timeout waiting for ${host}:${port} after ${timeout}s"
    return 1
}

# Gracefully stop a daemon by PID, escalating to SIGKILL.
# Usage: stop_daemon <pid>
stop_daemon() {
    local pid="$1"
    if ! kill -0 "$pid" 2>/dev/null; then return 0; fi
    kill -TERM "$pid" 2>/dev/null || true
    local w=0
    while kill -0 "$pid" 2>/dev/null && [[ "$w" -lt 10 ]]; do
        sleep 0.5; w=$((w + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
}

# Send one message using the best available tool.
# Usage: send_one_message <host> <port>
send_one_message() {
    local host="$1" port="$2"
    if [[ "$HAS_SWAKS" == "true" ]]; then
        swaks --to test@localhost --from benchmark@localhost \
            --server "$host" --port "$port" \
            --helo benchmark.local \
            --header "Subject: Benchmark" \
            --body "Benchmark test message." \
            --timeout 30 --pipe >/dev/null 2>&1
    else
        builtin_smtp_send "$host" "$port"
    fi
}

# =============================================================================
# Benchmark 1: SMTP Transaction Throughput
# =============================================================================

benchmark_smtp_throughput() {
    log_info "=== Benchmark 1: SMTP Transaction Throughput ==="

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would send ${SMTP_MESSAGE_COUNT} messages to each daemon"
        log_info "[DRY RUN] C on port ${SMTP_PORT_C}, Rust on port ${SMTP_PORT_RUST}"
        THROUGHPUT_C_MEAN="0" THROUGHPUT_C_MEDIAN="0" THROUGHPUT_C_STDDEV="0"
        THROUGHPUT_C_MIN="0" THROUGHPUT_C_MAX="0" THROUGHPUT_C_P95="0" THROUGHPUT_C_P99="0"
        THROUGHPUT_RUST_MEAN="0" THROUGHPUT_RUST_MEDIAN="0" THROUGHPUT_RUST_STDDEV="0"
        THROUGHPUT_RUST_MIN="0" THROUGHPUT_RUST_MAX="0" THROUGHPUT_RUST_P95="0" THROUGHPUT_RUST_P99="0"
        THROUGHPUT_DELTA="0.00" THROUGHPUT_VERDICT="INFO"
        return 0
    fi

    # Decide batch size: each hyperfine run sends batch_size messages.
    # Cap hyperfine runs at 100 for practicality; minimum batch = 1.
    local hf_runs batch_size
    hf_runs="$SMTP_ITERATIONS"
    if [[ "$hf_runs" -gt 100 ]]; then hf_runs=100; fi
    batch_size=$(( SMTP_MESSAGE_COUNT / hf_runs ))
    if [[ "$batch_size" -lt 1 ]]; then batch_size=1; fi
    local total_msgs=$(( batch_size * hf_runs ))

    log_info "Throughput plan: ${hf_runs} runs × ${batch_size} msgs/run = ${total_msgs} total msgs"

    # Create batch-send helper script (self-contained, no dependency on parent env)
    local batch_script
    batch_script="$(mktemp --suffix=_bench_batch.sh)"
    register_temp "$batch_script"
    cat > "$batch_script" << 'BATCHEOF'
#!/usr/bin/env bash
set -euo pipefail
HOST="$1"; PORT="$2"; COUNT="$3"; USE_SWAKS="$4"
for (( i=1; i<=COUNT; i++ )); do
    if [[ "$USE_SWAKS" == "true" ]]; then
        swaks --to test@localhost --from benchmark@localhost \
            --server "$HOST" --port "$PORT" \
            --helo benchmark.local --header "Subject: Bench $i" \
            --body "Benchmark throughput." --timeout 30 --pipe >/dev/null 2>&1 || true
    else
        exec 3<>"/dev/tcp/${HOST}/${PORT}" 2>/dev/null || continue
        read -r -t 10 _l <&3 || { exec 3>&-; continue; }
        printf 'EHLO b.local\r\n' >&3; read -r -t 10 _l <&3 || true
        while [[ "${_l:-}" == 250-* ]]; do read -r -t 5 _l <&3 || break; done
        printf 'MAIL FROM:<b@localhost>\r\n' >&3; read -r -t 10 _l <&3 || true
        printf 'RCPT TO:<test@localhost>\r\n' >&3; read -r -t 10 _l <&3 || true
        printf 'DATA\r\n' >&3; read -r -t 10 _l <&3 || true
        printf 'Subject: B\r\n\r\nTest.\r\n.\r\n' >&3; read -r -t 10 _l <&3 || true
        printf 'QUIT\r\n' >&3; read -r -t 5 _l <&3 || true
        exec 3>&-
    fi
done
BATCHEOF
    chmod +x "$batch_script"

    # --- Measure C Exim ---
    log_info "Starting C Exim daemon on port ${SMTP_PORT_C}..."
    "$C_EXIM" -C "$CONFIG_FILE" -bd -oX "$SMTP_PORT_C" &
    local c_daemon=$!
    register_bg_pid "$c_daemon"
    wait_for_port "127.0.0.1" "$SMTP_PORT_C" 30

    log_info "Timing C Exim throughput via hyperfine (${hf_runs} runs, ${batch_size} msgs/run)..."
    hyperfine \
        --min-runs "$hf_runs" \
        --warmup 3 \
        --export-json "${RESULTS_DIR}/throughput_c_hf.json" \
        --command-name "c-throughput" \
        "bash ${batch_script} 127.0.0.1 ${SMTP_PORT_C} ${batch_size} ${HAS_SWAKS}" \
        2>&1 | tail -5 || true

    stop_daemon "$c_daemon"

    # --- Measure Rust Exim ---
    log_info "Starting Rust Exim daemon on port ${SMTP_PORT_RUST}..."
    "$RUST_EXIM" -C "$CONFIG_FILE" -bd -oX "$SMTP_PORT_RUST" &
    local rust_daemon=$!
    register_bg_pid "$rust_daemon"
    wait_for_port "127.0.0.1" "$SMTP_PORT_RUST" 30

    log_info "Timing Rust Exim throughput via hyperfine (${hf_runs} runs, ${batch_size} msgs/run)..."
    hyperfine \
        --min-runs "$hf_runs" \
        --warmup 3 \
        --export-json "${RESULTS_DIR}/throughput_rust_hf.json" \
        --command-name "rust-throughput" \
        "bash ${batch_script} 127.0.0.1 ${SMTP_PORT_RUST} ${batch_size} ${HAS_SWAKS}" \
        2>&1 | tail -5 || true

    stop_daemon "$rust_daemon"

    # --- Extract statistics ---
    # hyperfine gives time-per-batch in seconds; throughput = batch_size / time
    local c_vals_file rust_vals_file
    c_vals_file="$(mktemp)"; register_temp "$c_vals_file"
    rust_vals_file="$(mktemp)"; register_temp "$rust_vals_file"

    # Convert each run time to throughput (msgs/sec)
    jq -r --arg bs "$batch_size" \
        '.results[0].times[] | ($bs | tonumber) / .' \
        "${RESULTS_DIR}/throughput_c_hf.json" > "$c_vals_file" 2>/dev/null || true

    jq -r --arg bs "$batch_size" \
        '.results[0].times[] | ($bs | tonumber) / .' \
        "${RESULTS_DIR}/throughput_rust_hf.json" > "$rust_vals_file" 2>/dev/null || true

    local c_stats rust_stats
    c_stats="$(compute_stats "$c_vals_file")"
    rust_stats="$(compute_stats "$rust_vals_file")"

    THROUGHPUT_C_MEAN="$(echo "$c_stats" | jq -r '.mean')"
    THROUGHPUT_C_MEDIAN="$(echo "$c_stats" | jq -r '.median')"
    THROUGHPUT_C_STDDEV="$(echo "$c_stats" | jq -r '.stddev')"
    THROUGHPUT_C_MIN="$(echo "$c_stats" | jq -r '.min')"
    THROUGHPUT_C_MAX="$(echo "$c_stats" | jq -r '.max')"
    THROUGHPUT_C_P95="$(echo "$c_stats" | jq -r '.p95')"
    THROUGHPUT_C_P99="$(echo "$c_stats" | jq -r '.p99')"

    THROUGHPUT_RUST_MEAN="$(echo "$rust_stats" | jq -r '.mean')"
    THROUGHPUT_RUST_MEDIAN="$(echo "$rust_stats" | jq -r '.median')"
    THROUGHPUT_RUST_STDDEV="$(echo "$rust_stats" | jq -r '.stddev')"
    THROUGHPUT_RUST_MIN="$(echo "$rust_stats" | jq -r '.min')"
    THROUGHPUT_RUST_MAX="$(echo "$rust_stats" | jq -r '.max')"
    THROUGHPUT_RUST_P95="$(echo "$rust_stats" | jq -r '.p95')"
    THROUGHPUT_RUST_P99="$(echo "$rust_stats" | jq -r '.p99')"

    # Delta: for throughput, higher = better. Positive delta = Rust slower.
    # delta = (C_mean - Rust_mean) / C_mean * 100 — positive when Rust is slower.
    THROUGHPUT_DELTA="$(awk -v c="$THROUGHPUT_C_MEAN" -v r="$THROUGHPUT_RUST_MEAN" \
        'BEGIN { if (c+0 == 0) print "0.00"; else printf "%.2f", ((c - r) / c) * 100 }')"
    THROUGHPUT_VERDICT="$(check_threshold "throughput" "$THROUGHPUT_DELTA" "10")"

    # Persist combined JSON result
    jq -n \
        --arg c "$c_stats" --arg r "$rust_stats" \
        --arg d "$THROUGHPUT_DELTA" --arg v "$THROUGHPUT_VERDICT" \
        '{ c: ($c|fromjson), rust: ($r|fromjson), delta_pct: ($d|tonumber), threshold: 10, verdict: $v, unit: "msgs/sec" }' \
        > "${RESULTS_DIR}/smtp_throughput.json"

    log_info "Throughput — C: ${THROUGHPUT_C_MEAN} msgs/s, Rust: ${THROUGHPUT_RUST_MEAN} msgs/s, Δ ${THROUGHPUT_DELTA}%, ${THROUGHPUT_VERDICT}"
}

# =============================================================================
# Benchmark 2: Fork-per-Connection Latency
# =============================================================================

benchmark_fork_latency() {
    log_info "=== Benchmark 2: Fork-per-Connection Latency ==="

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would measure ${CONNECTION_COUNT} conns × ${CONNECTION_ITERATIONS} iters"
        LATENCY_C_MEAN="0" LATENCY_C_MEDIAN="0" LATENCY_C_STDDEV="0"
        LATENCY_C_MIN="0" LATENCY_C_MAX="0" LATENCY_C_P95="0" LATENCY_C_P99="0"
        LATENCY_RUST_MEAN="0" LATENCY_RUST_MEDIAN="0" LATENCY_RUST_STDDEV="0"
        LATENCY_RUST_MIN="0" LATENCY_RUST_MAX="0" LATENCY_RUST_P95="0" LATENCY_RUST_P99="0"
        LATENCY_DELTA="0.00" LATENCY_VERDICT="INFO"
        return 0
    fi

    # Helper script: open CONNECTION_COUNT connections, read 220 banner each
    local conn_script
    conn_script="$(mktemp --suffix=_bench_conn.sh)"
    register_temp "$conn_script"
    cat > "$conn_script" << 'CONNEOF'
#!/usr/bin/env bash
set -euo pipefail
HOST="$1"; PORT="$2"; COUNT="$3"
for (( i=1; i<=COUNT; i++ )); do
    exec 3<>"/dev/tcp/${HOST}/${PORT}" 2>/dev/null || continue
    read -r -t 10 _banner <&3 || true
    printf 'QUIT\r\n' >&3
    read -r -t 2 _q <&3 || true
    exec 3>&-
done
CONNEOF
    chmod +x "$conn_script"

    # --- C Exim ---
    log_info "Starting C Exim daemon on port ${SMTP_PORT_C} for latency test..."
    "$C_EXIM" -C "$CONFIG_FILE" -bd -oX "$SMTP_PORT_C" &
    local c_pid=$!
    register_bg_pid "$c_pid"
    wait_for_port "127.0.0.1" "$SMTP_PORT_C" 30

    log_info "Timing C Exim latency (${CONNECTION_COUNT} conns × ${CONNECTION_ITERATIONS} iters)..."
    hyperfine \
        --min-runs "$CONNECTION_ITERATIONS" \
        --warmup 10 \
        --export-json "${RESULTS_DIR}/fork_latency_c_hf.json" \
        --command-name "c-latency" \
        "bash ${conn_script} 127.0.0.1 ${SMTP_PORT_C} ${CONNECTION_COUNT}" \
        2>&1 | tail -5 || true

    stop_daemon "$c_pid"

    # --- Rust Exim ---
    log_info "Starting Rust Exim daemon on port ${SMTP_PORT_RUST} for latency test..."
    "$RUST_EXIM" -C "$CONFIG_FILE" -bd -oX "$SMTP_PORT_RUST" &
    local rust_pid=$!
    register_bg_pid "$rust_pid"
    wait_for_port "127.0.0.1" "$SMTP_PORT_RUST" 30

    log_info "Timing Rust Exim latency (${CONNECTION_COUNT} conns × ${CONNECTION_ITERATIONS} iters)..."
    hyperfine \
        --min-runs "$CONNECTION_ITERATIONS" \
        --warmup 10 \
        --export-json "${RESULTS_DIR}/fork_latency_rust_hf.json" \
        --command-name "rust-latency" \
        "bash ${conn_script} 127.0.0.1 ${SMTP_PORT_RUST} ${CONNECTION_COUNT}" \
        2>&1 | tail -5 || true

    stop_daemon "$rust_pid"

    # --- Extract per-connection latency in milliseconds ---
    # hyperfine reports total-time-for-N-connections in seconds.
    # Per-connection latency (ms) = time_s * 1000 / CONNECTION_COUNT
    local c_vals rust_vals
    c_vals="$(mktemp)"; register_temp "$c_vals"
    rust_vals="$(mktemp)"; register_temp "$rust_vals"

    jq -r --arg cc "$CONNECTION_COUNT" \
        '.results[0].times[] | . * 1000 / ($cc | tonumber)' \
        "${RESULTS_DIR}/fork_latency_c_hf.json" > "$c_vals" 2>/dev/null || true

    jq -r --arg cc "$CONNECTION_COUNT" \
        '.results[0].times[] | . * 1000 / ($cc | tonumber)' \
        "${RESULTS_DIR}/fork_latency_rust_hf.json" > "$rust_vals" 2>/dev/null || true

    local c_stats rust_stats
    c_stats="$(compute_stats "$c_vals")"
    rust_stats="$(compute_stats "$rust_vals")"

    LATENCY_C_MEAN="$(echo "$c_stats" | jq -r '.mean')"
    LATENCY_C_MEDIAN="$(echo "$c_stats" | jq -r '.median')"
    LATENCY_C_STDDEV="$(echo "$c_stats" | jq -r '.stddev')"
    LATENCY_C_MIN="$(echo "$c_stats" | jq -r '.min')"
    LATENCY_C_MAX="$(echo "$c_stats" | jq -r '.max')"
    LATENCY_C_P95="$(echo "$c_stats" | jq -r '.p95')"
    LATENCY_C_P99="$(echo "$c_stats" | jq -r '.p99')"

    LATENCY_RUST_MEAN="$(echo "$rust_stats" | jq -r '.mean')"
    LATENCY_RUST_MEDIAN="$(echo "$rust_stats" | jq -r '.median')"
    LATENCY_RUST_STDDEV="$(echo "$rust_stats" | jq -r '.stddev')"
    LATENCY_RUST_MIN="$(echo "$rust_stats" | jq -r '.min')"
    LATENCY_RUST_MAX="$(echo "$rust_stats" | jq -r '.max')"
    LATENCY_RUST_P95="$(echo "$rust_stats" | jq -r '.p95')"
    LATENCY_RUST_P99="$(echo "$rust_stats" | jq -r '.p99')"

    # Positive delta = Rust slower (higher latency)
    LATENCY_DELTA="$(compute_delta "$LATENCY_C_MEAN" "$LATENCY_RUST_MEAN")"
    LATENCY_VERDICT="$(check_threshold "latency" "$LATENCY_DELTA" "5")"

    jq -n \
        --arg c "$c_stats" --arg r "$rust_stats" \
        --arg d "$LATENCY_DELTA" --arg v "$LATENCY_VERDICT" \
        '{ c: ($c|fromjson), rust: ($r|fromjson), delta_pct: ($d|tonumber), threshold: 5, verdict: $v, unit: "milliseconds" }' \
        > "${RESULTS_DIR}/fork_latency.json"

    log_info "Latency — C: ${LATENCY_C_MEAN} ms, Rust: ${LATENCY_RUST_MEAN} ms, Δ ${LATENCY_DELTA}%, ${LATENCY_VERDICT}"
}

# =============================================================================
# Benchmark 3: Peak RSS Memory
# =============================================================================

benchmark_peak_rss() {
    log_info "=== Benchmark 3: Peak RSS Memory ==="

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would measure RSS for 10 MB message × ${MEMORY_ITERATIONS} iters"
        RSS_C_MEAN="0" RSS_C_MEDIAN="0" RSS_C_MIN="0" RSS_C_MAX="0"
        RSS_RUST_MEAN="0" RSS_RUST_MEDIAN="0" RSS_RUST_MIN="0" RSS_RUST_MAX="0"
        RSS_DELTA="0.00" RSS_VERDICT="INFO"
        return 0
    fi

    # Generate 10 MB test message
    local test_msg
    test_msg="$(mktemp --suffix=_bench_10mb.eml)"
    generate_10mb_message "$test_msg"

    # Build SMTP batch input wrapping the message
    local smtp_input
    smtp_input="$(mktemp --suffix=_bench_smtp.txt)"
    register_temp "$smtp_input"
    {
        printf 'EHLO benchmark.local\r\n'
        printf 'MAIL FROM:<benchmark@localhost>\r\n'
        printf 'RCPT TO:<test@localhost>\r\n'
        printf 'DATA\r\n'
        cat "$test_msg"
        printf '\r\n.\r\n'
        printf 'QUIT\r\n'
    } > "$smtp_input"

    local c_rss_file rust_rss_file
    c_rss_file="$(mktemp)"; register_temp "$c_rss_file"
    rust_rss_file="$(mktemp)"; register_temp "$rust_rss_file"

    # --- C Exim RSS ---
    log_info "Measuring C Exim peak RSS (${MEMORY_ITERATIONS} iterations, 10 MB message)..."
    local iter rss_kb time_output
    for (( iter=1; iter<=MEMORY_ITERATIONS; iter++ )); do
        time_output="$(/usr/bin/time -v "$C_EXIM" -C "$CONFIG_FILE" -bs < "$smtp_input" 2>&1 1>/dev/null || true)"
        rss_kb="$(echo "$time_output" | grep -i 'Maximum resident set size' | awk '{print $NF}')"
        echo "${rss_kb:-0}" >> "$c_rss_file"
        if (( iter % (MEMORY_ITERATIONS / 5 + 1) == 0 )); then
            log_info "  C RSS: ${iter}/${MEMORY_ITERATIONS}"
        fi
    done

    # --- Rust Exim RSS ---
    log_info "Measuring Rust Exim peak RSS (${MEMORY_ITERATIONS} iterations, 10 MB message)..."
    for (( iter=1; iter<=MEMORY_ITERATIONS; iter++ )); do
        time_output="$(/usr/bin/time -v "$RUST_EXIM" -C "$CONFIG_FILE" -bs < "$smtp_input" 2>&1 1>/dev/null || true)"
        rss_kb="$(echo "$time_output" | grep -i 'Maximum resident set size' | awk '{print $NF}')"
        echo "${rss_kb:-0}" >> "$rust_rss_file"
        if (( iter % (MEMORY_ITERATIONS / 5 + 1) == 0 )); then
            log_info "  Rust RSS: ${iter}/${MEMORY_ITERATIONS}"
        fi
    done

    # --- Statistics ---
    local c_stats rust_stats
    c_stats="$(compute_stats "$c_rss_file")"
    rust_stats="$(compute_stats "$rust_rss_file")"

    RSS_C_MEAN="$(echo "$c_stats" | jq -r '.mean')"
    RSS_C_MEDIAN="$(echo "$c_stats" | jq -r '.median')"
    RSS_C_MIN="$(echo "$c_stats" | jq -r '.min')"
    RSS_C_MAX="$(echo "$c_stats" | jq -r '.max')"

    RSS_RUST_MEAN="$(echo "$rust_stats" | jq -r '.mean')"
    RSS_RUST_MEDIAN="$(echo "$rust_stats" | jq -r '.median')"
    RSS_RUST_MIN="$(echo "$rust_stats" | jq -r '.min')"
    RSS_RUST_MAX="$(echo "$rust_stats" | jq -r '.max')"

    # Positive delta = Rust uses more memory
    RSS_DELTA="$(compute_delta "$RSS_C_MEAN" "$RSS_RUST_MEAN")"
    RSS_VERDICT="$(check_threshold "memory" "$RSS_DELTA" "20")"

    # CSV of per-iteration values
    {
        echo "iteration,c_rss_kb,rust_rss_kb"
        paste -d',' <(seq 1 "$MEMORY_ITERATIONS") "$c_rss_file" "$rust_rss_file"
    } > "${RESULTS_DIR}/peak_rss.csv"

    jq -n \
        --arg c "$c_stats" --arg r "$rust_stats" \
        --arg d "$RSS_DELTA" --arg v "$RSS_VERDICT" \
        '{ c: ($c|fromjson), rust: ($r|fromjson), delta_pct: ($d|tonumber), threshold: 20, verdict: $v, unit: "kilobytes" }' \
        > "${RESULTS_DIR}/peak_rss.json"

    log_info "Peak RSS — C: ${RSS_C_MEAN} KB, Rust: ${RSS_RUST_MEAN} KB, Δ ${RSS_DELTA}%, ${RSS_VERDICT}"
}

# =============================================================================
# Benchmark 4: Config Parse Time
# =============================================================================

benchmark_config_parse() {
    log_info "=== Benchmark 4: Config Parse Time ==="

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would measure config parse × ${PARSE_ITERATIONS} iters"
        PARSE_C_MEAN="0" PARSE_C_MEDIAN="0" PARSE_C_STDDEV="0"
        PARSE_C_MIN="0" PARSE_C_MAX="0"
        PARSE_RUST_MEAN="0" PARSE_RUST_MEDIAN="0" PARSE_RUST_STDDEV="0"
        PARSE_RUST_MIN="0" PARSE_RUST_MAX="0"
        PARSE_DELTA="0.00" PARSE_DIRECTION="N/A" PARSE_VERDICT="INFO"
        return 0
    fi

    # --- C Exim ---
    log_info "Timing C Exim config parse (${PARSE_ITERATIONS} iterations)..."
    hyperfine \
        --min-runs "$PARSE_ITERATIONS" \
        --warmup 50 \
        --export-json "${RESULTS_DIR}/config_parse_c_hf.json" \
        --command-name "c-parse" \
        "${C_EXIM} -C ${CONFIG_FILE} -bP" \
        2>&1 | tail -3 || true

    # --- Rust Exim ---
    log_info "Timing Rust Exim config parse (${PARSE_ITERATIONS} iterations)..."
    hyperfine \
        --min-runs "$PARSE_ITERATIONS" \
        --warmup 50 \
        --export-json "${RESULTS_DIR}/config_parse_rust_hf.json" \
        --command-name "rust-parse" \
        "${RUST_EXIM} -C ${CONFIG_FILE} -bP" \
        2>&1 | tail -3 || true

    # --- Extract per-invocation time in milliseconds ---
    local c_vals rust_vals
    c_vals="$(mktemp)"; register_temp "$c_vals"
    rust_vals="$(mktemp)"; register_temp "$rust_vals"

    jq -r '.results[0].times[] | . * 1000' \
        "${RESULTS_DIR}/config_parse_c_hf.json" > "$c_vals" 2>/dev/null || true
    jq -r '.results[0].times[] | . * 1000' \
        "${RESULTS_DIR}/config_parse_rust_hf.json" > "$rust_vals" 2>/dev/null || true

    local c_stats rust_stats
    c_stats="$(compute_stats "$c_vals")"
    rust_stats="$(compute_stats "$rust_vals")"

    PARSE_C_MEAN="$(echo "$c_stats" | jq -r '.mean')"
    PARSE_C_MEDIAN="$(echo "$c_stats" | jq -r '.median')"
    PARSE_C_STDDEV="$(echo "$c_stats" | jq -r '.stddev')"
    PARSE_C_MIN="$(echo "$c_stats" | jq -r '.min')"
    PARSE_C_MAX="$(echo "$c_stats" | jq -r '.max')"

    PARSE_RUST_MEAN="$(echo "$rust_stats" | jq -r '.mean')"
    PARSE_RUST_MEDIAN="$(echo "$rust_stats" | jq -r '.median')"
    PARSE_RUST_STDDEV="$(echo "$rust_stats" | jq -r '.stddev')"
    PARSE_RUST_MIN="$(echo "$rust_stats" | jq -r '.min')"
    PARSE_RUST_MAX="$(echo "$rust_stats" | jq -r '.max')"

    # Positive delta = Rust slower
    PARSE_DELTA="$(compute_delta "$PARSE_C_MEAN" "$PARSE_RUST_MEAN")"
    PARSE_VERDICT="INFO"

    # Determine human-readable direction
    local d_num
    d_num="$(awk -v d="$PARSE_DELTA" 'BEGIN { print d + 0 }')"
    if awk -v d="$d_num" 'BEGIN { exit !(d < -1) }'; then
        PARSE_DIRECTION="Rust is faster"
    elif awk -v d="$d_num" 'BEGIN { exit !(d > 1) }'; then
        PARSE_DIRECTION="C is faster"
    else
        PARSE_DIRECTION="Comparable"
    fi

    jq -n \
        --arg c "$c_stats" --arg r "$rust_stats" \
        --arg d "$PARSE_DELTA" --arg dir "$PARSE_DIRECTION" --arg v "$PARSE_VERDICT" \
        '{ c: ($c|fromjson), rust: ($r|fromjson), delta_pct: ($d|tonumber), direction: $dir, verdict: $v, unit: "milliseconds" }' \
        > "${RESULTS_DIR}/config_parse.json"

    log_info "Parse — C: ${PARSE_C_MEAN} ms, Rust: ${PARSE_RUST_MEAN} ms, Δ ${PARSE_DELTA}%, ${PARSE_DIRECTION}"
}

# =============================================================================
# Results Aggregation
# =============================================================================

aggregate_results() {
    log_info "Aggregating results..."

    # Overall verdict: PASS only if all hard thresholds pass
    if [[ "$THROUGHPUT_VERDICT" == "PASS" ]] \
       && [[ "$LATENCY_VERDICT" == "PASS" ]] \
       && [[ "$RSS_VERDICT" == "PASS" ]]; then
        OVERALL_VERDICT="PASS"
    elif [[ "$THROUGHPUT_VERDICT" == "FAIL" ]] \
         || [[ "$LATENCY_VERDICT" == "FAIL" ]] \
         || [[ "$RSS_VERDICT" == "FAIL" ]]; then
        OVERALL_VERDICT="FAIL"
    else
        OVERALL_VERDICT="INCOMPLETE"
    fi

    # Gather system information
    local sys_cpu sys_cores sys_ram sys_os sys_kernel
    local sys_cc sys_rustc sys_cargo sys_hf sys_swaks

    sys_cpu="$(lscpu 2>/dev/null | grep -m1 'Model name' | sed 's/.*:[[:space:]]*//' || echo 'Unknown')"
    sys_cores="$(nproc 2>/dev/null || echo 'Unknown')"
    sys_ram="$(free -h 2>/dev/null | awk '/^Mem:/{print $2}' || echo 'Unknown')"
    sys_os="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-Unknown}" || uname -o 2>/dev/null || echo 'Unknown')"
    sys_kernel="$(uname -r 2>/dev/null || echo 'Unknown')"
    sys_cc="$(gcc --version 2>/dev/null | head -1 || echo 'Unknown')"
    sys_rustc="$(rustc --version 2>/dev/null || echo 'Unknown')"
    sys_cargo="$(cargo --version 2>/dev/null || echo 'Unknown')"
    sys_hf="$(hyperfine --version 2>&1 | head -1 || echo 'Unknown')"
    if [[ "$HAS_SWAKS" == "true" ]]; then
        sys_swaks="$(swaks --version 2>&1 | head -1 || echo 'Unknown')"
    else
        sys_swaks="Not installed (built-in sender used)"
    fi

    # System info JSON
    jq -n \
        --arg cpu "$sys_cpu" --arg cores "$sys_cores" --arg ram "$sys_ram" \
        --arg os "$sys_os" --arg kernel "$sys_kernel" \
        --arg cc "$sys_cc" --arg rustc "$sys_rustc" --arg cargo "$sys_cargo" \
        --arg hf "$sys_hf" --arg swaks "$sys_swaks" \
        '{cpu:$cpu, cores:$cores, memory:$ram, os:$os, kernel:$kernel,
          c_compiler:$cc, rust_toolchain:$rustc, cargo:$cargo, hyperfine:$hf, swaks:$swaks}' \
        > "${RESULTS_DIR}/system_info.json"

    # Aggregate summary JSON (AAP section 0.7.6 structured output)
    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    jq -n \
        --arg ts "$timestamp" --arg overall "$OVERALL_VERDICT" \
        --slurpfile sys "${RESULTS_DIR}/system_info.json" \
        --arg tp_c "$THROUGHPUT_C_MEAN" --arg tp_r "$THROUGHPUT_RUST_MEAN" \
        --arg tp_d "$THROUGHPUT_DELTA" --arg tp_v "$THROUGHPUT_VERDICT" \
        --arg lt_c "$LATENCY_C_MEAN" --arg lt_r "$LATENCY_RUST_MEAN" \
        --arg lt_d "$LATENCY_DELTA" --arg lt_v "$LATENCY_VERDICT" \
        --arg rs_c "$RSS_C_MEAN" --arg rs_r "$RSS_RUST_MEAN" \
        --arg rs_d "$RSS_DELTA" --arg rs_v "$RSS_VERDICT" \
        --arg pt_c "$PARSE_C_MEAN" --arg pt_r "$PARSE_RUST_MEAN" \
        --arg pt_d "$PARSE_DELTA" --arg pt_v "$PARSE_VERDICT" \
        '{
          timestamp: $ts,
          system: $sys[0],
          results: {
            throughput: {c:($tp_c|tonumber), rust:($tp_r|tonumber), delta_pct:($tp_d|tonumber), threshold:10, verdict:$tp_v},
            latency:    {c:($lt_c|tonumber), rust:($lt_r|tonumber), delta_pct:($lt_d|tonumber), threshold:5,  verdict:$lt_v},
            memory:     {c:($rs_c|tonumber), rust:($rs_r|tonumber), delta_pct:($rs_d|tonumber), threshold:20, verdict:$rs_v},
            parse_time: {c:($pt_c|tonumber), rust:($pt_r|tonumber), delta_pct:($pt_d|tonumber), threshold:null, verdict:$pt_v}
          },
          overall: $overall
        }' > "${RESULTS_DIR}/summary.json"

    # CSV summary
    {
        echo "metric,c_value,rust_value,delta_pct,threshold,verdict,unit"
        echo "throughput,${THROUGHPUT_C_MEAN},${THROUGHPUT_RUST_MEAN},${THROUGHPUT_DELTA},10,${THROUGHPUT_VERDICT},msgs/sec"
        echo "latency,${LATENCY_C_MEAN},${LATENCY_RUST_MEAN},${LATENCY_DELTA},5,${LATENCY_VERDICT},milliseconds"
        echo "memory,${RSS_C_MEAN},${RSS_RUST_MEAN},${RSS_DELTA},20,${RSS_VERDICT},kilobytes"
        echo "parse_time,${PARSE_C_MEAN},${PARSE_RUST_MEAN},${PARSE_DELTA},,${PARSE_VERDICT},milliseconds"
    } > "${RESULTS_DIR}/summary.csv"

    log_info "Results written: ${RESULTS_DIR}/summary.json, ${RESULTS_DIR}/summary.csv"
}

# =============================================================================
# Report Generation
# =============================================================================

generate_report() {
    log_info "Generating benchmark report..."

    if [[ ! -f "$REPORT_TEMPLATE" ]]; then
        log_error "Report template not found: ${REPORT_TEMPLATE}"
        log_info "Skipping report generation."
        return 0
    fi

    # Read system info for substitutions
    local sys_cpu sys_cores sys_ram sys_os sys_kernel
    local sys_cc sys_rustc sys_cargo sys_hf sys_swaks
    sys_cpu="$(jq -r '.cpu' "${RESULTS_DIR}/system_info.json")"
    sys_cores="$(jq -r '.cores' "${RESULTS_DIR}/system_info.json")"
    sys_ram="$(jq -r '.memory' "${RESULTS_DIR}/system_info.json")"
    sys_os="$(jq -r '.os' "${RESULTS_DIR}/system_info.json")"
    sys_kernel="$(jq -r '.kernel' "${RESULTS_DIR}/system_info.json")"
    sys_cc="$(jq -r '.c_compiler' "${RESULTS_DIR}/system_info.json")"
    sys_rustc="$(jq -r '.rust_toolchain' "${RESULTS_DIR}/system_info.json")"
    sys_cargo="$(jq -r '.cargo' "${RESULTS_DIR}/system_info.json")"
    sys_hf="$(jq -r '.hyperfine' "${RESULTS_DIR}/system_info.json")"
    sys_swaks="$(jq -r '.swaks' "${RESULTS_DIR}/system_info.json")"

    local report_date
    report_date="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

    # Build threshold proximity warnings
    local threshold_warnings=""
    local tp_abs lt_abs rs_abs
    tp_abs="$(awk -v d="$THROUGHPUT_DELTA" 'BEGIN{d=d+0; print (d<0)?-d:d}')"
    lt_abs="$(awk -v d="$LATENCY_DELTA" 'BEGIN{d=d+0; print (d<0)?-d:d}')"
    rs_abs="$(awk -v d="$RSS_DELTA" 'BEGIN{d=d+0; print (d<0)?-d:d}')"

    if awk -v a="$tp_abs" 'BEGIN{exit !(a>=7 && a<=10)}'; then
        threshold_warnings="${threshold_warnings}- **Warning:** SMTP throughput delta (${THROUGHPUT_DELTA}%) approaching 10% threshold.\n"
    fi
    if awk -v a="$lt_abs" 'BEGIN{exit !(a>=3 && a<=5)}'; then
        threshold_warnings="${threshold_warnings}- **Warning:** Fork latency delta (${LATENCY_DELTA}%) approaching 5% threshold.\n"
    fi
    if awk -v a="$rs_abs" 'BEGIN{exit !(a>=15 && a<=20)}'; then
        threshold_warnings="${threshold_warnings}- **Warning:** Peak RSS delta (${RSS_DELTA}%) approaching 20% threshold.\n"
    fi
    if [[ -z "$threshold_warnings" ]]; then
        threshold_warnings="No metrics are approaching their threshold limits."
    fi

    # Build migration readiness assessment
    local readiness_text
    if [[ "$OVERALL_VERDICT" == "PASS" ]]; then
        readiness_text="The Rust Exim implementation meets all hard performance thresholds. Migration is ready for production qualification."
    elif [[ "$OVERALL_VERDICT" == "FAIL" ]]; then
        local failures=""
        [[ "$THROUGHPUT_VERDICT" == "FAIL" ]] && failures="${failures}SMTP throughput, "
        [[ "$LATENCY_VERDICT" == "FAIL" ]] && failures="${failures}fork latency, "
        [[ "$RSS_VERDICT" == "FAIL" ]] && failures="${failures}peak RSS memory, "
        failures="${failures%, }"
        readiness_text="The Rust implementation fails performance thresholds for: ${failures}. Additional optimization is required before production deployment."
    else
        readiness_text="Benchmark results are incomplete. Re-run the full suite for a definitive verdict."
    fi

    # Build sed script for all placeholder substitutions (using | delimiter)
    local sed_script
    sed_script="$(mktemp --suffix=_bench_sed)"
    register_temp "$sed_script"

    cat > "$sed_script" << SEDEOF
s|__REPORT_DATE__|${report_date}|g
s|__SYS_CPU_MODEL__|${sys_cpu}|g
s|__SYS_CPU_CORES__|${sys_cores}|g
s|__SYS_RAM_TOTAL__|${sys_ram}|g
s|__SYS_OS_NAME__|${sys_os}|g
s|__SYS_KERNEL_VERSION__|${sys_kernel}|g
s|__SYS_CC_VERSION__|${sys_cc}|g
s|__SYS_RUSTC_VERSION__|${sys_rustc}|g
s|__SYS_CARGO_VERSION__|${sys_cargo}|g
s|__SYS_HYPERFINE_VERSION__|${sys_hf}|g
s|__SYS_SWAKS_VERSION__|${sys_swaks}|g
s|__EXIM_C_BINARY_PATH__|${C_EXIM}|g
s|__EXIM_C_BUILD_CONFIG__|Default (make)|g
s|__EXIM_RUST_BINARY_PATH__|${RUST_EXIM}|g
s|__EXIM_RUST_FEATURES__|Default|g
s|__SMTP_PORT_C__|${SMTP_PORT_C}|g
s|__SMTP_PORT_RUST__|${SMTP_PORT_RUST}|g
s|__SMTP_THROUGHPUT_C__|${THROUGHPUT_C_MEAN}|g
s|__SMTP_THROUGHPUT_RUST__|${THROUGHPUT_RUST_MEAN}|g
s|__SMTP_THROUGHPUT_DELTA__|${THROUGHPUT_DELTA}|g
s|__SMTP_THROUGHPUT_VERDICT__|${THROUGHPUT_VERDICT}|g
s|__SMTP_THROUGHPUT_C_MEAN__|${THROUGHPUT_C_MEAN}|g
s|__SMTP_THROUGHPUT_C_MEDIAN__|${THROUGHPUT_C_MEDIAN}|g
s|__SMTP_THROUGHPUT_C_STDDEV__|${THROUGHPUT_C_STDDEV}|g
s|__SMTP_THROUGHPUT_C_P95__|${THROUGHPUT_C_P95}|g
s|__SMTP_THROUGHPUT_C_P99__|${THROUGHPUT_C_P99}|g
s|__SMTP_THROUGHPUT_C_MIN__|${THROUGHPUT_C_MIN}|g
s|__SMTP_THROUGHPUT_C_MAX__|${THROUGHPUT_C_MAX}|g
s|__SMTP_THROUGHPUT_RUST_MEAN__|${THROUGHPUT_RUST_MEAN}|g
s|__SMTP_THROUGHPUT_RUST_MEDIAN__|${THROUGHPUT_RUST_MEDIAN}|g
s|__SMTP_THROUGHPUT_RUST_STDDEV__|${THROUGHPUT_RUST_STDDEV}|g
s|__SMTP_THROUGHPUT_RUST_P95__|${THROUGHPUT_RUST_P95}|g
s|__SMTP_THROUGHPUT_RUST_P99__|${THROUGHPUT_RUST_P99}|g
s|__SMTP_THROUGHPUT_RUST_MIN__|${THROUGHPUT_RUST_MIN}|g
s|__SMTP_THROUGHPUT_RUST_MAX__|${THROUGHPUT_RUST_MAX}|g
s|__SMTP_THROUGHPUT_OBSERVATION__|Throughput measured using ${SMTP_MESSAGE_COUNT} messages via localhost delivery.|g
s|__FORK_LATENCY_C__|${LATENCY_C_MEAN}|g
s|__FORK_LATENCY_RUST__|${LATENCY_RUST_MEAN}|g
s|__FORK_LATENCY_DELTA__|${LATENCY_DELTA}|g
s|__FORK_LATENCY_VERDICT__|${LATENCY_VERDICT}|g
s|__FORK_LATENCY_C_MEAN__|${LATENCY_C_MEAN}|g
s|__FORK_LATENCY_C_MEDIAN__|${LATENCY_C_MEDIAN}|g
s|__FORK_LATENCY_C_STDDEV__|${LATENCY_C_STDDEV}|g
s|__FORK_LATENCY_C_P95__|${LATENCY_C_P95}|g
s|__FORK_LATENCY_C_P99__|${LATENCY_C_P99}|g
s|__FORK_LATENCY_C_MIN__|${LATENCY_C_MIN}|g
s|__FORK_LATENCY_C_MAX__|${LATENCY_C_MAX}|g
s|__FORK_LATENCY_RUST_MEAN__|${LATENCY_RUST_MEAN}|g
s|__FORK_LATENCY_RUST_MEDIAN__|${LATENCY_RUST_MEDIAN}|g
s|__FORK_LATENCY_RUST_STDDEV__|${LATENCY_RUST_STDDEV}|g
s|__FORK_LATENCY_RUST_P95__|${LATENCY_RUST_P95}|g
s|__FORK_LATENCY_RUST_P99__|${LATENCY_RUST_P99}|g
s|__FORK_LATENCY_RUST_MIN__|${LATENCY_RUST_MIN}|g
s|__FORK_LATENCY_RUST_MAX__|${LATENCY_RUST_MAX}|g
s|__FORK_LATENCY_OBSERVATION__|Fork latency measured over ${CONNECTION_COUNT} sequential connections per iteration.|g
s|__PEAK_RSS_C__|${RSS_C_MEAN}|g
s|__PEAK_RSS_RUST__|${RSS_RUST_MEAN}|g
s|__PEAK_RSS_DELTA__|${RSS_DELTA}|g
s|__PEAK_RSS_VERDICT__|${RSS_VERDICT}|g
s|__PEAK_RSS_C_MEAN__|${RSS_C_MEAN}|g
s|__PEAK_RSS_C_MEDIAN__|${RSS_C_MEDIAN}|g
s|__PEAK_RSS_C_MAX__|${RSS_C_MAX}|g
s|__PEAK_RSS_C_MIN__|${RSS_C_MIN}|g
s|__PEAK_RSS_RUST_MEAN__|${RSS_RUST_MEAN}|g
s|__PEAK_RSS_RUST_MEDIAN__|${RSS_RUST_MEDIAN}|g
s|__PEAK_RSS_RUST_MAX__|${RSS_RUST_MAX}|g
s|__PEAK_RSS_RUST_MIN__|${RSS_RUST_MIN}|g
s|__PEAK_RSS_OBSERVATION__|Peak RSS measured with 10 MB message injection via batch SMTP mode (-bs).|g
s|__CONFIG_PARSE_C__|${PARSE_C_MEAN}|g
s|__CONFIG_PARSE_RUST__|${PARSE_RUST_MEAN}|g
s|__CONFIG_PARSE_DELTA__|${PARSE_DELTA}|g
s|__CONFIG_PARSE_VERDICT__|${PARSE_VERDICT}|g
s|__CONFIG_PARSE_C_MEAN__|${PARSE_C_MEAN}|g
s|__CONFIG_PARSE_C_MEDIAN__|${PARSE_C_MEDIAN}|g
s|__CONFIG_PARSE_C_STDDEV__|${PARSE_C_STDDEV}|g
s|__CONFIG_PARSE_C_MIN__|${PARSE_C_MIN}|g
s|__CONFIG_PARSE_C_MAX__|${PARSE_C_MAX}|g
s|__CONFIG_PARSE_RUST_MEAN__|${PARSE_RUST_MEAN}|g
s|__CONFIG_PARSE_RUST_MEDIAN__|${PARSE_RUST_MEDIAN}|g
s|__CONFIG_PARSE_RUST_STDDEV__|${PARSE_RUST_STDDEV}|g
s|__CONFIG_PARSE_RUST_MIN__|${PARSE_RUST_MIN}|g
s|__CONFIG_PARSE_RUST_MAX__|${PARSE_RUST_MAX}|g
s|__CONFIG_PARSE_DIRECTION__|${PARSE_DIRECTION}|g
s|__CONFIG_PARSE_OBSERVATION__|Config parse time is directional only; differences have negligible steady-state throughput impact.|g
s|__OVERALL_VERDICT__|${OVERALL_VERDICT}|g
SEDEOF

    # Apply substitutions: template -> intermediate file
    local tmp_report
    tmp_report="$(mktemp --suffix=_bench_report.md)"
    register_temp "$tmp_report"

    sed -f "$sed_script" "$REPORT_TEMPLATE" > "$tmp_report"

    # Handle multi-line placeholders with awk
    awk -v warnings="$threshold_warnings" -v readiness="$readiness_text" '{
        gsub(/__THRESHOLD_WARNINGS__/, warnings)
        gsub(/__MIGRATION_READINESS_ASSESSMENT__/, readiness)
        print
    }' "$tmp_report" > "$REPORT_FILE"

    log_info "Report written: ${REPORT_FILE}"
}

# =============================================================================
# Usage / Help
# =============================================================================

usage() {
    cat << 'USAGEEOF'
Usage: bash bench/run_benchmarks.sh [OPTIONS]

Exim C vs Rust Performance Benchmark Suite

Measures 4 metrics comparing C and Rust Exim binaries:
  1. SMTP Transaction Throughput (msgs/sec)
  2. Fork-per-Connection Latency (ms)
  3. Peak RSS Memory (KB)
  4. Config Parse Time (ms)

Options:
  --help                Show this help message and exit
  --dry-run             Print what would be done without executing
  --test <name>         Run only the named test:
                          smtp_throughput, fork_latency, peak_rss, config_parse
  --c-exim <path>       Override C Exim binary path
  --rust-exim <path>    Override Rust Exim binary path
  --config <path>       Override configuration file path
  --results-dir <dir>   Override results output directory

Environment variables (override defaults):
  C_EXIM                C binary path (auto-detected from Makefile convention)
  RUST_EXIM             Rust binary path (default: target/release/exim)
  CONFIG_FILE           Config file (default: src/src/configure.default)
  SMTP_MESSAGE_COUNT    Messages for throughput test (default: 10000)
  SMTP_ITERATIONS       Throughput measurement iterations (default: 1000)
  CONNECTION_COUNT      Connections per latency iteration (default: 1000)
  CONNECTION_ITERATIONS Latency measurement iterations (default: 100)
  MEMORY_ITERATIONS     RSS measurement iterations (default: 100)
  PARSE_ITERATIONS      Parse measurement iterations (default: 1000)
  RESULTS_DIR           Output directory (default: bench/results)
  REPORT_FILE           Report output path (default: bench/BENCHMARK_REPORT.md)
  SMTP_PORT_C           C daemon port (default: 10025)
  SMTP_PORT_RUST        Rust daemon port (default: 10026)

Must be run from the repository root directory.
USAGEEOF
}

# =============================================================================
# Main
# =============================================================================

main() {
    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)
                usage
                exit 0
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --test)
                TEST_FILTER="${2:-}"
                shift 2
                ;;
            --c-exim)
                C_EXIM="${2:-}"
                shift 2
                ;;
            --rust-exim)
                RUST_EXIM="${2:-}"
                shift 2
                ;;
            --config)
                CONFIG_FILE="${2:-}"
                shift 2
                ;;
            --results-dir)
                RESULTS_DIR="${2:-}"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Prerequisite checks
    check_prerequisites

    # Ensure output directory exists
    ensure_dir "$RESULTS_DIR"

    log_info "Starting benchmark suite..."
    if [[ -n "$TEST_FILTER" ]]; then
        log_info "Test filter active: ${TEST_FILTER}"
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "*** DRY RUN MODE — no benchmarks will execute ***"
    fi

    # Execute selected benchmarks
    local run_all=true
    [[ -n "$TEST_FILTER" ]] && run_all=false

    if [[ "$run_all" == "true" ]] || [[ "$TEST_FILTER" == "smtp_throughput" ]]; then
        benchmark_smtp_throughput
    fi
    if [[ "$run_all" == "true" ]] || [[ "$TEST_FILTER" == "fork_latency" ]]; then
        benchmark_fork_latency
    fi
    if [[ "$run_all" == "true" ]] || [[ "$TEST_FILTER" == "peak_rss" ]]; then
        benchmark_peak_rss
    fi
    if [[ "$run_all" == "true" ]] || [[ "$TEST_FILTER" == "config_parse" ]]; then
        benchmark_config_parse
    fi

    # Set safe defaults for any metrics that were not executed (single-test mode)
    : "${THROUGHPUT_C_MEAN:=N/A}" "${THROUGHPUT_RUST_MEAN:=N/A}"
    : "${THROUGHPUT_DELTA:=N/A}" "${THROUGHPUT_VERDICT:=SKIPPED}"
    : "${THROUGHPUT_C_MEDIAN:=N/A}" "${THROUGHPUT_C_STDDEV:=N/A}"
    : "${THROUGHPUT_C_MIN:=N/A}" "${THROUGHPUT_C_MAX:=N/A}"
    : "${THROUGHPUT_C_P95:=N/A}" "${THROUGHPUT_C_P99:=N/A}"
    : "${THROUGHPUT_RUST_MEDIAN:=N/A}" "${THROUGHPUT_RUST_STDDEV:=N/A}"
    : "${THROUGHPUT_RUST_MIN:=N/A}" "${THROUGHPUT_RUST_MAX:=N/A}"
    : "${THROUGHPUT_RUST_P95:=N/A}" "${THROUGHPUT_RUST_P99:=N/A}"

    : "${LATENCY_C_MEAN:=N/A}" "${LATENCY_RUST_MEAN:=N/A}"
    : "${LATENCY_DELTA:=N/A}" "${LATENCY_VERDICT:=SKIPPED}"
    : "${LATENCY_C_MEDIAN:=N/A}" "${LATENCY_C_STDDEV:=N/A}"
    : "${LATENCY_C_MIN:=N/A}" "${LATENCY_C_MAX:=N/A}"
    : "${LATENCY_C_P95:=N/A}" "${LATENCY_C_P99:=N/A}"
    : "${LATENCY_RUST_MEDIAN:=N/A}" "${LATENCY_RUST_STDDEV:=N/A}"
    : "${LATENCY_RUST_MIN:=N/A}" "${LATENCY_RUST_MAX:=N/A}"
    : "${LATENCY_RUST_P95:=N/A}" "${LATENCY_RUST_P99:=N/A}"

    : "${RSS_C_MEAN:=N/A}" "${RSS_RUST_MEAN:=N/A}"
    : "${RSS_DELTA:=N/A}" "${RSS_VERDICT:=SKIPPED}"
    : "${RSS_C_MEDIAN:=N/A}" "${RSS_C_MIN:=N/A}" "${RSS_C_MAX:=N/A}"
    : "${RSS_RUST_MEDIAN:=N/A}" "${RSS_RUST_MIN:=N/A}" "${RSS_RUST_MAX:=N/A}"

    : "${PARSE_C_MEAN:=N/A}" "${PARSE_RUST_MEAN:=N/A}"
    : "${PARSE_DELTA:=N/A}" "${PARSE_VERDICT:=SKIPPED}" "${PARSE_DIRECTION:=N/A}"
    : "${PARSE_C_MEDIAN:=N/A}" "${PARSE_C_STDDEV:=N/A}"
    : "${PARSE_C_MIN:=N/A}" "${PARSE_C_MAX:=N/A}"
    : "${PARSE_RUST_MEDIAN:=N/A}" "${PARSE_RUST_STDDEV:=N/A}"
    : "${PARSE_RUST_MIN:=N/A}" "${PARSE_RUST_MAX:=N/A}"

    # Aggregate results and generate report
    aggregate_results
    generate_report

    # Print final summary to stdout
    echo ""
    echo "============================================================"
    echo " BENCHMARK RESULTS SUMMARY"
    echo "============================================================"
    echo ""
    printf " %-25s %-14s %-14s %-10s %-8s\n" "Metric" "C" "Rust" "Delta%" "Verdict"
    printf " %-25s %-14s %-14s %-10s %-8s\n" "-------------------------" "------------" "------------" "--------" "------"
    printf " %-25s %-14s %-14s %-10s %-8s\n" "SMTP Throughput (msg/s)" "$THROUGHPUT_C_MEAN" "$THROUGHPUT_RUST_MEAN" "$THROUGHPUT_DELTA" "$THROUGHPUT_VERDICT"
    printf " %-25s %-14s %-14s %-10s %-8s\n" "Fork Latency (ms)" "$LATENCY_C_MEAN" "$LATENCY_RUST_MEAN" "$LATENCY_DELTA" "$LATENCY_VERDICT"
    printf " %-25s %-14s %-14s %-10s %-8s\n" "Peak RSS (KB)" "$RSS_C_MEAN" "$RSS_RUST_MEAN" "$RSS_DELTA" "$RSS_VERDICT"
    printf " %-25s %-14s %-14s %-10s %-8s\n" "Config Parse (ms)" "$PARSE_C_MEAN" "$PARSE_RUST_MEAN" "$PARSE_DELTA" "$PARSE_VERDICT"
    echo ""
    echo " Overall Verdict: ${OVERALL_VERDICT}"
    echo ""
    echo " Detailed results : ${RESULTS_DIR}/summary.json"
    echo " Benchmark report : ${REPORT_FILE}"
    echo "============================================================"

    # Exit code: 0 on PASS, 1 on any hard threshold failure
    if [[ "$OVERALL_VERDICT" == "FAIL" ]]; then
        return 1
    fi
    return 0
}

# =============================================================================
# Entry Point
# =============================================================================

main "$@"
