#!/usr/bin/env bash
# ==============================================================================
# LogAnalyzer Pro 2.0 — Linux Authentication Telemetry Collector
# Compatible with Kali Linux, Debian, Ubuntu, and Red Hat distributions.
# Safely extracts authentication logs from /var/log/auth.log or systemd journal.
# ==============================================================================

set -o pipefail

VERSION="2.0.0"
SINCE_WINDOW="24 hours ago"
MAX_EVENTS=500
OUTPUT_FORMAT="text" # text or json
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "linux-endpoint")
DEFAULT_OUTPUT="linux_auth_${HOSTNAME_VAL}.log"
OUTPUT_FILE=""
CHECKPOINT_FILE="linux_checkpoint.json"

show_banner() {
    echo "=========================================================="
    echo "   LogAnalyzer Pro 2.0 — Linux Security Telemetry Collector"
    echo "=========================================================="
}

show_help() {
    show_banner
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -s, --since <time>       Time window (e.g. '24 hours ago', '1 hour ago', 'today')"
    echo "                           Default: '24 hours ago'"
    echo "  -m, --max-events <num>   Maximum number of events to extract (Default: 500)"
    echo "  -o, --output <path>      Output file destination (Default: linux_auth_<hostname>.log)"
    echo "  -f, --format <format>    Output format: 'text' (syslog) or 'json' (NDJSON from journal)"
    echo "                           Default: 'text'"
    echo "  -c, --checkpoint <path>  Checkpoint file to store high-water mark timestamp"
    echo "                           Default: 'linux_checkpoint.json'"
    echo "  -h, --help               Display this help message and exit"
    echo ""
    echo "Examples:"
    echo "  sudo $0 -s '12 hours ago' -m 200 -o /tmp/kali_auth.log"
    echo "  sudo $0 --format json -o /tmp/kali_auth.json"
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--since)
            SINCE_WINDOW="$2"
            shift 2
            ;;
        -m|--max-events)
            MAX_EVENTS="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -f|--format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        -c|--checkpoint)
            CHECKPOINT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "[-] Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

show_banner

# Set default output file extension based on format if not explicitly supplied
if [[ -z "$OUTPUT_FILE" ]]; then
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        OUTPUT_FILE="linux_auth_${HOSTNAME_VAL}.json"
    else
        OUTPUT_FILE="linux_auth_${HOSTNAME_VAL}.log"
    fi
fi

# Ensure output directory exists if path contains directories
OUTPUT_DIR=$(dirname "$OUTPUT_FILE")
if [[ "$OUTPUT_DIR" != "." && ! -d "$OUTPUT_DIR" ]]; then
    mkdir -p "$OUTPUT_DIR" 2>/dev/null || true
fi

echo "[*] Hostname: $HOSTNAME_VAL"
echo "[*] Time window: since '$SINCE_WINDOW'"
echo "[*] Max events: $MAX_EVENTS"
echo "[*] Format: $OUTPUT_FORMAT"
echo "[*] Target output: $OUTPUT_FILE"

# Determine collection source
LOG_SOURCE=""
if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    if command -v journalctl >/dev/null 2>&1; then
        LOG_SOURCE="journalctl_json"
    else
        echo "[-] Error: 'journalctl' is required for JSON export on Linux."
        exit 1
    fi
else
    # Text syslog mode: Check /var/log/auth.log (Debian/Kali) or /var/log/secure (RHEL)
    if [[ -r "/var/log/auth.log" ]]; then
        LOG_SOURCE="auth_log"
    elif [[ -r "/var/log/secure" ]]; then
        LOG_SOURCE="secure_log"
    elif command -v journalctl >/dev/null 2>&1; then
        echo "[!] /var/log/auth.log is not directly readable. Falling back to 'journalctl'."
        LOG_SOURCE="journalctl_text"
    else
        echo "[-] Permission denied or log source not found."
        echo "    Tip: Run this script with 'sudo' or add your user to the 'adm' or 'systemd-journal' group:"
        echo "    sudo $0 -o $OUTPUT_FILE"
        exit 1
    fi
fi

echo "[*] Selected source: $LOG_SOURCE"

# Perform extraction
COLLECTED_COUNT=0
TMP_OUT=$(mktemp)

if [[ "$LOG_SOURCE" == "auth_log" || "$LOG_SOURCE" == "secure_log" ]]; then
    SOURCE_PATH="/var/log/auth.log"
    [[ "$LOG_SOURCE" == "secure_log" ]] && SOURCE_PATH="/var/log/secure"

    # Filter auth events: sshd, sudo, su, pam, authentication
    grep -E "sshd|sudo|pam_unix|su:|invalid user|Accepted|Failed" "$SOURCE_PATH" | tail -n "$MAX_EVENTS" > "$TMP_OUT"
    COLLECTED_COUNT=$(wc -l < "$TMP_OUT" | tr -d ' ')

elif [[ "$LOG_SOURCE" == "journalctl_text" ]]; then
    journalctl -u ssh -u sshd -u sudo --since "$SINCE_WINDOW" --no-pager -n "$MAX_EVENTS" 2>/dev/null > "$TMP_OUT"
    COLLECTED_COUNT=$(wc -l < "$TMP_OUT" | tr -d ' ')

elif [[ "$LOG_SOURCE" == "journalctl_json" ]]; then
    journalctl -u ssh -u sshd -u sudo --since "$SINCE_WINDOW" -o json --no-pager -n "$MAX_EVENTS" 2>/dev/null > "$TMP_OUT"
    COLLECTED_COUNT=$(wc -l < "$TMP_OUT" | tr -d ' ')
fi

if [[ "$COLLECTED_COUNT" -eq 0 ]]; then
    echo "[!] No security events found in the specified window."
    rm -f "$TMP_OUT"
    exit 0
fi

# Move extracted events to destination
cp "$TMP_OUT" "$OUTPUT_FILE"
rm -f "$TMP_OUT"

echo "[+] Successfully collected $COLLECTED_COUNT security events into: $OUTPUT_FILE"

# Save checkpoint
TIMESTAMP_NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
cat <<EOF > "$CHECKPOINT_FILE"
{
  "channel": "linux_auth",
  "computer_name": "$HOSTNAME_VAL",
  "last_collected_at": "$TIMESTAMP_NOW",
  "total_events_collected": $COLLECTED_COUNT,
  "source_type": "$LOG_SOURCE",
  "output_file": "$OUTPUT_FILE"
}
EOF

echo "[+] Saved checkpoint to: $CHECKPOINT_FILE"

echo ""
echo "=========================================================="
echo "                  NEXT STEPS (TRANSFER & INGEST)          "
echo "=========================================================="
echo "To ingest these events into LogAnalyzer Pro on Windows:"
echo ""
echo "1. Transfer the file to your Windows host:"
echo "   scp $OUTPUT_FILE user@<WINDOWS_IP>:\"c:/Users/aadit/OneDrive/Desktop/LOGANALYZER PRO/data/collected/\""
echo "   (or copy to a VirtualBox Shared Folder: /media/sf_shared/)"
echo ""
echo "2. On Windows, run the LogAnalyzer ingestion command:"
echo "   python scripts/ingest_collected.py --file data/collected/$OUTPUT_FILE"
echo "=========================================================="
exit 0
