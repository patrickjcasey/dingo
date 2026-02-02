#!/usr/bin/env bash
#
# Download test data files that are not available as git submodules.
# These files are sourced from the Wireshark Wiki SampleCaptures page.
#
# Usage: ./scripts/download-testdata.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SAMPLES_DIR="$PROJECT_ROOT/testdata/samples"

# Wireshark wiki sample captures base URL
WIRESHARK_BASE_URL="https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures"

# Files to download from Wireshark wiki
declare -A WIKI_SAMPLES=(
    ["dns.cap"]="dns.cap"
    # contain various DNS exploits
    ["zlip-1.pcap"]="zlip-1.pcap"
    ["zlip-2.pcap"]="zlip-2.pcap"
    ["zlip-3.pcap"]="zlip-3.pcap"
)

if ! command -v curl &> /dev/null; then
    echo "[X] 'curl' is required but not installed"
    exit 1
fi

if [ ! -d "$SAMPLES_DIR" ]; then
    mkdir -p "$SAMPLES_DIR"
    echo "[*] Created $SAMPLES_DIR"
fi

for local_name in "${!WIKI_SAMPLES[@]}"; do
    remote_name="${WIKI_SAMPLES[$local_name]}"
    target_path="$SAMPLES_DIR/$local_name"
    if [[ -f "$target_path" ]]; then
        echo "    [!] $local_name (already exists, skipping)"
    else
        if curl -sSfL "$WIRESHARK_BASE_URL/$remote_name" -o "$target_path"; then
            echo "    [*] Downloaded: $local_name"
        else
            echo "    [X] Failed to download $local_name"
            echo "           URL: $WIRESHARK_BASE_URL/$remote_name"
            echo "           You may need to download this file manually."
        fi
    fi
done
echo "[*] Download complete, files located in: $SAMPLES_DIR"