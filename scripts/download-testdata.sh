#!/usr/bin/env bash
#
# Download test data files that are not available as git submodules.
# These files are sourced from the Wireshark Wiki SampleCaptures page.
#
# Usage: ./scripts/download-testdata.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SAMPLES_DIR="$PROJECT_ROOT/testdata/samples"

# Wireshark wiki sample captures base URL
WIKI_BASE="https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures"

# Files to download from Wireshark wiki
declare -A WIKI_SAMPLES=(
    ["dns.cap"]="dns.cap"
    ["dns-remoteshell.pcap"]="dns-remoteshell.pcap"
    ["zlip-1.pcap"]="zlip-1.pcap"
    ["zlip-2.pcap"]="zlip-2.pcap"
    ["zlip-3.pcap"]="zlip-3.pcap"
)

echo "==> Creating samples directory..."
mkdir -p "$SAMPLES_DIR"

echo "==> Downloading Wireshark wiki samples..."
for local_name in "${!WIKI_SAMPLES[@]}"; do
    remote_name="${WIKI_SAMPLES[$local_name]}"
    target_path="$SAMPLES_DIR/$local_name"

    if [[ -f "$target_path" ]]; then
        echo "    [skip] $local_name (already exists)"
    else
        echo "    [download] $local_name..."
        if curl -sSfL "$WIKI_BASE/$remote_name" -o "$target_path"; then
            echo "    [ok] $local_name"
        else
            echo "    [error] Failed to download $local_name"
            echo "           URL: $WIKI_BASE/$remote_name"
            echo "           You may need to download this file manually."
        fi
    fi
done

echo ""
echo "==> Download complete!"
echo ""
echo "Downloaded files are in: $SAMPLES_DIR"
echo ""
echo "File descriptions:"
echo "  dns.cap              - Various DNS lookups"
echo "  dns-remoteshell.pcap - DNS anomaly (remoteshell on DNS port)"
echo "  zlip-1.pcap          - Endless self-referential pointer loop"
echo "  zlip-2.pcap          - Endless cross-referencing decompression"
echo "  zlip-3.pcap          - Long domain via multiple decompression"
