#!/usr/bin/env bash
#
# Extract raw DNS payloads from PCAP files for use as fuzzing corpus seeds.
#
# This script uses tshark (Wireshark CLI) to extract DNS payloads.
# Each payload is written to a separate file in the output directory.
#
# Usage: ./scripts/extract-dns-payloads.sh <output_dir> <pcap_file>...
#
# Example:
#   ./scripts/extract-dns-payloads.sh fuzz/corpus/parse_message testdata/samples/*.pcap
#
set -euo pipefail

# TODO: usage function

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <output_dir> <pcap_file>..."
    echo ""
    echo "Extract raw DNS payloads from PCAP files for fuzzing corpus."
    echo ""
    echo "Arguments:"
    echo "  output_dir  Directory to write extracted payloads"
    echo "  pcap_file   One or more PCAP files to process"
    echo ""
    echo "Requires: tshark (Wireshark CLI)"
    exit 1
fi

OUTPUT_DIR="$1"
shift

if ! command -v tshark &> /dev/null; then
    echo "[X] 'tshark' is required but not installed"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

TOTAL_EXTRACTED=0

for pcap_file in "$@"; do
    if [[ ! -f "$pcap_file" ]]; then
        echo "[warn] File not found: $pcap_file"
        continue
    fi

    basename=$(basename "$pcap_file" | sed 's/\.[^.]*$//')
    echo "[process] $pcap_file"

    # Extract DNS payloads using tshark
    # -T fields: output as fields
    # -e dns.data: raw DNS payload (hex)
    # We filter for DNS packets and extract the raw bytes
    count=0
    while IFS= read -r hex_payload; do
        if [[ -n "$hex_payload" ]]; then
            output_file="$OUTPUT_DIR/${basename}_$(printf '%04d' $count).dns"
            echo "$hex_payload" | xxd -r -p > "$output_file"
            ((count++))
        fi
    done < <(tshark -r "$pcap_file" -Y "dns" -T fields -e dns.data 2>/dev/null || true)

    # If dns.data didn't work, try extracting UDP payload for port 53
    if [[ $count -eq 0 ]]; then
        while IFS= read -r hex_payload; do
            if [[ -n "$hex_payload" ]]; then
                output_file="$OUTPUT_DIR/${basename}_$(printf '%04d' $count).dns"
                echo "$hex_payload" | xxd -r -p > "$output_file"
                ((count++))
            fi
        done < <(tshark -r "$pcap_file" -Y "udp.port == 53" -T fields -e data 2>/dev/null || true)
    fi

    echo "         Extracted $count DNS payloads"
    TOTAL_EXTRACTED=$((TOTAL_EXTRACTED + count))
done

echo ""
echo "[*] Total extracted: $TOTAL_EXTRACTED payloads"
echo "[*] Output directory: $OUTPUT_DIR"
