# Test Data Sources

This directory contains external test data used for testing the Dingo DNS parser.

## Git Submodules

### dns-fuzzing (CZ-NIC)
- **Source:** https://github.com/CZ-NIC/dns-fuzzing
- **Contents:** AFL seed packets for DNS fuzzing, originally developed for Knot DNS
- **Directory:** `dns-fuzzing/packet/` contains raw DNS packets (`.pkt` files)

### wireshark
- **Source:** https://gitlab.com/wireshark/wireshark
- **Contents:** Test capture files from Wireshark's test suite
- **Note:** Uses sparse checkout to only include `test/captures/`

## Manual Downloads

Some test files are not available in git repositories and must be downloaded manually.
Run the download script to fetch these files:

```bash
./scripts/download-testdata.sh
```

### Wireshark Wiki Samples

These files are downloaded from the [Wireshark Wiki SampleCaptures](https://wiki.wireshark.org/SampleCaptures) page:

| File                   | Description                                         |
| ---------------------- | --------------------------------------------------- |
| `dns.cap`              | Various DNS lookups                                 |
| `dns-remoteshell.pcap` | DNS anomaly caused by remoteshell on DNS port       |
| `zlip-1.pcap`          | Endless self-referential pointer decompression flaw |
| `zlip-2.pcap`          | Endless cross-referencing decompression             |
| `zlip-3.pcap`          | Very long domain through multiple decompression     |

## Updating Submodules

### Initial Setup

```bash
git submodule update --init --recursive
```

### Update CZ-NIC Fuzzing Corpus

```bash
git -C testdata/dns-fuzzing fetch origin
git -C testdata/dns-fuzzing checkout origin/master
git add testdata/dns-fuzzing
git commit -m "chore: update CZ-NIC fuzzing corpus"
```

### Update Wireshark Test Captures

```bash
git -C testdata/wireshark fetch origin
git -C testdata/wireshark checkout origin/master
git add testdata/wireshark
git commit -m "chore: update Wireshark test captures"
```

## Directory Structure

```
testdata/
├── README.md                    # This file
├── dns-fuzzing/                 # Git submodule: CZ-NIC fuzzing seeds
│   └── packet/                  # Raw DNS packets (.pkt files)
├── wireshark/                   # Git submodule: Wireshark (sparse checkout)
│   └── test/
│       └── captures/            # PCAP test files
└── samples/                     # Manual downloads (created by script)
    ├── dns.cap
    ├── dns-remoteshell.pcap
    ├── zlip-1.pcap
    ├── zlip-2.pcap
    └── zlip-3.pcap
```
