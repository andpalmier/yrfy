# yrfy - YARAify CLI Client

A command-line tool for interacting with the [YARAify API](https://yaraify.abuse.ch/api/).

> **Part of the abuse.ch CLI toolkit** - This project is part of a collection of CLI tools for interacting with [abuse.ch](https://abuse.ch) services:
> - [urlhs](https://github.com/andpalmier/urlhs) - URLhaus (malware URL database)
> - [tfox](https://github.com/andpalmier/tfox) - ThreatFox (IOC database)
> - [yrfy](https://github.com/andpalmier/yrfy) - YARAify (YARA scanning)
> - [mbzr](https://github.com/andpalmier/mbzr) - MalwareBazaar (malware samples)

[![Go Report Card](https://goreportcard.com/badge/github.com/andpalmier/yrfy)](https://goreportcard.com/report/github.com/andpalmier/yrfy)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## Features

- ✅ Uses only Go standard libraries
- 📝 JSON output for easy parsing
- ⚡️ Built-in rate limiting (10 req/s)
- 🐳 Docker, Podman, and Apple container support
- 🔍 YARA and ClamAV scanning
- 📦 Optional malware unpacking

## Installation

### Using Homebrew

```bash
brew install andpalmier/tap/yrfy
```

### Using Go

```bash
go install github.com/andpalmier/yrfy@latest
```

### Using Container (Docker/Podman)

```bash
# Pull pre-built image
docker pull ghcr.io/andpalmier/yrfy:latest

# Or build locally
docker build -t yrfy .
```

### From Source

```bash
git clone https://github.com/andpalmier/yrfy.git
cd yrfy
make build
```

## Quick Start

1. **Get your API key** from [abuse.ch Authentication Portal](https://auth.abuse.ch/)

2. **Set your API key**:

```bash
export ABUSECH_API_KEY="your_api_key_here"
```

3. **Scan a file**:

```bash
yrfy scan -file malware.exe
```

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `scan` | Scan a file with YARA and ClamAV |
| `task` | Get results for a scan task |
| `query` | Query by hash, YARA rule, ClamAV, or fuzzy hash |
| `version` | Show version information |

### Scan Files

```bash
# Basic scan
yrfy scan -file malware.exe

# Scan with unpacking (PE files only)
yrfy scan -file packed.exe -unpack

# Private scan (don't share)
yrfy scan -file private.exe -no-share

# Skip if already known
yrfy scan -file sample.exe -skip-known
```

### Get Task Results

```bash
# Get scan results
yrfy task -id fb2763e9-7b84-11ec-9f01-42010aa4000b

# With Malpedia token for non-public YARA rules
yrfy task -id fb2763e9-7b84-11ec-9f01-42010aa4000b -malpedia-token YOUR_TOKEN
```

### Query Data

```bash
# By file hash
yrfy query -hash b0bb095dd0ad8b8de1c83b13c38e68dd

# By YARA rule
yrfy query -yara MALWARE_Win_Emotet -limit 50

# By ClamAV signature
yrfy query -clamav Win.Malware.Emotet

# By imphash
yrfy query -imphash 43fd39eb6df6bf3a9a3edd1f646cd16e

# By TLSH
yrfy query -tlsh T138F423C1EB53E7E1C8EF4D38920FFB6546...
```

### Container Usage

```bash
# Run with Docker (mount file for scanning)
docker run --rm -e ABUSECH_API_KEY="your_key" -v $(pwd):/data ghcr.io/andpalmier/yrfy scan -file /data/sample.exe

# Run with Podman
podman run --rm -e ABUSECH_API_KEY="your_key" -v $(pwd):/data ghcr.io/andpalmier/yrfy scan -file /data/sample.exe

# Run with Apple container
container run --rm -e ABUSECH_API_KEY="your_key" -v $(pwd):/data ghcr.io/andpalmier/yrfy scan -file /data/sample.exe

# Query without mounting
docker run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/yrfy query -yara MALWARE_Win_Emotet
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ABUSECH_API_KEY` | Your abuse.ch API key (required) |

## License

This project is licensed under the AGPLv3 License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [YARAify](https://yaraify.abuse.ch) by abuse.ch
- [abuse.ch](https://abuse.ch) for their work in fighting malware
