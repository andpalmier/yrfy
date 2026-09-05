# yrfy - YARAify CLI client

A command-line client for the [YARAify API](https://yaraify.abuse.ch/api/). It scans files against public and private YARA and ClamAV signatures, looks up what YARAify already knows, and manages the rules you have deployed on YARAhub.

> Part of the abuse.ch CLI toolkit, a set of clients for [abuse.ch](https://abuse.ch) services:
> - [urlhs](https://github.com/andpalmier/urlhs) for URLhaus, the malware URL database
> - [tfox](https://github.com/andpalmier/tfox) for ThreatFox, the IOC database
> - [yrfy](https://github.com/andpalmier/yrfy) for YARAify, YARA scanning
> - [mbzr](https://github.com/andpalmier/mbzr) for MalwareBazaar, malware samples

[![CI](https://github.com/andpalmier/yrfy/actions/workflows/ci.yml/badge.svg)](https://github.com/andpalmier/yrfy/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## Features

- Scans against YARA and ClamAV signatures, public and private
- Optional malware unpacking for PE executables
- Built on the Go standard library, with no third party dependencies
- Prints JSON, so you can pipe it into jq or anything else
- Rate limits itself to 10 requests per second
- Runs under Docker, Podman, and Apple container

## Installation

### Homebrew

```bash
brew install --cask andpalmier/tap/yrfy
```

Homebrew casks are macOS only. On Linux, use `go install` or a pre-built binary.

### Go

```bash
go install github.com/andpalmier/yrfy@latest
```

### Container

```bash
# Pull the pre-built image
docker pull ghcr.io/andpalmier/yrfy:latest

# Or build it yourself
docker build -t yrfy .
```

### From source

```bash
git clone https://github.com/andpalmier/yrfy.git
cd yrfy
make build
```

## Quick start

Get an API key from the [abuse.ch Authentication Portal](https://auth.abuse.ch/), export it, then scan something:

```bash
export ABUSECH_API_KEY="your_api_key_here"
yrfy scan -file malware.exe
```

Every command reads the key from `ABUSECH_API_KEY`. When a query fails, yrfy prints the reason rather than a bare status code.

## Usage

### Global flags

These go before the command name.

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Print what the client is doing |
| `-t`, `--timeout` | Timeout per request, as a duration such as `45s` or `5m` (default `2m`) |
| `-V`, `--version` | Print version information |
| `-h`, `--help` | Print help |

The default timeout is deliberately generous. Scanning a file takes longer than a lookup, and unpacking longer still.

### Commands

| Command | Description |
|---------|-------------|
| `scan` | Scan a file against YARA and ClamAV signatures |
| `task` | Fetch the results of a scan by task id |
| `rescan` | Rescan a file YARAify already holds |
| `query` | Look up by hash, YARA rule, ClamAV signature or fuzzy hash |
| `download` | Fetch a file, or its unpacked form |
| `rules` | List, download or delete YARA rules on YARAhub |
| `version` | Print version information |

### Scanning files

```bash
# A plain scan
yrfy scan -file malware.exe

# Unpack first, which works on PE executables only
yrfy scan -file packed.exe -unpack

# Keep the file private
yrfy scan -file private.exe -no-share

# Skip files YARAify has already seen
yrfy scan -file sample.exe -skip-known
```

A scan returns a task id. Fetch its results with `task`:

```bash
yrfy task -id fb2763e9-7b84-11ec-9f01-42010aa4000b

# Matches against non-public rules need a Malpedia token
yrfy task -id fb2763e9-7b84-11ec-9f01-42010aa4000b -malpedia-token YOUR_TOKEN
```

To run a file YARAify already holds against the current rule set, ask for a rescan. It returns a new task id, queued:

```bash
yrfy rescan -hash 3cf9260ab6feb907cca7138f8959cbfa
```

### Looking things up

```bash
# By file hash, MD5, SHA1, SHA256 or SHA3-384
yrfy query -hash b0bb095dd0ad8b8de1c83b13c38e68dd

# By YARA rule name
yrfy query -yara MALWARE_Win_Emotet -limit 50

# By ClamAV signature
yrfy query -clamav Win.Malware.Emotet

# By structural or fuzzy hash
yrfy query -imphash 43fd39eb6df6bf3a9a3edd1f646cd16e
yrfy query -tlsh T138F423C1EB53E7E1C8EF4D38920FFB6546...
yrfy query -telfhash t1dd211d716b2195266ea0cd9088eca7b2512c97072349df33cf31849c24140aeea3ac4f
yrfy query -gimphash a081e2fab5999d99ed6be718af55e93df171d14bc83c7ca5fdc0907edba0d338c
yrfy query -dhash 92264e9e361ccdee
```

### Downloading files

```bash
yrfy download -sha256 <hash>

# The unpacked form, when YARAify managed to unpack it
yrfy download -sha256 <hash> -unpacked

# Choose where it lands
yrfy download -sha256 <hash> -out /tmp/sample.zip
```

Files are zipped with AES128 and the password `infected`. A tool that reports `compression type 99` cannot read AES archives, so reach for 7-Zip or Python's pyzipper. Files whose reporter chose not to share them cannot be downloaded at all.

### YARA rules

```bash
# Recently deployed public rules
yrfy rules -recent

# The rules deployed under your own account
yrfy rules -mine

# Print one rule by its YARAhub UUID
yrfy rules -get 1b95ce79-6034-4740-8e45-5f0840602d1a

# Every public rule, as an archive
yrfy rules -all -out /tmp/yaraify-rules.zip

# Remove one of your own rules. This cannot be undone
yrfy rules -delete bcbf6764-19ae-44f1-adb1-db0d23c100fb
```

A rule only appears in listings if its author set `yarahub_rule_matching_tlp` to `TLP:WHITE`, and can only be downloaded if `yarahub_rule_sharing_tlp` is `TLP:WHITE` too. abuse.ch rebuilds the full archive every five minutes, so fetching it more often than that gains you nothing.

Deploying a rule is not covered here. The API documentation describes it only by pointing at a sample script, without specifying the request, so yrfy does not guess at it. Upload rules through the YARAify web interface.

### Running in a container

```bash
# Scanning needs the file mounted
docker run --rm -e ABUSECH_API_KEY="your_key" -v $(pwd):/data ghcr.io/andpalmier/yrfy scan -file /data/sample.exe

podman run --rm -e ABUSECH_API_KEY="your_key" -v $(pwd):/data ghcr.io/andpalmier/yrfy scan -file /data/sample.exe

container run --rm -e ABUSECH_API_KEY="your_key" -v $(pwd):/data ghcr.io/andpalmier/yrfy scan -file /data/sample.exe

# A query needs nothing mounted
docker run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/yrfy query -yara MALWARE_Win_Emotet
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `ABUSECH_API_KEY` | Your abuse.ch API key. Required. |

## License

Licensed under the AGPLv3. See [LICENSE](LICENSE) for the full text.

## Acknowledgments

- [YARAify](https://yaraify.abuse.ch) by abuse.ch
- [abuse.ch](https://abuse.ch) for their work against malware
