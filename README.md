# yrfy

CLI for the [YARAify API](https://yaraify.abuse.ch/api/). Scan files, look up known samples, and manage YARA rules on YARAhub.

[![CI](https://github.com/andpalmier/yrfy/actions/workflows/ci.yml/badge.svg)](https://github.com/andpalmier/yrfy/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## Install

```bash
brew install --cask andpalmier/tap/yrfy
go install github.com/andpalmier/yrfy@latest
docker pull ghcr.io/andpalmier/yrfy:latest
```

Homebrew works on macOS only. On Linux, use Go or a release binary.

## Quick start

```bash
export ABUSECH_API_KEY="your_api_key_here"
yrfy scan -file malware.exe
```

Most commands need `ABUSECH_API_KEY`. `yrfy rules -all` downloads the public archive without one.

## Commands

- `scan`: scan a file against YARA and ClamAV signatures.
- `task`: fetch scan results by task id.
- `rescan`: rescan a file YARAify already holds.
- `query`: look up by hash, YARA rule, ClamAV signature, or fuzzy hash.
- `download`: fetch a file or its unpacked form.
- `rules`: list, download, or delete YARA rules on YARAhub.
- `version`: print version information.

## Examples

```bash
yrfy scan -file packed.exe -unpack
yrfy scan -file private.exe -no-share
yrfy task -id fb2763e9-7b84-11ec-9f01-42010aa4000b
yrfy query -yara MALWARE_Win_Zegost -limit 50
yrfy download -sha256 <hash> -unpacked -out /tmp/sample.zip
yrfy rules -recent
yrfy rules -mine
yrfy rules -all -out /tmp/yaraify-rules.zip
```

## Notes

- Downloads are AES128 ZIP files with the password `infected`. Use 7-Zip or `pyzipper`.
- Files whose reporter chose not to share them cannot be downloaded.
- The full public rule archive rebuilds every five minutes.
- Deploy rules through the YARAify web interface.
- The default timeout is two minutes. Raise `-t` for slow scans or unpacking.

## Container

```bash
docker run --rm -e ABUSECH_API_KEY="your_key" -v "$PWD":/data ghcr.io/andpalmier/yrfy scan -file /data/sample.exe
docker run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/yrfy query -yara MALWARE_Win_Zegost
```

## License

AGPLv3. See [LICENSE](LICENSE).
