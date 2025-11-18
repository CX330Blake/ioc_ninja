# IoC Ninja

![version](https://img.shields.io/badge/version-1.3.5-blue)
![license](https://img.shields.io/badge/license-MIT-green)

![](https://github-production-user-asset-6210df.s3.amazonaws.com/108129644/515628109-1aecaec7-1e09-44b6-ada1-0bf0d6474019.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20251118%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20251118T145744Z&X-Amz-Expires=300&X-Amz-Signature=79f206e03dd2c3a16cfa5a79c7fbbd582b3af09fe5a1f6ae8ffcb96f23760e0b&X-Amz-SignedHeaders=host)

IoC Ninja is a Binary Ninja plugin that scans a BinaryView's user-visible strings and extracts Indicators of Compromise (IoCs) — IP addresses, domains, URLs, email addresses, API keys, hashes, PEM blocks, Base64 blocks, file paths, registry keys and other useful artifacts. Findings are presented in an interactive Qt UI with selectable detectors, incremental results, live-domain filtering, and CSV export.

**Why this is useful**

- Quickly surface potential IoCs embedded in binaries without writing custom extraction scripts.
- A large, curated set of regular expressions and heuristics for many IoC classes (see `ioc_logic.py`).
- Optional DNS-based live-domain filtering to reduce false positives.
- Background scanning with incremental UI updates and exportable CSV output for triage.

## Features

- Pattern-based detection for IPv4/IPv6, domains, URLs, emails, UUIDs, MACs, MD5/SHA hashes, JWTs, API keys, PEM blocks, Base64 blocks, file paths, registry keys and more.
- Heuristic checks: high-entropy tokens, base64 decode validation and file-hash extraction.
- GUI: choose detectors, run scans in background, view incremental and aggregated results, export to CSV.
- Live DNS filtering: optionally show only resolvable domains.

## Requirements

- Binary Ninja (minimum version referenced in `plugin.json`: 3164)
- Python 3 (Binary Ninja's bundled Python is recommended)
- The plugin uses the Binary Ninja API and PySide6; these are typically supplied by the Binary Ninja application.

## Installation

You can install this manually or in Binary Ninja Plugin Manager. To install it manually, you can follow the instructions.

1. Clone the repository and put `ioc_ninja` inside your Binary Ninja `plugins` directory.

    - MacOS: `~/Library/Application Support/Binary Ninja/plugins/`
    - Linux: `~/.binaryninja/plugins/`
    - Windows: `%APPDATA%\Binary Ninja\plugins/`

2. Restart Binary Ninja to load the plugin.

## Usage

> You can modify the settings in Binary Ninja's settings page.

1. Open a binary in Binary Ninja.
2. Open the plugin UI: `Plugins -> IoC Ninja` (or use the command palette).
3. Select IoC types to scan (or use the All/None shortcuts) and click `Scan`.
4. Watch progress and partial results in the UI. Use the search box to filter by Type, Value, or Address.
5. Export results using the `Export` button (CSV) for further triage.

## Developer & Testing

- Core logic: `ioc_ninja/core/ioc_logic.py`
- UI: `ioc_ninja/ui/ioc_ui.py`
- Compatibility shim for legacy imports: `ioc_ninja/logic/ioc_logic.py`
- Tests: `tests/test_ioc_regex.py` (mocks Binary Ninja internals so tests can run outside the host application).

Run unit tests locally (Python 3 required):

```bash
python3 -m pytest tests/test_ioc_regex.py
# or (tests include a small runner):
python3 tests/test_ioc_regex.py
```

When adding or changing detectors, please add/update tests in `tests/test_ioc_regex.py` to cover edge cases.

## Getting Help

- Open an issue in this repository for bugs or feature requests. Include: Binary Ninja version, small repro if possible, and steps to reproduce.
- For quick questions, code pointers, or to propose changes, open a discussion or PR.

## Contributing & Maintainers

- This project is maintained in this repository. See `LICENSE` for license details (MIT).
- Contributions are welcome via pull requests — for larger changes, open an issue first to discuss the approach.

## License

This project is licensed under the MIT License — see `LICENSE` for details.
