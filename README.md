# IoC Ninja
Author: **CX330**

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/461e21af-7760-464e-94e3-3caa642598a3" />

IoC Ninja is a Binary Ninja plugin that scans a BinaryView's user-visible strings and extracts Indicators of Compromise (IoCs) — IP addresses, domains, URLs, email addresses, API keys, hashes, PEM blocks, Base64 blocks, file paths, registry keys and other useful artifacts. Findings are presented in an interactive Qt UI with selectable detectors, incremental results, live-domain filtering, and CSV export.

**Why this is useful**

- Quickly surface potential IoCs embedded in binaries without writing custom extraction scripts.
- A large, curated set of regular expressions and heuristics for many IoC classes (see `ioc_logic.py`).
- Optional DNS-based live-domain filtering to reduce false positives.
- Background scanning with incremental UI updates and exportable CSV output for triage.

## Demo


https://github.com/user-attachments/assets/91370a2d-aece-44b5-b6e7-0e48109088b5


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

### Minimum Version

This plugin requires the following minimum version of Binary Ninja:

* 3164

### Install via Plugin Manager

Open Binary Ninja Plugin Manager and search for "IoC Ninja" to install it.

### Install Manually

1. Clone the repository and put `ioc_ninja` inside your Binary Ninja `plugins` directory.

    - MacOS: `~/Library/Application Support/Binary Ninja/plugins/`
    - Linux: `~/.binaryninja/plugins/`
    - Windows: `%APPDATA%\\Binary Ninja\\plugins/`

2. Restart Binary Ninja to load the plugin.

## Usage

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

This plugin is released under a MIT license.
