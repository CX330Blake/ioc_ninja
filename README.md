# IoC Ninja

![version](https://img.shields.io/badge/version-1.3.5-blue)
![license](https://img.shields.io/badge/license-MIT-green)

<img width="1536" height="1024" alt="ChatGPT Banner Design Nov 17 2025 (1)" src="https://github.com/user-attachments/assets/1aecaec7-1e09-44b6-ada1-0bf0d6474019" />

IoC Ninja is a Binary Ninja plugin that scans a BinaryView's user-visible strings and extracts Indicators of Compromise (IoCs) such as IP addresses, domains, URLs, email addresses, hashes, API keys, PEM blocks and other commonly useful artifacts. Results are shown in an interactive UI with selectable detectors, live-domain filtering, and export options.

**Why this is useful**

- Quickly surface potential IoCs embedded in binaries without writing custom scripts.
- Large set of vetted regular expressions and heuristics (IPv4/IPv6, domains, URLs, emails, MD5/SHA hashes, API keys, JWTs, PEM blocks, Base64, file paths, registry keys, etc.).
- Optional DNS-based live-domain filtering to reduce false positives.
- Export scan results for further triage (CSV) and easy navigation back to addresses in the BinaryView.

**Quick links**

- Plugin metadata: `plugin.json`
- License: `LICENSE`

## Features

- Pattern-based detection for many IoC types (see `ioc_logic.py` for full list).
- Heuristic checks for high-entropy tokens and base64-decoded validation.
- GUI: choose which IoC types to scan, run scans in a background thread, and view incremental results.
- Live DNS filtering option to keep only resolvable domains.
- Export results and copy values for manual analysis.

## Requirements

- Binary Ninja (minimum version specified in `plugin.json`: 3164)
- Python 3 (the Python bundled with Binary Ninja is recommended)
- The plugin uses the Binary Ninja API and PySide6 for UI; these are normally provided by the Binary Ninja application.

## Installation

There are two simple options to install the plugin for Binary Ninja:

1. Manual (recommended during development)

    - Clone or copy this repository into your Binary Ninja `plugins` directory. Example paths:

    - macOS: `~/Library/Application Support/Binary Ninja/plugins/`
    - Linux: `~/.binaryninja/plugins/`
    - Windows: `%APPDATA%\Binary Ninja\plugins\`

    Example (macOS / zsh):

    ```bash
    git clone <this-repo-url> ioc_ninja
    ln -s "$PWD/ioc_ninja" "$HOME/Library/Application Support/Binary Ninja/plugins/ioc_ninja"
    ```

2. Drop-in

    - Zip the repo contents (or copy the folder) and place them inside the `plugins` directory for Binary Ninja.

After installing, restart Binary Ninja.

## Usage

- Open a binary in Binary Ninja.
- From Binary Ninja's menu open: `Plugins -> IoC Ninja` (or run the plugin via the command palette). This opens the IoC Ninja tab.
- Select the IoC types to scan (or use the ✅All / ❌None shortcuts).
- Click `Scan` to start scanning strings; progress and partial results appear incrementally.
- Use the `Search` box to filter results by Type, Value or Address.
- Use the `Export` button to save results as CSV for sharing or further processing.
- Enable the "Resolvable domains only (DNS)" setting from Binary Ninja's Settings -> IoC Ninja to filter domains by DNS resolution.

## Developer & Testing

- The core detection logic lives in `ioc_logic.py`. The UI is implemented in `ioc_ui.py` and exported widget helpers are in `ui/widget.py`.
- Lightweight unit tests for regex coverage exist at `tests/test_ioc_regex.py`. The tests mock `binaryninja` internals so they can be run outside the Binary Ninja process.

Run tests locally (requires Python 3):

```bash
python3 -m pytest tests/test_ioc_regex.py
# or
python3 tests/test_ioc_regex.py
```

Notes for contributors:

- If you add or change a detection regex, update or add tests in `tests/test_ioc_regex.py` to cover edge cases.

## Getting Help

- Open an issue on this repository for bug reports or feature requests.
- Include a short description, steps to reproduce, a sample file (if possible), and which Binary Ninja version you are using.

## Contributing & Maintainers

- This project is maintained in this repository. See `LICENSE` for licensing (MIT).
- Contributions are welcome via pull requests. For larger changes, open an issue first to discuss the approach.

If you want to extend the plugin:

- Add detectors in `ioc_logic.py` (patterns are grouped in `IOC_PATTERNS`).
- Add UI options in `ioc_ui.py` and wire them into the scanning worker (`IoCScanWorker`).

## Files of Interest

- `ioc_logic.py` — core IoC extraction logic and regex patterns
- `ioc_ui.py` — Qt-based user interface and scanning worker
- `ui/widget.py` — small adapter exposing `IoCNinjaWidget` for Binary Ninja UI
- `plugin.json` — plugin metadata (version, supported platforms, etc.)
- `tests/test_ioc_regex.py` — regex/unit tests

## License

This project is licensed under the MIT License — see `LICENSE` for details.
