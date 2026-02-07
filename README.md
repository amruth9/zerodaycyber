# Zero-Day Ransomware Folder Defender (Windows)

This repository contains a Python script (`defender.py`) that monitors a target folder on Windows and reacts to ransomware-like behavior.

## What it does

- Watches a folder recursively for file activity (`watchdog`, with polling fallback).
- Detects suspicious patterns such as:
  - Known ransomware-style extension changes (e.g. `.locked`, `.encrypted`, `.crypt`).
  - High-entropy file content (often seen in encrypted output).
  - Burst file modifications in a short time window.
- Responds by:
  - Applying a write-deny ACL lockdown on the monitored folder via `icacls`.
  - Attempting to terminate non-whitelisted processes that have files open in that folder (via `psutil`).

> ⚠️ This is a heuristic detector and not a guaranteed ransomware prevention system. False positives and false negatives are possible.

## Requirements

- Python 3.9+
- Optional but recommended:
  - `watchdog`
  - `psutil`

Install dependencies:

```bash
pip install watchdog psutil
```

## Usage

```bash
python defender.py "C:\\Path\\To\\Monitor"
```

### Useful options

- `--burst-threshold <int>`: Number of events inside the window before triggering burst alert (default: `25`).
- `--burst-window <seconds>`: Sliding window in seconds for burst detection (default: `10`).
- `--entropy-threshold <float>`: Shannon entropy threshold for suspicious files (default: `7.2`).
- `--no-lockdown`: Skip ACL lockdown action.
- `--whitelist <proc1> <proc2> ...`: Process names never terminated (default: `explorer.exe`).

Example:

```bash
python defender.py "C:\\SensitiveData" --burst-threshold 40 --burst-window 8 --whitelist explorer.exe backup.exe
```

## Operational notes

- Run from an elevated shell for ACL/process actions to work reliably.
- Test in a non-production directory first.
- If `watchdog` is missing, script falls back to polling mode automatically.
- If `psutil` is missing, process termination is skipped.

## Repository hygiene

Python bytecode artifacts are ignored via:

- `__pycache__/`
- `*.pyc`
