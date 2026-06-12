# CrackMeUp

## Overview
CrackMeUp is a Python wrapper around Hashcat for password audit workflows. It automates multi-pass cracking with curated wordlist/rule combinations, tracks progress in optional session files, and generates summary outputs for analysis.

At the end of a run, CrackMeUp combines discovered cracks, runs a final `hashcat --show`, and exports a CSV report with:
- Username
- Hash
- Plaintext password
- Password length
- Password complexity category

## Requirements
1. Hashcat installed and available in `PATH`
2. Python 3
3. Python dependencies from `requirements.txt`
4. Hash file prepared for the target Hashcat mode (for NTLM audits this is commonly `-m 1000`)

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 crackmeup.py -m MODE -d HASH_DIR -p POT_BASE -f HASH_FILE [options] -s crackmeup_session.json
```

### Required arguments
- `-m`, `--mode`: Hashcat mode (example: `1000` for NTLM)
- `-d`, `--hash_dir`: Directory containing hash input and where outputs are written
- `-p`, `--pot`: Base name for pot files
- `-f`, `--hash_file`: Hash file to crack (inside `hash_dir`)

### Optional arguments
- `-a`, `--all`: Force all wordlist/rule combinations and use timestamped pot files
- `-s`, `--session`: Session JSON file path to resume/start progress tracking
- `-e`, `--effort`: Effort level (`low`, `medium`, `high`), default `medium`
- `-w`, `--workload`: Hashcat workload profile (`auto`, `1`, `2`, `3`, `4`), default `auto`
- `--auto_mask`: Automatically launch mask attacks for frequently seen mask patterns
- `--mask_threshold`: Minimum mask frequency to trigger auto mask attack (default: `20`)
- `--rules_path`: Override rules directory
- `--wordlist_path`: Override wordlists directory

## Effort levels
Effort level controls how many wordlists/rules are used:
- `low`: smallest set (fastest)
- `medium`: balanced/default
- `high`: largest set (most comprehensive)

## Session and resume behavior
When `--session` is provided, CrackMeUp stores completed combinations and completed masks in JSON so interrupted runs can continue without redoing completed work.

If the run is interrupted (`Ctrl+C`), current progress is saved before exiting.

## Auto workload tuning
With `--workload auto`, CrackMeUp chooses workload profiles based on hash mode:
- Fast hashes: higher workload profile
- Slow hashes (for example bcrypt, PBKDF2, WPA families): lower workload profile

## Example commands

Basic run:

```bash
python3 crackmeup.py \
  -m 1000 \
  -d /opt/tools/hashcat-files/hashes/2023PWAudit \
  -f 20231028-ad-int-hashes.txt \
  -p ad_name-ntlm
```

Resumable run with high effort and auto masks:

```bash
python3 crackmeup.py \
  -m 1000 \
  -d /opt/tools/hashcat-files/hashes/2023PWAudit \
  -f 20231028-ad-int-hashes.txt \
  -p ad_name-ntlm \
  -s crackmeup-session.json \
  -e high \
  --auto_mask \
  --mask_threshold 20
```

## Output files
CrackMeUp writes outputs to `hash_dir`, including:
- Hashcat run logs (`hashcat-*.log`)
- Pot files per run (`*.pot`)
- Session tracking file (`*.json`, when `--session` is used)
- Line-delimited run summaries (`hashcat_session_log_*.json`)
- Combined deduplicated pot-style output (`hashcat_combined_*.txt`)
- Final Hashcat show output (`temp-*.txt`)
- Final CSV analysis report (`hashcat-*.csv`)

## Notes
- For long cracking jobs over SSH, use `screen` or `tmux`.
- Ensure your wordlist/rule paths match your environment, or override with `--wordlist_path` and `--rules_path`.

## Wordlists and rule sets
- https://weakpass.com/
- https://github.com/n0kovo/hashcat-rules-collection
- https://github.com/praetorian-inc/Hob0Rules
