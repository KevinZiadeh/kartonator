#!/usr/bin/env bash
# Usage: ./setup_karton_attributes.sh [http://localhost:8080]
# Reads credentials from karton.docker.ini or karton.ini, logs in, and creates attributes.

set -euo pipefail

URL="${1:-http://localhost:8080}"
URL="${URL%/}"  # Strip trailing slash

echo "Target URL: $URL"

# Write the Python script to a temp file so uv can run it with args
TMPSCRIPT=$(mktemp ./mwdb_setup_XXXXXX.py)
trap 'rm -f "$TMPSCRIPT"' EXIT

cat > "$TMPSCRIPT" << 'PYTHON_EOF'
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests"]
# ///

import sys
import configparser
import requests
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

base_url = sys.argv[1].rstrip("/")

config = configparser.ConfigParser()
found = False
for candidate in ["karton.docker.ini", "karton.ini"]:
    if Path(candidate).exists():
        config.read(candidate)
        print(f"[+] Loaded config from: {candidate}")
        found = True
        break

if not found:
    print("[!] Neither karton.docker.ini nor karton.ini was found in the current directory.")
    sys.exit(1)

try:
    username = config["mwdb"]["username"]
    password = config["mwdb"]["password"]
except KeyError as e:
    print(f"[!] Missing key in [mwdb] section: {e}")
    sys.exit(1)

# ── Login ─────────────────────────────────────────────────────────────────────

print(f"[*] Logging in as '{username}' ...")
resp = requests.post(
    f"{base_url}/api/auth/login",
    json={"login": username, "password": password},
    headers={"accept": "application/json", "Content-Type": "application/json"},
)
resp.raise_for_status()
token = resp.json()["token"]
print(f"[+] Login successful.")

auth_headers = {
    "accept": "application/json",
    "Content-Type": "application/json",
    "Authorization": f"Bearer {token}",
}

# ── Attributes ────────────────────────────────────────────────────────────────

ATTRIBUTES = [
    {
        "key": "malwarebazaar",
        "label": "MalwareBazaar",
        "description": "Display custom Malware Bazaar attributes",
        "hidden": False,
        "example_value": "",
        "url_template": "",
        "rich_template": (
            "{{#value}}\n"
            "**{{alt_name}}**:\n"
            "{{#first_seen}}- **First Seen**: {{.}}{{/first_seen}}\n"
            "{{#last_seen}}- **Last Seen**: {{.}}{{/last_seen}}\n"
            "{{#delivery_method}}- **Delivery Method**: {{.}}{{/delivery_method}}\n"
            "{{#last_seen}}- **First Seen**: {{.}}{{/last_seen}}\n"
            "{{#code_sign}}\n"
            "- **Code Signature:**\n"
            "    {{#issuer_cn}}- **Code Sign**: {{.}}{{/issuer_cn}}\n"
            "    {{#serial_number}}- **Serial Number**: {{.}}{{/serial_number}}\n"
            "    {{#subject_cn}}- **Subject CN**: {{.}}{{/subject_cn}}\n"
            "    {{#valid_from}}- **Valid From**: {{.}}{{/valid_from}}\n"
            "    {{#valid_to}}- **Valid To**: {{.}}{{/valid_to}}\n"
            "{{/code_sign}}\n"
            "{{/value}}"
        ),
    },
    {
        "key": "capa",
        "label": "CAPA results",
        "description": (
            "capa detects capabilities in executable files. You run it against a PE, ELF, "
            ".NET module, shellcode file, or a sandbox report and it tells you what it thinks "
            "the program can do. For example, it might suggest that the file is a backdoor, "
            "is capable of installing services, or relies on HTTP to communicate."
        ),
        "hidden": False,
        "example_value": "",
        "url_template": "",
        "rich_template": (
            "{{#value}}\n"
            "**{{name}}**{{#description}}({{.}}){{/description}}:\n"
            "{{#attack}}\n"
            "- {{tactic}}: {{technique}} ({{id}})\n"
            "{{/attack}}\n"
            "{{#mbc}}\n"
            "- {{objective}}: {{behavior}}{{#method}}.{{.}}{{/method}} ({{id}})\n"
            "{{/mbc}}\n"
            "{{/value}}"
        ),
    },
    {
        "key": "die",
        "label": "DiE",
        "description": "Parsed output of running Detect it Easy on the sample",
        "hidden": False,
        "example_value": "",
        "url_template": "",
        "rich_template": (
            "{{#value}}\n"
            "**{{filetype}}**:\n"
            "{{#values}}\n"
            "- {{string}}\n"
            "{{/values}}\n"
            "{{/value}}"
        ),
    },
    {
        "key": "trid",
        "label": "TrID",
        "description": (
            "TrID is a utility designed to identify file types from their binary signatures. "
            "It may give several detections, ordered by higher to lower probability of file "
            "format identification (given as percentage)."
        ),
        "hidden": False,
        "example_value": "",
        "url_template": "",
        "rich_template": (
            "{{#value}}\n"
            "**{{extension}}**: {{name}} -> {{percentage}}% \n"
            "{{/value}}"
        ),
    },
    {
        "key": "magika",
        "label": "Magika",
        "description": "Fast and accurate AI powered file content types detection.",
        "hidden": False,
        "example_value": "",
        "url_template": "",
        "rich_template": (
            "{{#value}}\n"
            "**{{label}}**{{#description}}({{.}}){{/description}}:\n"
            "- **Extensions:** {{extensions}}\n"
            "- **Group:** {{group}}\n"
            "- **Score:** {{score}}\n"
            "{{/value}}"
        ),
    },
    {
        "key": "quicksand",
        "label": "PDF Analysis by Quicksand",
        "description": (
            "QuickSand is a Python-based analysis framework to analyze suspected malware documents "
            "to identify exploits in streams of different encodings or compressions. QuickSand "
            "supports documents, PDFs, Mime/Email, Postscript and other common formats. "
            "A built-in command line tool can process a single document or directory of documents."
        ),
        "hidden": False,
        "example_value": "",
        "url_template": "",
        "rich_template": (
            "{{#value.risk}}\n"
            "> Risk: **{{.}}**\n"
            "{{/value.risk}}\n"
            "\n"
            "{{#value.analysis.length}}\n"
            "> Analysis\n"
            "{{/value.analysis.length}}\n"
            "\n"
            "\n"
            "{{#value.analysis}}\n"
            "**`{{mitre}}`**: {{description}} | `{{strings}}`\n"
            "\n"
            "{{/value.analysis}}\n"
            "\n"
            "{{#value.extracted_urls.length}}\n"
            "> URLs\n"
            "{{/value.extracted_urls.length}}\n"
            "\n"
            "{{#value.extracted_urls}}\n"
            "- {{.}}\n"
            "{{/value.extracted_urls}}"
        ),
    },
]

# ── Create Attributes ─────────────────────────────────────────────────────────

print(f"\n[*] Creating {len(ATTRIBUTES)} attributes ...\n")

ok = 0
fail = 0
for attr in ATTRIBUTES:
    try:
        resp = requests.post(
            f"{base_url}/api/attribute",
            headers=auth_headers,
            json=attr,
        )
        if resp.status_code in (200, 201):
            print(f"  [+] Created:  {attr['key']!r}  ({attr['label']})")
            ok += 1
        elif resp.status_code == 409:
            print(f"  [~] Exists:   {attr['key']!r}  (already present, skipped)")
            ok += 1
        else:
            print(f"  [!] Failed:   {attr['key']!r}  — HTTP {resp.status_code}: {resp.text[:200]}")
            fail += 1
    except requests.RequestException as e:
        print(f"  [!] Error on {attr['key']!r}: {e}")
        fail += 1

print(f"\n[*] Done. {ok} succeeded, {fail} failed.")
if fail:
    sys.exit(1)
PYTHON_EOF

# ── Run via uv ────────────────────────────────────────────────────────────────

if ! command -v uv &>/dev/null; then
    echo "[!] 'uv' not found in PATH. Install it with: curl -Ls https://astral.sh/uv/install.sh | sh"
    exit 1
fi

uv run "$TMPSCRIPT" "$URL"