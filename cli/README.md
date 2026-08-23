# glassbox CLI

A security control plane for developers and security engineers. Every
command is a thin client over Glassbox's own HTTP API - it talks to a
server, never executes anything itself.

## Install

From the root of this repository (any Python 3.10+):

    pip install .\cli        # Windows
    pip install ./cli        # macOS / Linux

This provides a real `glassbox` command. If it's "not recognized", you
installed into a virtualenv - activate it first, or call the script by
full path (`.venv\Scripts\glassbox.exe`).

## Connect (one time)

1. Log into your Glassbox web account.
2. Top nav -> **API Tokens** -> **Generate Token** (copy it immediately -
   it is shown only once).
3. Then run:

       glassbox init --api-url https://your-glassbox-host

   Paste the token at the prompt (each character appears as `*`) and press
   Enter. It is validated against the live API before being saved to
   `~/.glassbox/config.json`.

Non-interactive alternative (CI pipelines, dotfiles):

    set GLASSBOX_API_TOKEN=...      # or pass --token to any command
    set GLASSBOX_API_URL=https://your-glassbox-host

## The core loop

    glassbox check .                      # offline: hardcoded secrets in your source
    glassbox assess https://yoursite.com  # full assessment + wait for result
    glassbox readiness https://yoursite.com
    glassbox findings                     # findings from the latest assessment
    glassbox report --csv                 # export the latest report as CSV
    glassbox gate https://yoursite.com --fail-on high   # CI/CD: exit 1 on high+ findings

Lower-level commands:

    glassbox assets list            # your registered Assets
    glassbox scan start <asset-id>  # trigger a scan for an Asset
    glassbox compare <id> <id>      # diff two assessments
    glassbox verify <url>           # re-assess + diff against last run

Every command supports `--help`. Launching commands still enforce the same
server-side authorization as the web UI (domain ownership/SSRF/tier gates) -
the CLI cannot bypass them.
