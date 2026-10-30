# DefenSync Trusted Devices — print-only QA command sheet.
# Does not start services, send email, or modify the database.
# Run from the repo root:
#   powershell -ExecutionPolicy Bypass -File scripts\qa_trusted_devices_commands.ps1

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
python scripts/qa_trusted_devices_setup.py --print-commands --print-checklist
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
