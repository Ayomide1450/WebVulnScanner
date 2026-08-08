# Vercel Python entrypoint for the web/API layer only.
#
# This wraps the existing Flask app factory unchanged - no scan-execution
# logic lives here. Per docs/vercel-migration.md, this covers auth/org/
# billing/dashboard/report routes; it does NOT make scan execution
# serverless-safe. Routes that spawn a background scan thread
# (webvulnscanner/scan_routes.py's new_scan_* views) will still not survive
# a Vercel function's request lifetime until the queue/worker split
# described in that doc is actually built - deploying this as-is means
# those routes remain unreliable on Vercel specifically, even though every
# other route works.
from webvulnscanner import create_app

app = create_app()
