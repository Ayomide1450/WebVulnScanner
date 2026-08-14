"""
WebVulnScanner - a local, single-user-per-account website security checkup
tool.

Run only against domains you own or are explicitly authorized to test.

This file is now a thin app factory (Workstream 4's cutover). Everything
else - models, blueprints, checks, orchestrators, entitlement gating - lives
in the `webvulnscanner/` package. The old synchronous `/`, `/scan`,
`/scan-advanced`, `/scan-media` routes that used to live here are retired in
favor of `webvulnscanner.public_routes` ("/") and `webvulnscanner.scan_routes`
(`/dashboard`, `/scan/new` + its four dedicated `/base`/`/advanced`/`/media`/
`/api` sub-pages, `/scan/<id>`, `/scan/<id>/events`, `/scan/<id>/report`,
`/scan/<id>/compare/<other_id>`).
"""
from webvulnscanner import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=False, port=5000)
