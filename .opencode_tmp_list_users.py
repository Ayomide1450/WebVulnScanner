from webvulnscanner import create_app
from webvulnscanner.models import User

app = create_app()
with app.app_context():
    for u in User.query.all():
        org = u.organization
        plan = org.plan.value if org else None
        verified = sorted(d.domain for d in org.verifications) if org else []
        print(u.email, "|", org.name if org else None, "|", plan, "|", ",".join(verified) or "-")
