"""Phase 21 (ST-04/05): the /selftest page - one click to prove the ten
intrusive checks actually detect what they claim to detect, against an
in-process loopback lure. No Scan row, no report file, no external traffic;
the whole run lives inside this process for ~2 seconds."""

from flask import Blueprint, render_template
from flask_login import login_required
from flask_wtf import FlaskForm

from .extensions import limiter
from .selftest import run_selftest

selftest = Blueprint("selftest", __name__)


class SelfTestForm(FlaskForm):
    pass


@selftest.route("/selftest", methods=["GET", "POST"])
@login_required
@limiter.limit("30/hour", methods=["POST"])
def index():
    form = SelfTestForm()
    report = None
    if form.validate_on_submit():
        report = run_selftest()
    return render_template("selftest.html", form=form, report=report)
