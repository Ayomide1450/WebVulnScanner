# Production image for Fly.io (or any Docker-based host). Mirrors the same
# startCommand Render's render.yaml/Procfile already use (flask db upgrade
# then gunicorn) so behavior doesn't diverge between deploy targets.
FROM python:3.12-slim

WORKDIR /app

# psycopg2-binary and Pillow (already in requirements.txt) need these at
# import/runtime; kept minimal rather than pulling the full build-essential set.
# WeasyPrint (Phase 24) needs pango/harfbuzz for text layout and font-noto for
# non-ASCII/CJK glyph coverage; fontconfig caches fonts at build time.
# python3-saml (Phase 26) needs libxmlsec1 for SAML Response signature validation;
# libxmlsec1-dev + pkg-config needed at build time for the C extension.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 libjpeg62-turbo zlib1g \
    pango1.0-tools libpango-1.0-0 libpangocairo-1.0-0 \
    libharfbuzz0b libharfbuzz-subset0 \
    libfontconfig1 fonts-noto-cjk \
    libxml2 libxmlsec1 libxmlsec1-dev pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && fc-cache -f

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=app.py \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

# --workers 1: SCHEDULER_ENABLED's in-process daemon thread (glassbox/scheduler.py)
# and Flask-Limiter's in-memory storage are both single-process assumptions
# today - see CLAUDE.md's "Known limitations" before raising this. --threads 4
# lets background scan threads (threading.Thread per scan) and normal request
# handling overlap within that one worker.
CMD ["sh", "-c", "flask db upgrade && gunicorn app:app --workers 1 --threads 4 --timeout 120 --bind 0.0.0.0:8080"]
