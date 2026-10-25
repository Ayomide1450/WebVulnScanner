# Detection roadmap — closing the gap between the scanner and a pentester

You're right that the scanner misses issues a manual test would catch. That
isn't a defect to patch — it's structural. This document explains *which*
classes of bug are out of reach, which are reachable with more work, and a
prioritised plan for the reachable ones. It's deliberately honest about the
ceiling, because overstating what an automated tool finds is exactly what
erodes trust with a security-literate buyer.

## The honest framing: three tiers of findability

**Tier 1 — mechanically detectable (Glassbox already does these well).**
Missing security headers, weak TLS, exposed paths, outdated JS, reflected
XSS canaries, SQLi error signatures, open redirects. One request, one
deterministic signal. This is the scanner's home ground.

**Tier 2 — detectable with state, baselines, or correlation (the growth
area — most of this doc).** IDOR, auth bypass, cache poisoning, race
conditions, some SSRF. A scanner *can* find these, but only with multiple
authenticated sessions, baseline diffing, and logic that reasons about
*relationships between responses* rather than single responses. Glassbox
has started here (the cross-account IDOR check, the credentialed
auth-comparison) but it's shallow.

**Tier 3 — needs a human (never fully automatable; this is your service's
moat).** Business-logic flaws ("can I apply the same coupon twice", "can I
skip the payment step"), chained exploits, anything requiring understanding
of what the application is *for*. Don't try to automate these — they're the
reason the manual review is worth $1,250.

The strategic point: **push Tier 2 as far as it will go so the automated
scan is genuinely useful, then sell Tier 3 as the thing only a human
does.** That split is also your honest sales pitch.

---

## Prioritised Tier-2 improvements

Ranked by value-to-effort. Each is a real, bounded piece of work.

### 1. Two-session IDOR sweep (highest value)
**Gap:** the current IDOR check is narrow. Broken access control is the #1
real-world bug and the one your whole sales pitch leans on.
**Method:** take two authenticated sessions (A and B). Crawl A's authorised
surface, harvest every URL/API path containing an ID-like token
(`/order/1042`, `/api/user/88`, `?doc=551`). Replay each with B's session
and with no session. Flag any that returns A's object identifiers or a
200 with B-distinct content.
**Why it's Tier 2 not 3:** it's mechanical once you have two accounts — no
understanding of meaning required, just "did B reach A's object."
**Effort:** medium. The two-account harness already exists for the advanced
scan. This extends it from a handful of endpoints to a systematic sweep.
**Confidence discipline:** only "Confirmed" when B *provably* received A's
data (an ID or marker seeded into A's object echoes back), never on a bare
200 — the existing corroboration lock already enforces this philosophy.

### 2. Baseline-diff everything (force-multiplier for all other checks)
**Gap:** many false positives and misses come from judging one response in
isolation. The cache-deception fix in this session is a microcosm — it only
became correct once it compared against a baseline.
**Method:** fetch a known-good baseline per endpoint (normal request), then
judge every probe as a *diff* against it: status delta, length delta,
timing delta, reflected-content delta. Response length/time is often the
only signal for blind injection and broken auth.
**Effort:** medium, but it's infrastructure that sharpens a dozen existing
checks at once. Build it as a helper every check can call.

### 3. Blind & time-based injection (SQLi, SSTI, command)
**Gap:** the scanner catches injection that *reflects* an error or a canary.
It misses blind injection, which is most of real-world injection.
**Method:** boolean-differential (`' AND 1=1` vs `' AND 1=2` → different
response = injectable) and time-based (`SLEEP(5)` → measurable delay),
leaning on the baseline-diff infrastructure from #2. The codebase already
has `TIME_BLIND_DELAY` constants — extend that discipline across parameters.
**Effort:** medium-high. **Safety:** keep the existing "stop after first
confirmed, cap probes" constraints — blind probes are noisy and you must not
hammer a target.

### 4. Authenticated crawl depth + state awareness
**Gap:** the crawler is same-origin, depth-1, and largely unauthenticated.
Most of an app's attack surface is *behind* login and more than one click
deep.
**Method:** drive an authenticated session, follow forms (read-only — never
auto-submit state-changing POSTs without explicit opt-in, per the existing
safety rule), build a fuller URL inventory to feed checks #1 and #3.
**Effort:** high. This is the backbone that makes 1 and 3 much stronger.

### 5. Smarter secret & exposure detection
**Gap:** secret detection is regex-on-responses. It misses secrets in
sourcemaps, `.git/config`, `.env` left in webroot, JWT structure/claims,
and API keys in JS bundles.
**Method:** fetch-and-parse sourcemaps, probe a curated high-signal path
list (`.git/HEAD`, `.env`, `/actuator`, `/.well-known/`), decode and inspect
JWTs for `alg:none`/weak secrets (there's already a `jwt` check to deepen).
**Effort:** low-medium, high signal, low false-positive risk. Good
quick win.

### 6. Headless-browser pass for client-side bugs (bigger bet)
**Gap:** the scanner sees raw HTML, not the rendered DOM. It misses DOM XSS,
client-side open redirects, `postMessage` bugs, and anything a modern SPA
only exposes after JS runs.
**Method:** an opt-in Playwright/headless-Chromium check that renders the
page, hooks `eval`/`innerHTML`/`document.write` sinks, and watches for
canary execution.
**Effort:** high, and it adds a heavy dependency. Worth it once 1–5 are
done, because SPAs are increasingly where the bugs are.

---

## What NOT to build (and tell customers so)

- **Business-logic abuse** — coupon reuse, price tampering, workflow
  skipping. These require understanding the app's purpose. This is Tier 3:
  your manual review, not the scanner.
- **Full CVE/dependency scanning** — `npm audit`/Trivy/Semgrep do this on
  the source repo far better than a black-box scanner can from outside.
  Integrate/recommend them rather than reimplementing.
- **Anything destructive** — the whole codebase is built around
  non-destructive, authorised testing. Do not add exploit payloads that
  modify or delete data to chase a higher "confirmed" rate. The restraint
  is a feature and a legal necessity.

## Suggested sequence

1. **Baseline-diff infrastructure (#2)** — unlocks the quality of
   everything else.
2. **Two-session IDOR sweep (#1)** — highest-value finding class, and the
   centre of your sales story.
3. **Secret/exposure deepening (#5)** — cheap, high-signal quick win.
4. **Blind injection (#3)** — on top of the baseline infra.
5. **Authenticated crawl (#4)**, then **headless pass (#6)** — the larger
   bets, once the fundamentals are strong.

Each should land as its own phase with its own tests, its own safety
constraints preserved, and its findings held to the existing
confidence/corroboration discipline — a scanner that cries wolf is worse
than one that stays quiet.
