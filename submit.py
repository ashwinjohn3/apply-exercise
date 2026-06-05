#!/usr/bin/env python3
"""
Run modes:
  python3 submit.py --selftest   Reproduce the published test vector to prove 
                                 signing logic is correct. No network.
  python3 submit.py --dry-run    Print the exact body + signature we WOULD send.
  python3 submit.py              Build the payload from the CI environment, POST
                                 it, and print the returned receipt. Refuses to
                                 run outside GitHub Actions.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

# Load a local .env for convenience when running on a developer machine.
# python-dotenv is intentionally NOT a CI dependency: in GitHub Actions the
# signing secret is injected straight into the environment, so a missing library
# (or missing .env file) must never be fatal.
try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    pass
else:
    load_dotenv()

ENDPOINT = "https://b12.io/apply/submission"

SIGNING_SECRET = os.environ.get("B12_SIGNING_SECRET")

# Applicant details.
NAME = "Ashwin John Chempolil"
EMAIL = "ashwinchempolil@gmail.com"
RESUME_LINK = "https://github.com/ashwinjohn3/ajc-portfolio/raw/main/public/resume.pdf"


def canonical_body(payload: dict) -> bytes:
    """Serialize to the exact bytes the server will hash.

    sort_keys -> alphabetical key order; separators -> no whitespace; UTF-8 bytes.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(body: bytes, secret: str) -> str:
    """Return the X-Signature-256 header value for the given raw body."""
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def selftest() -> int:
    """Reproduce the published test vector to prove the signing logic is correct."""
    example = {
        "timestamp": "2026-01-06T16:59:37.571Z",
        "name": "Your name",
        "email": "you@example.com",
        "resume_link": "https://pdf-or-html-or-linkedin.example.com",
        "repository_link": "https://link-to-github-or-other-forge.example.com/your/repository",
        "action_run_link": "https://link-to-github-or-another-forge.example.com/your/repository/actions/runs/run_id",
    }
    expected_body = (
        '{"action_run_link":"https://link-to-github-or-another-forge.example.com'
        '/your/repository/actions/runs/run_id","email":"you@example.com",'
        '"name":"Your name","repository_link":"https://link-to-github-or-other-forge'
        '.example.com/your/repository","resume_link":"https://pdf-or-html-or-linkedin'
        '.example.com","timestamp":"2026-01-06T16:59:37.571Z"}'
    )
    expected_digest = "c5db257a56e3c258ec1162459c9a295280871269f4cf70146d2c9f1b52671d45"

    body = canonical_body(example)
    if body.decode("utf-8") != expected_body:
        sys.exit("FAIL: canonical body does not match the published example.")
    digest = sign(body, "hello-there-from-b12").removeprefix("sha256=")
    if digest != expected_digest:
        sys.exit(f"FAIL: digest mismatch — got {digest}")
    print("selftest OK: canonical body and HMAC-SHA256 digest match the published test vector.")
    return 0


def build_payload() -> dict:
    """Assemble the payload, discovering repo/run links from the CI environment.

    Outside GitHub Actions the GITHUB_* vars are absent; we fall back to obvious
    placeholders so --dry-run still shows the shape. submit() guards against
    actually POSTing those placeholders.
    """
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "OWNER/REPO")
    run_id = os.environ.get("GITHUB_RUN_ID", "RUN_ID")

    now = datetime.now(timezone.utc)
    timestamp = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    return {
        "timestamp": timestamp,
        "name": NAME,
        "email": EMAIL,
        "resume_link": RESUME_LINK,
        "repository_link": f"{server}/{repo}",
        "action_run_link": f"{server}/{repo}/actions/runs/{run_id}",
    }


def submit(payload: dict) -> int:
    if not os.environ.get("GITHUB_RUN_ID"):
        sys.exit("Refusing to POST outside GitHub Actions (no GITHUB_RUN_ID). Use --dry-run locally.")

    body = canonical_body(payload)
    signature = sign(body, SIGNING_SECRET)

    request = urllib.request.Request(
        ENDPOINT,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "X-Signature-256": signature},
    )
    try:
        with urllib.request.urlopen(request) as response:
            status = response.status
            text = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        sys.exit(f"B12 returned HTTP {exc.code}: {detail}")

    print(f"HTTP {status}")
    print(text)
    receipt = json.loads(text).get("receipt")
    if not receipt:
        sys.exit("No receipt in response — submission may have failed.")
    print(f"RECEIPT: {receipt}")

    # Surface the receipt in the Actions run summary for easy copy/paste.
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(f"## Submission receipt\n\n`{receipt}`\n")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()

    payload = build_payload()

    if "--dry-run" in argv:
        body = canonical_body(payload)
        print("Canonical body:")
        print(body.decode("utf-8"))
        print("\nX-Signature-256:")
        print(sign(body, SIGNING_SECRET))
        return 0

    return submit(payload)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
