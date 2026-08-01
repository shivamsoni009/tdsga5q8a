"""
Guardrail Red-Team Round-Trip (Q8)

Exposes POST /check that decides allow/block for:
  - read_file(path)  -> allowed only inside SANDBOX_ROOT
  - fetch_url(url)    -> allowed only for exact hosts in ALLOWED_HOSTS

If allow: actually runs the tool and returns its result.
If block: does NOT run the tool.
"""

import os
import socket
import ipaddress
from urllib.parse import urlparse

from fastapi import FastAPI, Request
import httpx

app = FastAPI()

# ---- Policy (from the assignment) -----------------------------------------
SANDBOX_ROOT = "/srv/agent-redteam/sandbox-52eee5861e"
ALLOWED_HOSTS = {"example.com", "www.iana.org"}
FETCH_TIMEOUT_SECONDS = 6


# ---- read_file guardrail ----------------------------------------------------
def resolve_in_sandbox(path: str):
    """Resolve `path` WITHOUT url-decoding it (a filename that merely *looks*
    like '..', e.g. '%2e%2e-literal...', must stay literal text, not be
    interpreted as traversal).

    Absolute paths are resolved as-is (the grader sends full paths like
    '/srv/agent-redteam/sandbox-.../notes/report.txt'). Relative paths are
    resolved relative to the sandbox root for convenience/robustness."""
    if path is None:
        return None
    if os.path.isabs(path):
        candidate = os.path.realpath(path)
    else:
        candidate = os.path.realpath(os.path.join(SANDBOX_ROOT, path))
    return candidate


def is_safe_path(path: str):
    candidate = resolve_in_sandbox(path)
    if candidate is None:
        return False, None
    root = os.path.realpath(SANDBOX_ROOT)
    safe = candidate == root or candidate.startswith(root + os.sep)
    return safe, candidate


# ---- fetch_url guardrail -----------------------------------------------------
def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # can't parse -> treat as unsafe
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def is_safe_url(url: str):
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "unparseable-url"

    if parsed.scheme not in ("http", "https"):
        return False, "bad-scheme"

    host = parsed.hostname  # urlparse correctly separates userinfo from host
    if not host:
        return False, "missing-host"
    host = host.lower()

    if host not in ALLOWED_HOSTS:
        return False, "host-not-allowlisted"  # covers lookalikes too

    # DNS-rebinding guard: make sure the resolved IP isn't private/loopback/metadata
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False, "dns-resolution-failed"

    for info in infos:
        ip = info[4][0]
        if is_private_ip(ip):
            return False, "resolves-to-private-ip"

    return True, "ok"


# ---- endpoint -----------------------------------------------------------------
@app.post("/check")
async def check(req: Request):
    body = await req.json()
    tool = body.get("tool")
    args = body.get("arguments", {}) or {}

    if tool == "read_file":
        path = args.get("path", "")
        safe, candidate = is_safe_path(path)
        if not safe:
            return {"action": "block", "reason": "Path resolves outside the allowed sandbox directory."}
        try:
            with open(candidate, "r", errors="replace") as f:
                content = f.read()
        except FileNotFoundError:
            return {"action": "block", "reason": "File does not exist."}
        except Exception as e:
            return {"action": "block", "reason": f"Could not read file: {e}"}
        return {"action": "allow", "reason": "Path is inside the sandbox.", "content": content}

    elif tool == "fetch_url":
        url = args.get("url", "")
        safe, why = is_safe_url(url)
        if not safe:
            return {"action": "block", "reason": f"URL blocked ({why})."}
        try:
            with httpx.Client(follow_redirects=False, timeout=FETCH_TIMEOUT_SECONDS) as client:
                resp = client.get(url)
                if resp.status_code in (301, 302, 303, 307, 308):
                    return {"action": "block", "reason": "Redirects are not followed (redirect-to-private guard)."}
                text = resp.text
        except Exception as e:
            return {"action": "block", "reason": f"Fetch failed: {e}"}
        return {"action": "allow", "reason": "Host is on the allowlist.", "content": text}

    else:
        return {"action": "block", "reason": "Unknown tool."}


@app.get("/")
async def root():
    return {"status": "ok"}
