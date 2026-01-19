#!/usr/bin/env python3
"""
HTTP-only Cursor AI sign-up helper.

Flow:
1) GET /sign-up
2) If Cloudflare challenge detected, solve via CapSolver and retry
3) If Turnstile is present, solve and attach token
4) Try API endpoints to trigger email code
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Iterable, List, Optional, Tuple

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)

CAPSOLVER_CREATE_URL = "https://api.capsolver.com/createTask"
CAPSOLVER_RESULT_URL = "https://api.capsolver.com/getTaskResult"

TURNSTILE_KEY_PATTERNS = [
    r'data-sitekey="([^"]+)"',
    r"data-sitekey='([^']+)'",
    r'"sitekey"\s*:\s*"([^"]+)"',
    r"'sitekey'\s*:\s*'([^']+)'",
]

CF_SCRIPT_PATTERNS = [
    r'["\'](/cdn-cgi/challenge-platform/[^"\']+chl_page/v1[^"\']*)["\']',
]

DEFAULT_ENDPOINTS = [
    "/api/auth/signup",
    "/api/auth/sign-up",
    "/api/auth/register",
    "/api/auth/send-code",
    "/api/auth/send-otp",
    "/api/auth/email",
    "/api/auth/signin/email",
]


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def decode_body(body: bytes, headers: Dict[str, str]) -> str:
    content_type = headers.get("Content-Type", "")
    match = re.search(r"charset=([^\s;]+)", content_type)
    charset = match.group(1) if match else "utf-8"
    return body.decode(charset, errors="replace")


def get_origin(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def extract_redirect_origin(url: str) -> Optional[str]:
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(parts.query)
    redirect_values = query.get("redirect_uri")
    if not redirect_values:
        return None
    redirect_url = redirect_values[0]
    if not redirect_url:
        return None
    return get_origin(redirect_url)


def normalize_endpoints(base_url: str, endpoints: Iterable[str]) -> List[str]:
    normalized = []
    for ep in endpoints:
        ep = ep.strip()
        if not ep:
            continue
        normalized.append(urllib.parse.urljoin(base_url, ep))
    return normalized


def extract_api_candidates(html: str) -> List[str]:
    candidates = set(re.findall(r'["\'](\/api\/[^"\']+)["\']', html))
    return sorted(candidates)


def rank_endpoints(endpoints: Iterable[str]) -> List[str]:
    keywords = [
        "sign-up",
        "signup",
        "register",
        "send-code",
        "send-otp",
        "verify",
        "verification",
        "email",
        "signin",
    ]

    def score(url: str) -> Tuple[int, int]:
        lower = url.lower()
        hits = sum(1 for key in keywords if key in lower)
        return (-hits, len(url))

    return sorted(endpoints, key=score)


def extract_turnstile_sitekey(html: str) -> Optional[str]:
    for pattern in TURNSTILE_KEY_PATTERNS:
        match = re.search(pattern, html)
        if match:
            return match.group(1)
    return None


def extract_challenge_script_path(html: str) -> Optional[str]:
    for pattern in CF_SCRIPT_PATTERNS:
        match = re.search(pattern, html)
        if match:
            return match.group(1)
    return None


def is_cf_challenge(status: int, headers: Dict[str, str], body_text: str) -> bool:
    if headers.get("cf-mitigated") == "challenge":
        return True
    if "cdn-cgi/challenge-platform" in body_text:
        return True
    if status in (403, 503) and "Just a moment" in body_text:
        return True
    return False


def set_cookie(jar: http.cookiejar.CookieJar, domain: str, name: str, value: str) -> None:
    cookie = http.cookiejar.Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain=domain,
        domain_specified=True,
        domain_initial_dot=domain.startswith("."),
        path="/",
        path_specified=True,
        secure=True,
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest={"HttpOnly": None},
        rfc2109=False,
    )
    jar.set_cookie(cookie)


def extract_cookie_value(cookie_header: str, name: str) -> Optional[str]:
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith(name + "="):
            return part.split("=", 1)[1]
    return None


class HttpClient:
    def __init__(self, user_agent: str, proxy: Optional[str], timeout: int) -> None:
        self.user_agent = user_agent
        self.timeout = timeout
        self.cookie_jar = http.cookiejar.CookieJar()
        self.last_url: Optional[str] = None

        handlers = [urllib.request.HTTPCookieProcessor(self.cookie_jar)]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self.opener = urllib.request.build_opener(*handlers)

    def request(
        self, method: str, url: str, headers: Optional[Dict[str, str]] = None, data: Optional[bytes] = None
    ) -> Tuple[int, Dict[str, str], bytes]:
        request_headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
        }
        if headers:
            request_headers.update(headers)
        req = urllib.request.Request(url, data=data, headers=request_headers, method=method)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                self.last_url = resp.geturl()
                body = resp.read()
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as exc:
            self.last_url = exc.geturl()
            body = exc.read()
            return exc.code, dict(exc.headers), body
        except urllib.error.URLError as exc:
            self.last_url = None
            raise RuntimeError(f"Request failed: {exc}") from exc

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], bytes]:
        return self.request("GET", url, headers=headers)

    def head(self, url: str, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], bytes]:
        return self.request("HEAD", url, headers=headers)

    def post(
        self, url: str, headers: Optional[Dict[str, str]] = None, data: Optional[bytes] = None
    ) -> Tuple[int, Dict[str, str], bytes]:
        return self.request("POST", url, headers=headers, data=data)


def capsolver_request(url: str, payload: Dict[str, object], timeout: int) -> Dict[str, object]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read()
        raise RuntimeError(f"CapSolver error: HTTP {exc.code} {body[:200]!r}") from exc
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"CapSolver response is not JSON: {body[:200]!r}") from exc


def capsolver_create_task(client_key: str, task: Dict[str, object], timeout: int) -> str:
    payload = {"clientKey": client_key, "task": task}
    response = capsolver_request(CAPSOLVER_CREATE_URL, payload, timeout=timeout)
    if response.get("errorId"):
        raise RuntimeError(f"CapSolver createTask error: {response}")
    task_id = response.get("taskId")
    if not task_id:
        raise RuntimeError(f"CapSolver createTask missing taskId: {response}")
    return str(task_id)


def capsolver_wait_for_result(
    client_key: str, task_id: str, timeout: int, poll_interval: int, poll_timeout: int
) -> Dict[str, object]:
    payload = {"clientKey": client_key, "taskId": task_id}
    deadline = time.time() + poll_timeout
    while time.time() < deadline:
        response = capsolver_request(CAPSOLVER_RESULT_URL, payload, timeout=timeout)
        if response.get("errorId"):
            raise RuntimeError(f"CapSolver getTaskResult error: {response}")
        if response.get("status") == "ready":
            return response
        time.sleep(poll_interval)
    raise RuntimeError("CapSolver timeout waiting for task result")


def build_capsolver_task(
    url: str,
    user_agent: str,
    proxy: Optional[str],
    html: Optional[str],
    sitekey: Optional[str],
    task_type: Optional[str],
    task_json: Optional[str],
) -> Dict[str, object]:
    if task_json:
        try:
            task = json.loads(task_json)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Invalid --capsolver-task-json") from exc
        if not isinstance(task, dict):
            raise RuntimeError("--capsolver-task-json must be a JSON object")
        return task

    if task_type:
        resolved_type = task_type
    else:
        if sitekey:
            resolved_type = "TurnstileTaskProxyless" if not proxy else "TurnstileTask"
        else:
            resolved_type = "CloudflareTask"

    task: Dict[str, object] = {"type": resolved_type, "websiteURL": url}
    if sitekey:
        task["websiteKey"] = sitekey
    if user_agent:
        task["userAgent"] = user_agent
    if proxy and not resolved_type.lower().endswith("proxyless"):
        task["proxy"] = proxy
    if html and "Cloudflare" in resolved_type:
        task["html"] = html
    return task


def extract_solution_token(solution: Dict[str, object]) -> Optional[str]:
    for key in ("token", "gRecaptchaResponse", "cf_turnstile_response", "captchaToken", "answer"):
        value = solution.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def extract_cf_clearance(solution: Dict[str, object]) -> Optional[str]:
    for key in ("cf_clearance", "cfClearance"):
        value = solution.get(key)
        if isinstance(value, str) and value:
            return value
    cookie_blob = solution.get("cookie") or solution.get("cookies")
    if isinstance(cookie_blob, str) and "cf_clearance=" in cookie_blob:
        return extract_cookie_value(cookie_blob, "cf_clearance")
    return None


def apply_capsolver_solution(
    client: HttpClient, base_url: str, solution: Dict[str, object]
) -> Tuple[Optional[str], Optional[str]]:
    user_agent = solution.get("userAgent")
    if isinstance(user_agent, str) and user_agent:
        client.user_agent = user_agent
        eprint(f"[capsolver] using user agent from solution: {user_agent}")

    cf_clearance = extract_cf_clearance(solution)
    if cf_clearance:
        domain = "." + urllib.parse.urlsplit(base_url).netloc
        set_cookie(client.cookie_jar, domain, "cf_clearance", cf_clearance)
        eprint("[capsolver] applied cf_clearance cookie")

    token = extract_solution_token(solution)
    return token, cf_clearance


def solve_with_capsolver(
    capsolver_key: str,
    task: Dict[str, object],
    timeout: int,
    poll_interval: int,
    poll_timeout: int,
) -> Dict[str, object]:
    eprint(f"[capsolver] createTask type={task.get('type')}")
    task_id = capsolver_create_task(capsolver_key, task, timeout=timeout)
    eprint(f"[capsolver] taskId={task_id}, polling...")
    result = capsolver_wait_for_result(
        capsolver_key, task_id, timeout=timeout, poll_interval=poll_interval, poll_timeout=poll_timeout
    )
    solution = result.get("solution")
    if not isinstance(solution, dict):
        raise RuntimeError(f"CapSolver result missing solution: {result}")
    return solution


def dump_response(
    dump_dir: Optional[str], name: str, status: int, headers: Dict[str, str], body: bytes
) -> None:
    if not dump_dir:
        return
    os.makedirs(dump_dir, exist_ok=True)
    path = os.path.join(dump_dir, f"{name}.txt")
    with open(path, "wb") as handle:
        handle.write(f"STATUS {status}\n".encode("utf-8"))
        for key, value in headers.items():
            handle.write(f"{key}: {value}\n".encode("utf-8"))
        handle.write(b"\n")
        handle.write(body)


def build_payload(
    email: str,
    password: Optional[str],
    name: Optional[str],
    invite_code: Optional[str],
    captcha_token: Optional[str],
    captcha_fields: List[str],
) -> Dict[str, object]:
    payload: Dict[str, object] = {"email": email}
    if password:
        payload["password"] = password
    if name:
        payload["name"] = name
    if invite_code:
        payload["inviteCode"] = invite_code
    if captcha_token and captcha_fields:
        for field in captcha_fields:
            field = field.strip()
            if field:
                payload[field] = captcha_token
    return payload


def looks_like_success(status: int, body_text: str) -> bool:
    if status in (200, 201, 202, 204):
        if re.search(r"(code|verification|verify|email).*(sent|send)", body_text, re.I):
            return True
        return True
    return False


def fetch_turnstile_sitekey_from_challenge(
    client: HttpClient,
    page_url: str,
    page_origin: str,
    html: str,
    dump_dir: Optional[str],
) -> Optional[str]:
    script_path = extract_challenge_script_path(html)
    if not script_path:
        return None
    script_url = urllib.parse.urljoin(page_origin, script_path)
    eprint(f"[flow] fetching challenge script: {script_url}")
    status, headers, body = client.get(
        script_url,
        headers={"Accept": "*/*", "Referer": page_url},
    )
    dump_response(dump_dir, "cf_challenge_script", status, headers, body)
    if status >= 400:
        return None
    script_text = decode_body(body, headers)
    return extract_turnstile_sitekey(script_text)


def try_nextauth_email(
    client: HttpClient,
    base_url: str,
    email: str,
    referer: str,
    dump_dir: Optional[str],
) -> bool:
    csrf_url = urllib.parse.urljoin(base_url, "/api/auth/csrf")
    status, headers, body = client.get(csrf_url, headers={"Accept": "application/json"})
    dump_response(dump_dir, "nextauth_csrf", status, headers, body)
    body_text = decode_body(body, headers)
    csrf_token = None
    try:
        data = json.loads(body_text)
        csrf_token = data.get("csrfToken")
    except json.JSONDecodeError:
        match = re.search(r'name="csrfToken"\s+value="([^"]+)"', body_text)
        if match:
            csrf_token = match.group(1)

    if not csrf_token:
        eprint("[nextauth] csrfToken not found")
        return False

    signin_url = urllib.parse.urljoin(base_url, "/api/auth/signin/email")
    form = {
        "csrfToken": csrf_token,
        "email": email,
        "callbackUrl": base_url,
        "json": "true",
    }
    data = urllib.parse.urlencode(form).encode("utf-8")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json, text/plain, */*",
        "Origin": base_url,
        "Referer": referer,
    }
    status, headers, body = client.post(signin_url, headers=headers, data=data)
    dump_response(dump_dir, "nextauth_signin_email", status, headers, body)
    body_text = decode_body(body, headers)
    eprint(f"[nextauth] status={status}")
    return looks_like_success(status, body_text)


def attempt_signup_requests(
    client: HttpClient,
    base_url: str,
    endpoints: List[str],
    email: str,
    password: Optional[str],
    name: Optional[str],
    invite_code: Optional[str],
    captcha_token: Optional[str],
    captcha_fields: List[str],
    referer: str,
    dump_dir: Optional[str],
) -> bool:
    payload = build_payload(email, password, name, invite_code, captcha_token, captcha_fields)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "Origin": base_url,
        "Referer": referer,
    }

    for endpoint in endpoints:
        if endpoint.endswith("/api/auth/signin/email"):
            continue
        data = json.dumps(payload).encode("utf-8")
        status, resp_headers, body = client.post(endpoint, headers=headers, data=data)
        dump_response(dump_dir, f"signup_{endpoint.rsplit('/', 1)[-1]}", status, resp_headers, body)
        body_text = decode_body(body, resp_headers)
        eprint(f"[signup] {endpoint} status={status}")
        if looks_like_success(status, body_text):
            eprint("[signup] success signal detected")
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Cursor AI email code trigger (HTTP only).")
    parser.add_argument("--email", required=True, help="Test email to register.")
    parser.add_argument("--password", help="Optional password if required by API.")
    parser.add_argument("--name", help="Optional name if required by API.")
    parser.add_argument("--invite-code", help="Optional invite code.")
    parser.add_argument("--base-url", default="https://authenticator.cursor.sh")
    parser.add_argument("--signup-path", default="/sign-up")
    parser.add_argument("--user-agent", default=DEFAULT_UA)
    parser.add_argument("--proxy", help="Optional proxy like http://user:pass@host:port")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--poll-interval", type=int, default=5)
    parser.add_argument("--poll-timeout", type=int, default=180)
    parser.add_argument("--capsolver-key", default=os.getenv("CAPSOLVER_API_KEY"))
    parser.add_argument("--capsolver-task-type", help="Override CapSolver task type.")
    parser.add_argument("--capsolver-task-json", help="Raw CapSolver task JSON.")
    parser.add_argument(
        "--captcha-fields",
        default="turnstileToken,captchaToken,cfTurnstileResponse",
        help="Comma-separated fields for captcha token in signup payload.",
    )
    parser.add_argument("--endpoints", help="Comma-separated API endpoints to try.")
    parser.add_argument("--dump-dir", help="Write response dumps to this directory.")
    args = parser.parse_args()

    client = HttpClient(args.user_agent, args.proxy, args.timeout)
    signup_url = urllib.parse.urljoin(args.base_url, args.signup_path)
    eprint(f"[flow] HEAD {signup_url}")
    head_status, head_headers, _ = client.head(signup_url, headers={"Accept": "text/html,*/*"})
    dump_response(args.dump_dir, "signup_head", head_status, head_headers, b"")
    page_url = client.last_url or signup_url
    if page_url != signup_url:
        eprint(f"[flow] redirect detected: {page_url}")

    eprint(f"[flow] GET {page_url}")
    status, headers, body = client.get(page_url)
    dump_response(args.dump_dir, "signup_page_initial", status, headers, body)
    body_text = decode_body(body, headers)
    page_origin = get_origin(page_url)
    if page_url != signup_url:
        eprint(f"[flow] landing page: {page_url}")

    if is_cf_challenge(status, headers, body_text):
        if not args.capsolver_key:
            eprint("Cloudflare challenge detected but CAPSOLVER_API_KEY is missing.")
            return 2
        eprint("[flow] Cloudflare challenge detected")
        sitekey = extract_turnstile_sitekey(body_text)
        if not sitekey:
            sitekey = fetch_turnstile_sitekey_from_challenge(
                client=client,
                page_url=page_url,
                page_origin=page_origin,
                html=body_text,
                dump_dir=args.dump_dir,
            )
            if sitekey:
                eprint(f"[flow] sitekey extracted from challenge: {sitekey}")
        if not sitekey and not args.capsolver_task_type and not args.capsolver_task_json:
            eprint(
                "Cloudflare challenge did not expose a Turnstile sitekey. "
                "Provide --capsolver-task-type or --capsolver-task-json."
            )
            return 5
        task = build_capsolver_task(
            url=page_url,
            user_agent=client.user_agent,
            proxy=args.proxy,
            html=body_text,
            sitekey=sitekey,
            task_type=args.capsolver_task_type,
            task_json=args.capsolver_task_json,
        )
        solution = solve_with_capsolver(
            args.capsolver_key,
            task,
            timeout=args.timeout,
            poll_interval=args.poll_interval,
            poll_timeout=args.poll_timeout,
        )
        apply_capsolver_solution(client, page_origin, solution)
        eprint(f"[flow] retry GET {page_url}")
        status, headers, body = client.get(page_url)
        dump_response(args.dump_dir, "signup_page_after_cf", status, headers, body)
        body_text = decode_body(body, headers)
        page_url = client.last_url or page_url
        page_origin = get_origin(page_url)
        if is_cf_challenge(status, headers, body_text):
            eprint("Cloudflare challenge still present after CapSolver.")
            return 3

    turnstile_sitekey = extract_turnstile_sitekey(body_text)
    captcha_token = None
    if turnstile_sitekey:
        if not args.capsolver_key:
            eprint("Turnstile detected but CAPSOLVER_API_KEY is missing.")
            return 4
        eprint(f"[flow] Turnstile sitekey detected: {turnstile_sitekey}")
        task = build_capsolver_task(
            url=page_url,
            user_agent=client.user_agent,
            proxy=args.proxy,
            html=None,
            sitekey=turnstile_sitekey,
            task_type=args.capsolver_task_type,
            task_json=args.capsolver_task_json,
        )
        solution = solve_with_capsolver(
            args.capsolver_key,
            task,
            timeout=args.timeout,
            poll_interval=args.poll_interval,
            poll_timeout=args.poll_timeout,
        )
        captcha_token, _ = apply_capsolver_solution(client, page_origin, solution)
        if not captcha_token:
            eprint("Turnstile solved but no token found in solution.")

    endpoints: List[str]
    if args.endpoints:
        endpoints = [item.strip() for item in args.endpoints.split(",") if item.strip()]
    else:
        extracted = extract_api_candidates(body_text)
        endpoints = extracted or DEFAULT_ENDPOINTS
    api_origin = page_origin
    endpoints = normalize_endpoints(api_origin, rank_endpoints(endpoints))

    captcha_fields = [item.strip() for item in args.captcha_fields.split(",") if item.strip()]
    referer = page_url
    nextauth_origin = extract_redirect_origin(page_url) or page_origin
    if nextauth_origin != page_origin:
        eprint(f"[flow] next-auth origin: {nextauth_origin}")

    eprint(f"[flow] trying {len(endpoints)} endpoints")
    success = attempt_signup_requests(
        client=client,
        base_url=api_origin,
        endpoints=endpoints,
        email=args.email,
        password=args.password,
        name=args.name,
        invite_code=args.invite_code,
        captcha_token=captcha_token,
        captcha_fields=captcha_fields,
        referer=referer,
        dump_dir=args.dump_dir,
    )

    if not success:
        eprint("[flow] fallback to next-auth email attempt")
        success = try_nextauth_email(
            client=client,
            base_url=nextauth_origin,
            email=args.email,
            referer=referer,
            dump_dir=args.dump_dir,
        )

    if success:
        eprint("[flow] completed. Check inbox for verification code.")
        return 0

    eprint("[flow] no success response detected. Check dumps/logs.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
