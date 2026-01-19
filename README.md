# Cursor AI HTTP autoreg helper

This script performs HTTP-only requests against `authenticator.cursor.sh` and tries to reach
the point where a verification code is sent to a test email. It handles Cloudflare challenges
via CapSolver and can solve Turnstile when present.

## Requirements

- Python 3.8+
- CapSolver API key (set in `CAPSOLVER_API_KEY`)

## Quick start

1) Export your CapSolver key:

   `export CAPSOLVER_API_KEY="..."`

2) Run the script:

   `python3 cursor_autoreg.py --email test@example.com`

## Common options

- Override base URL or signup path:

  `--base-url https://authenticator.cursor.sh --signup-path /sign-up`

- Provide a proxy:

  `--proxy http://user:pass@host:port`

- Force CapSolver task type (if auto selection fails):

  `--capsolver-task-type TurnstileTaskProxyless`

- Supply explicit API endpoints to try:

  `--endpoints /api/auth/sign-up,/api/auth/send-code`

- Write response dumps to a directory for debugging:

  `--dump-dir ./dumps`

## Notes

- The script is best-effort and relies on current Cursor endpoints. If endpoints change,
  pass `--endpoints` to target the correct API.
- The CapSolver task parameters may vary across task types. If needed, provide a raw
  task via `--capsolver-task-json` to override defaults.
