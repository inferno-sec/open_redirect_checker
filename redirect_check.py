#!/usr/bin/env python3
"""Check explicitly supplied URLs for open redirects."""

from __future__ import annotations

import argparse
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


DEFAULT_CANARY = "https://redirect-check.invalid/"
USER_AGENT = "redirect-checker/1.0"


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class Result:
    url: str
    parameter: str
    status: str
    detail: str


def validate_http_url(value: str, label: str) -> None:
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        _ = parts.port
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid URL: {exc}") from exc

    if parts.scheme not in {"http", "https"} or not hostname:
        raise ValueError(f"{label} must be an absolute HTTP or HTTPS URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError(f"{label} must not contain embedded credentials")


def redirect_parameters(url: str) -> list[str]:
    return list(dict.fromkeys(key for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)))


def replace_parameter(url: str, parameter: str, value: str) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    changed = [(key, value if key == parameter else old_value) for key, old_value in query]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(changed), parts.fragment))


def points_to_canary(location: str, tested_url: str, canary: str) -> bool:
    try:
        destination = urlsplit(urljoin(tested_url, location))
        expected = urlsplit(canary)
    except ValueError:
        return False
    return (
        destination.scheme in {"http", "https"}
        and destination.hostname is not None
        and destination.hostname.lower() == (expected.hostname or "").lower()
    )


def check_parameter(opener, url: str, parameter: str, canary: str, timeout: float) -> Result:
    tested_url = replace_parameter(url, parameter, canary)
    request = Request(tested_url, headers={"User-Agent": USER_AGENT})

    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as error:
        response = error
    except (URLError, TimeoutError, OSError) as error:
        return Result(url, parameter, "ERROR", str(error))

    try:
        status_code = response.getcode()
        location = response.headers.get("Location")
        if status_code is not None and 300 <= status_code < 400 and location:
            if points_to_canary(location, tested_url, canary):
                return Result(url, parameter, "OPEN", f"HTTP {status_code} -> {location}")
            return Result(url, parameter, "NO", f"HTTP {status_code} -> {location}")
        return Result(url, parameter, "NO", f"HTTP {status_code}")
    finally:
        response.close()


def read_targets(path: Path) -> list[tuple[int, str]]:
    targets = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        value = line.strip()
        if value and not value.startswith("#"):
            validate_http_url(value, f"line {line_number}")
            targets.append((line_number, value))
    return targets


def print_result(result: Result) -> None:
    print(f"{result.status:5}  {result.parameter:16}  {result.detail}  [{result.url}]")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check supplied URLs for redirects to a harmless canary host."
    )
    parser.add_argument("input", type=Path, help="text file with one authorized URL per line")
    parser.add_argument("--canary", default=DEFAULT_CANARY, help=f"redirect destination (default: {DEFAULT_CANARY})")
    parser.add_argument("--timeout", type=float, default=8.0, help="request timeout in seconds (default: 8)")
    parser.add_argument("--delay", type=float, default=1.0, help="delay between requests in seconds (default: 1)")
    parser.add_argument("--max-requests", type=int, default=100, help="maximum requests to send (default: 100)")
    args = parser.parse_args()

    try:
        validate_http_url(args.canary, "canary")
        targets = read_targets(args.input)
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(str(error))

    if args.timeout <= 0 or args.delay < 0 or args.max_requests <= 0:
        parser.error("--timeout and --max-requests must be positive; --delay cannot be negative")

    opener = build_opener(NoRedirectHandler)
    request_count = 0
    open_count = 0
    error_count = 0

    for line_number, url in targets:
        remaining = args.max_requests - request_count
        if remaining <= 0:
            print(f"Stopped at the request limit ({args.max_requests}).")
            break

        parameters = redirect_parameters(url)
        if not parameters:
            print_result(Result(url, "-", "SKIP", "no query parameters to test"))
            continue

        if len(parameters) > remaining:
            print(f"Stopped before line {line_number}: testing it would exceed --max-requests.")
            break

        for parameter in parameters:
            if request_count:
                time.sleep(args.delay)
            result = check_parameter(opener, url, parameter, args.canary, args.timeout)
            request_count += 1
            print_result(result)
            open_count += result.status == "OPEN"
            error_count += result.status == "ERROR"

    print(f"\nChecked {request_count} request(s); possible open redirects: {open_count}.")
    if error_count:
        return 1
    return 2 if open_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
