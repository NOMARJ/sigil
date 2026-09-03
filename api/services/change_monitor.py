"""
Sigil API — Website Change Monitoring Service

Sigil scans upstream artifacts once, but the thing at the other end of a URL can
change afterwards. When the content at a watched URL moves, the artifact users
receive today is not the artifact we vetted — that divergence is a supply-chain
signal, and it should cost us a rescan.

This module is the persistence layer plus the core polling logic:

    * ``normalise_body`` / ``content_hash`` — pure, deterministic content
      fingerprinting over bytes we actually received.
    * ``assert_safe_url`` / ``is_safe_url`` — SSRF guard. These URLs are
      attacker-influenceable (anyone who gets a listing into a registry chooses
      the URL we poll), so the guard is mandatory, not advisory.
    * ``check_source`` — one conditional GET, classified into a real
      ``ChangeEvent``. The network call is injectable so tests never leave the
      process.
    * ``select_due_sources`` / ``record_*`` / ``enqueue_rescan`` — the queue.

Nothing here fabricates a result. A failed fetch is recorded as an ``error``
event with a failure counter and backoff; it is never reported as "unchanged"
and never as a "change". A hash is only ever computed over bytes that were
actually received.

Schema: api/migrations/010_create_change_monitor.sql

Usage:
    # Poll one source without touching the database
    python -m api.services.change_monitor --url https://example.com/listing

    # Show what is due right now
    python -m api.services.change_monitor --due 25
"""

# sigil:ignore-file NET-013 -- this module is the SSRF guard, so it names the
# cloud instance-metadata endpoint (169.254.169.254) in the docstrings that
# explain what it blocks and why redirects are re-validated per hop. Same case
# as cli/src/residue/checks.rs naming the crontab and credential files it
# inspects. The guard is asserted against the real address in
# api/tests/test_change_monitor.py; no code here ever fetches it.

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import socket
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Iterable
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from api.database import db

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MONITORED_SOURCES_TABLE = "monitored_sources"
SOURCE_CHANGE_EVENTS_TABLE = "source_change_events"

#: Values accepted by CK_monitored_sources_source_type.
SOURCE_TYPES: frozenset[str] = frozenset(
    {"mcp_server", "registry_listing", "package_page", "marketplace", "other"}
)

#: Values accepted by CK_source_change_events_kind.
CHANGE_KINDS: frozenset[str] = frozenset(
    {"content", "etag", "first_seen", "gone", "error", "unchanged"}
)

#: Kinds that mean "the artifact we vetted may no longer be what users get".
CHANGE_KINDS_REQUIRING_RESCAN: frozenset[str] = frozenset({"content", "first_seen"})

DEFAULT_CHECK_INTERVAL_MINUTES = 360  # 6h — polite for listing pages
MIN_CHECK_INTERVAL_MINUTES = 5
MAX_BACKOFF_MINUTES = 1440  # 24h ceiling; a dead host is not worth more
BACKOFF_MAX_DOUBLINGS = 6  # 2**6 = 64x the base interval before the ceiling

DEFAULT_BATCH_SIZE = 25
#: Polite global budget for a polling worker. The worker owns the sleeping;
#: this module never sleeps so that tests stay instant.
MAX_REQUESTS_PER_MINUTE = 60
REQUEST_DELAY = 60.0 / MAX_REQUESTS_PER_MINUTE  # 1.0s between polls

REQUEST_TIMEOUT_SECONDS = 20.0
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_REDIRECTS = 2
MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})
#: Ports a public web endpoint plausibly listens on. Blocking everything else
#: keeps a watched URL from being aimed at redis/ssh/smtp on a reachable host.
ALLOWED_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})
#: Suffixes that only ever name internal infrastructure.
BLOCKED_HOST_SUFFIXES: tuple[str, ...] = (
    ".internal",
    ".local",
    ".localhost",
    ".lan",
    ".home",
    ".corp",
    ".intranet",
)
BLOCKED_HOSTNAMES: frozenset[str] = frozenset({"localhost", "ip6-localhost"})

USER_AGENT = "Sigil-ChangeMonitor/1.0 (+https://sigilsec.ai)"

#: Truncation width for the ``notes`` column (NVARCHAR(1000)).
MAX_NOTES_CHARS = 1000
#: Truncation width for the ``etag`` column (NVARCHAR(200)). Response headers
#: are attacker-chosen; an over-long value would make the UPDATE fail with
#: "String or binary data would be truncated" and the row would never advance.
MAX_ETAG_CHARS = 200
#: Truncation width for the ``last_modified`` column (NVARCHAR(100)).
MAX_LAST_MODIFIED_CHARS = 100

# The due-selection SQL, exposed as a constant so it can be asserted on in a
# test with a mocked pool. The Python-side predicate in ``is_due`` remains the
# authority; this query is a pre-filter that must apply the SAME backoff, or a
# population of backed-off rows fills the TOP window and starves the healthy
# sources behind them (a backed-off row has an older ``last_checked_at``, so it
# sorts first). The clamped-doublings expression below is ``backoff_minutes``
# transcribed into T-SQL, and the constants are interpolated from the Python
# constants so the two cannot drift apart.
_BACKOFF_DOUBLINGS_SQL = (
    "CASE"
    " WHEN consecutive_failures < 0 THEN 0"
    f" WHEN consecutive_failures > {BACKOFF_MAX_DOUBLINGS}"
    f" THEN {BACKOFF_MAX_DOUBLINGS}"
    " ELSE consecutive_failures"
    " END"
)
_BACKOFF_MINUTES_SQL = f"check_interval_minutes * POWER(2, {_BACKOFF_DOUBLINGS_SQL})"

DUE_SOURCES_SQL = f"""
    SELECT TOP (?) *
    FROM monitored_sources
    WHERE enabled = 1
      AND (
            last_checked_at IS NULL
            OR DATEADD(
                   minute,
                   CASE
                       WHEN {_BACKOFF_MINUTES_SQL} > {MAX_BACKOFF_MINUTES}
                       THEN {MAX_BACKOFF_MINUTES}
                       ELSE {_BACKOFF_MINUTES_SQL}
                   END,
                   last_checked_at
               ) <= CAST(? AS DATETIMEOFFSET)
          )
    ORDER BY
        CASE WHEN last_checked_at IS NULL THEN 0 ELSE 1 END,
        last_checked_at ASC
"""


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class MonitoredSource:
    """One watched URL. Mirrors a ``monitored_sources`` row."""

    id: str
    url: str
    source_type: str = "other"
    ref_id: str | None = None
    enabled: bool = True
    check_interval_minutes: int = DEFAULT_CHECK_INTERVAL_MINUTES
    last_checked_at: datetime | None = None
    last_changed_at: datetime | None = None
    last_status_code: int | None = None
    content_hash: str | None = None
    etag: str | None = None
    last_modified: str | None = None
    consecutive_failures: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "MonitoredSource":
        """Build a source from a DB row (SQL or in-memory shape)."""
        return cls(
            id=str(row.get("id") or ""),
            url=str(row.get("url") or ""),
            source_type=str(row.get("source_type") or "other"),
            ref_id=row.get("ref_id"),
            enabled=bool(row.get("enabled", True)),
            check_interval_minutes=int(
                row.get("check_interval_minutes") or DEFAULT_CHECK_INTERVAL_MINUTES
            ),
            last_checked_at=parse_timestamp(row.get("last_checked_at")),
            last_changed_at=parse_timestamp(row.get("last_changed_at")),
            last_status_code=_opt_int(row.get("last_status_code")),
            content_hash=row.get("content_hash") or None,
            etag=row.get("etag") or None,
            last_modified=row.get("last_modified") or None,
            consecutive_failures=int(row.get("consecutive_failures") or 0),
            metadata=_load_json_object(row.get("metadata_json")),
            created_at=parse_timestamp(row.get("created_at")),
            updated_at=parse_timestamp(row.get("updated_at")),
        )

    def to_row(self) -> dict[str, Any]:
        """Serialise to a DB row. Timestamps are ISO-8601 strings, matching the
        rest of the API layer (MSSQL parses them into DATETIMEOFFSET)."""
        return {
            "id": self.id,
            "url": self.url,
            "source_type": self.source_type,
            "ref_id": self.ref_id,
            "enabled": self.enabled,
            "check_interval_minutes": self.check_interval_minutes,
            "last_checked_at": _iso(self.last_checked_at),
            "last_changed_at": _iso(self.last_changed_at),
            "last_status_code": self.last_status_code,
            "content_hash": self.content_hash,
            "etag": self.etag,
            "last_modified": self.last_modified,
            "consecutive_failures": self.consecutive_failures,
            "metadata_json": json.dumps(self.metadata) if self.metadata else None,
            "created_at": _iso(self.created_at),
            "updated_at": _iso(self.updated_at),
        }

    def conditional_headers(self) -> dict[str, str]:
        """Validators to replay so the origin can answer 304 instead of a body."""
        headers: dict[str, str] = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if self.etag:
            headers["If-None-Match"] = self.etag
        if self.last_modified:
            headers["If-Modified-Since"] = self.last_modified
        return headers


@dataclass
class ChangeEvent:
    """One classified observation. Mirrors a ``source_change_events`` row.

    An event is produced for *every* poll, including the boring ones — the
    ``unchanged`` kind exists so ``check_source`` never has to return ``None``
    and callers never have to guess. Only events where ``is_change`` is true are
    worth persisting.
    """

    source_id: str
    change_kind: str
    id: str = ""
    detected_at: datetime | None = None
    previous_hash: str | None = None
    new_hash: str | None = None
    http_status: int | None = None
    bytes_before: int | None = None
    bytes_after: int | None = None
    notes: str = ""
    queued_for_rescan: bool = False
    rescan_enqueued_at: datetime | None = None

    @property
    def is_change(self) -> bool:
        """True when the observation is worth writing to the event table."""
        return self.change_kind != "unchanged"

    @property
    def is_failure(self) -> bool:
        """True when this poll did not yield usable content."""
        return self.change_kind in ("error", "gone")

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "ChangeEvent":
        """Build an event from a DB row (SQL or in-memory shape)."""
        return cls(
            id=str(row.get("id") or ""),
            source_id=str(row.get("source_id") or ""),
            change_kind=str(row.get("change_kind") or "error"),
            detected_at=parse_timestamp(row.get("detected_at")),
            previous_hash=row.get("previous_hash") or None,
            new_hash=row.get("new_hash") or None,
            http_status=_opt_int(row.get("http_status")),
            bytes_before=_opt_int(row.get("bytes_before")),
            bytes_after=_opt_int(row.get("bytes_after")),
            notes=str(row.get("notes") or ""),
            queued_for_rescan=bool(row.get("queued_for_rescan", False)),
            rescan_enqueued_at=parse_timestamp(row.get("rescan_enqueued_at")),
        )

    def to_row(self) -> dict[str, Any]:
        """Serialise to a DB row."""
        return {
            "id": self.id,
            "source_id": self.source_id,
            "detected_at": _iso(self.detected_at),
            "previous_hash": self.previous_hash,
            "new_hash": self.new_hash,
            "change_kind": self.change_kind,
            "http_status": self.http_status,
            "bytes_before": self.bytes_before,
            "bytes_after": self.bytes_after,
            "notes": self.notes[:MAX_NOTES_CHARS] or None,
            "queued_for_rescan": self.queued_for_rescan,
            "rescan_enqueued_at": _iso(self.rescan_enqueued_at),
            "created_at": _iso(self.detected_at),
        }


@dataclass
class FetchResult:
    """The outcome of one HTTP attempt, decoupled from httpx so tests can build
    one by hand.

    ``error`` being non-empty means no usable response was obtained — that is a
    failure, never a change. ``status_code`` may still be set alongside an error
    (e.g. a 500 response).
    """

    status_code: int | None = None
    body: bytes = b""
    etag: str | None = None
    last_modified: str | None = None
    content_type: str | None = None
    error: str = ""
    truncated: bool = False


#: A fetcher is called as ``await fetcher(url, headers, timeout)`` and must never
#: raise — it reports problems through ``FetchResult.error``.
Fetcher = Callable[[str, dict[str, str], float], Awaitable[FetchResult]]


class UnsafeURLError(ValueError):
    """Raised when a URL fails the SSRF guard."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def utcnow() -> datetime:
    """Current UTC time. Every time-dependent function takes ``now`` as an
    argument defaulting to this, so tests can pin the clock without sleeping."""
    return datetime.now(timezone.utc)


def new_id() -> str:
    """32-char identifier, matching the NVARCHAR(32) primary keys in the schema."""
    return uuid4().hex


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _opt_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _load_json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def parse_timestamp(value: Any) -> datetime | None:
    """Coerce a DB value to an aware UTC datetime.

    The SQL path returns ``datetime`` (aioodbc registers a DATETIMEOFFSET output
    converter); the in-memory path returns whatever we wrote, which is an ISO
    string. Both have to round-trip, and a naive datetime is assumed UTC because
    that is the only clock this service ever writes.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            logger.warning("Unparseable timestamp value: %s", value)
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    logger.warning("Unexpected timestamp type %s", type(value).__name__)
    return None


# ---------------------------------------------------------------------------
# URL safety (SSRF guard)
# ---------------------------------------------------------------------------
#
# There is no reusable guard in this repo to borrow.
#   * api/services/clawhub_crawler.py::_validated_clawhub_url is a single-host
#     allowlist (hostname == "clawhub.ai" and path prefix /api/v1/); it cannot
#     admit arbitrary watched URLs.
#   * api/services/mcp_crawler.py builds every URL from a constant base, so it
#     has no guard at all.
#   * api/middleware/security.py::URLValidator.is_valid_url does substring
#     matching on the hostname ("10." in hostname), which both over-blocks
#     ("acme10.com") and under-blocks (IPv6, decimal/hex IPv4 literals, and
#     0.0.0.0/8 forms it does not enumerate).
# So the guard below is written here, against ``ipaddress`` rather than string
# prefixes.

_NUMERIC_LABEL = re.compile(r"^(?:0[xX][0-9a-fA-F]+|[0-9]+)$")

# IPv6 prefixes that tunnel an IPv4 address; see _embedded_ipv4.
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
_SIXTOFOUR_PREFIX = ipaddress.ip_network("2002::/16")


def _reject(url: str, reason: str) -> None:
    raise UnsafeURLError(f"{reason}: {url[:200]}")


def _check_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, url: str) -> None:
    """Reject any address that is not globally routable.

    ``is_global`` is False for loopback (127/8, ::1), private (10/8, 172.16/12,
    192.168/16, fc00::/7), link-local (169.254/16 — this is what covers the
    cloud instance metadata endpoint 169.254.169.254), CGNAT, multicast,
    unspecified (0.0.0.0) and the reserved blocks, so one check covers the whole
    non-public space instead of an enumeration that will inevitably miss a form.
    """
    embedded = _embedded_ipv4(ip)
    if embedded is not None:
        # ::ffff:127.0.0.1 must be judged as 127.0.0.1, not as an IPv6 address.
        # The same holds for every other IPv6 form that carries an IPv4 address
        # inside it — see _embedded_ipv4 for why is_global alone is not enough.
        _check_ip(embedded, url)
        return
    if not ip.is_global:
        _reject(url, f"non-public IP address {ip}")


def _embedded_ipv4(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    """Return the IPv4 address embedded in an IPv6 address, if there is one.

    Several IPv6 forms carry a v4 address in their low bits, and a host that
    reaches them reaches the v4 address. ``is_global`` does not see through the
    wrapper — ``ipaddress.IPv6Address("::127.0.0.1").is_global`` is True even
    though it addresses loopback — so each form has to be unwrapped and judged
    on the v4 address it actually targets:

    * ``::ffff:0:0/96``  IPv4-mapped   (``::ffff:127.0.0.1``)
    * ``::/96``          IPv4-compatible, deprecated but still routed by some
      stacks (``::127.0.0.1``) — this is the one that bypassed the guard
    * ``64:ff9b::/96``   NAT64 well-known prefix (``64:ff9b::7f00:1``)
    * ``2002::/16``      6to4, which encodes the v4 address in bits 16-48
    """
    if not isinstance(ip, ipaddress.IPv6Address):
        return None

    mapped = ip.ipv4_mapped
    if mapped is not None:
        return mapped

    value = int(ip)

    # ::/96 — IPv4-compatible. Exclude :: (unspecified) and ::1 (loopback),
    # which are their own addresses rather than wrapped v4 ones and are already
    # caught by is_global.
    if value >> 32 == 0 and value > 1:
        return ipaddress.IPv4Address(value & 0xFFFFFFFF)

    # 64:ff9b::/96 and 64:ff9b:1::/48 — NAT64.
    if ip in _NAT64_PREFIX:
        return ipaddress.IPv4Address(value & 0xFFFFFFFF)

    # 2002::/16 — 6to4 carries the v4 address in the 32 bits after the prefix.
    if ip in _SIXTOFOUR_PREFIX:
        return ipaddress.IPv4Address((value >> 80) & 0xFFFFFFFF)

    return None


def assert_safe_url(url: str) -> str:
    """Validate a URL for outbound fetching, returning it normalised.

    Raises :class:`UnsafeURLError` with the reason on rejection.

    LIMITATION, stated plainly: this is a *syntactic* check. A hostname that
    resolves to a private address still passes here. Use
    :func:`assert_safe_url_resolved` when a resolver is available — that is what
    :func:`default_fetcher` does before every request and after every redirect.
    """
    if not url or not isinstance(url, str):
        _reject(str(url), "empty or non-string URL")
    if len(url) > MAX_URL_LENGTH:
        _reject(url, f"URL longer than {MAX_URL_LENGTH} characters")

    try:
        parsed = urlsplit(url.strip())
    except ValueError:
        # urlsplit itself raises on a malformed bracketed literal such as
        # "http://[not:an:address]/". Letting that escape would surface a
        # caller-supplied URL as an unhandled ValueError (a 500 from the
        # router) instead of a refusal, so it is normalised into the same
        # UnsafeURLError every other rejection uses.
        _reject(url, "malformed URL")
        raise AssertionError("unreachable")  # pragma: no cover
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        _reject(url, f"scheme {parsed.scheme!r} is not http/https")
    if parsed.username or parsed.password:
        # Credentials in a URL are how a fetcher gets tricked into authenticating
        # against an internal service, and they have no place in a public page.
        _reject(url, "URL contains embedded credentials")

    try:
        port = parsed.port
    except ValueError:
        _reject(url, "malformed port")
        raise AssertionError("unreachable")  # pragma: no cover
    if port is not None and port not in ALLOWED_PORTS:
        _reject(url, f"port {port} is not in the allowed set")

    hostname = (parsed.hostname or "").strip().rstrip(".").lower()
    if not hostname:
        _reject(url, "URL has no hostname")
    if hostname in BLOCKED_HOSTNAMES:
        _reject(url, f"blocked hostname {hostname!r}")
    if hostname.endswith(BLOCKED_HOST_SUFFIXES):
        _reject(url, f"internal-only hostname suffix in {hostname!r}")

    if ":" in hostname:
        # urlsplit strips the brackets from "[::1]", so an IPv6 literal reaches
        # here as a bare "::1". It must be judged as an address: the dotted-label
        # logic below would read "::1" as a single label (rejecting every
        # globally routable IPv6 host) and "::127.0.0.1" as four labels (letting
        # a loopback address through). A colon is not legal in a DNS hostname,
        # so anything containing one is a literal or it is malformed.
        try:
            # A zone id ("fe80::1%eth0") is never valid for a remote fetch.
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            _reject(url, f"malformed IPv6 literal {hostname!r}")
            raise AssertionError("unreachable")  # pragma: no cover
        _check_ip(literal, url)
        normalised = urlunsplit(
            (parsed.scheme.lower(), parsed.netloc, parsed.path, parsed.query, "")
        )
        return normalised

    labels = hostname.split(".")
    if all(_NUMERIC_LABEL.match(label) for label in labels):
        # Either a dotted-quad literal or an obfuscated one (decimal 2130706433,
        # octal 0177.0.0.1, hex 0x7f.1). Anything numeric must parse as a real,
        # globally routable IPv4 address or it does not get fetched.
        try:
            candidate = ipaddress.ip_address(hostname)
        except ValueError:
            _reject(url, f"numeric hostname {hostname!r} is not a valid IP literal")
            raise AssertionError("unreachable")  # pragma: no cover
        _check_ip(candidate, url)
    elif len(labels) == 1:
        # A single label ("intranet") is resolved through the host's search
        # domains, which is an internal-network reach by another name.
        _reject(url, f"single-label hostname {hostname!r}")
    else:
        try:
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            literal = None
        if literal is not None:
            _check_ip(literal, url)

    normalised = urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, parsed.path, parsed.query, "")
    )
    return normalised


def is_safe_url(url: str) -> bool:
    """Boolean form of :func:`assert_safe_url`. Never raises."""
    try:
        assert_safe_url(url)
    except UnsafeURLError:
        return False
    except Exception as e:  # defensive: a guard must not take the caller down
        logger.warning("URL safety check errored for %r: %s", url, e)
        return False
    return True


def _default_resolver(hostname: str) -> list[str]:
    """Resolve a hostname to every A/AAAA address, via the stdlib."""
    infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]


async def resolve_safe_url(
    url: str,
    *,
    resolver: Callable[[str], Iterable[str]] | None = None,
) -> tuple[str, list[str]]:
    """:func:`assert_safe_url` plus a DNS check on every resolved address.

    Returns ``(safe_url, validated_addresses)``. The addresses are returned so
    the caller can *connect to one of them* instead of re-resolving the name —
    without that, DNS can change between this lookup and the socket connect
    (rebinding), and the check proves nothing. :func:`default_fetcher` pins the
    connection to ``validated_addresses[0]``; see :func:`_pinned_request_target`.

    For a URL whose host is already an IP literal, the literal is returned as
    the single validated address (``assert_safe_url`` has already checked it).

    ``resolver`` is injectable so tests can exercise the logic without DNS.
    """
    safe = assert_safe_url(url)
    hostname = (urlsplit(safe).hostname or "").strip().rstrip(".").lower()

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return safe, [hostname]  # already validated as a literal

    resolve = resolver or _default_resolver
    try:
        addresses = list(await asyncio.to_thread(resolve, hostname))
    except Exception as e:
        raise UnsafeURLError(f"could not resolve {hostname!r}: {e}") from e

    if not addresses:
        raise UnsafeURLError(f"{hostname!r} resolved to no addresses")
    validated: list[str] = []
    for address in addresses:
        bare = address.split("%", 1)[0]
        try:
            resolved = ipaddress.ip_address(bare)
        except ValueError:
            raise UnsafeURLError(
                f"{hostname!r} resolved to unparseable address {address!r}"
            ) from None
        _check_ip(resolved, safe)
        validated.append(bare)
    return safe, validated


async def assert_safe_url_resolved(
    url: str,
    *,
    resolver: Callable[[str], Iterable[str]] | None = None,
) -> str:
    """:func:`resolve_safe_url`, keeping only the normalised URL."""
    safe, _addresses = await resolve_safe_url(url, resolver=resolver)
    return safe


def _pinned_request_target(
    safe_url: str, address: str
) -> tuple[str, str | None, str | None]:
    """Rewrite ``safe_url`` so the request connects to ``address``.

    Returns ``(request_url, host_header, sni_hostname)``. The URL carries the
    validated IP literal — which is what httpx connects to, so there is no
    second DNS lookup to rebind — while the ``Host`` header and the TLS SNI /
    certificate hostname keep the original name, so the origin still serves the
    right virtual host and certificate verification is unchanged.

    When the host is already an IP literal there is nothing to pin: the URL is
    returned unchanged and both overrides are ``None``.
    """
    parts = urlsplit(safe_url)
    hostname = (parts.hostname or "").strip().rstrip(".")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return safe_url, None, None

    literal = ipaddress.ip_address(address.split("%", 1)[0])
    host_part = f"[{literal}]" if literal.version == 6 else str(literal)
    netloc = f"{host_part}:{parts.port}" if parts.port else host_part
    pinned = urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))
    # assert_safe_url has already rejected embedded credentials, so netloc is
    # exactly host[:port] and is the correct Host header value.
    return pinned, parts.netloc, hostname


# ---------------------------------------------------------------------------
# Content normalisation and hashing (pure)
# ---------------------------------------------------------------------------

_TEXT_HINTS = ("text/", "json", "xml", "javascript", "html", "csv", "yaml")

# Each pattern below removes a value that the ORIGIN regenerates per request and
# that carries no supply-chain meaning. Anything whose change could plausibly
# indicate tampering — script bodies, HTML comments, subresource integrity
# hashes, version numbers, URLs other than their cache-buster suffix — is
# deliberately left alone. Over-normalising hides attacks; that trade is only
# worth making where the value is provably per-request noise.
_VOLATILE_PATTERNS: tuple[tuple[re.Pattern[bytes], bytes], ...] = (
    # CSRF tokens in <meta> — rotated per response by most frameworks.
    (
        re.compile(
            rb"""(?is)(<meta[^>]{0,200}?name=["'](?:csrf-token|csrf_token|_csrf)"""
            rb"""["'][^>]{0,200}?content=["'])[^"']*(["'])"""
        ),
        rb"\1\2",
    ),
    # CSRF tokens in hidden form inputs.
    (
        re.compile(
            rb"""(?is)(<input[^>]{0,200}?name=["'](?:authenticity_token"""
            rb"""|csrfmiddlewaretoken|__RequestVerificationToken)["']"""
            rb"""[^>]{0,200}?value=["'])[^"']*(["'])"""
        ),
        rb"\1\2",
    ),
    # CSP nonces — required to be unique per response by the spec itself.
    (re.compile(rb"""(?i)\snonce=["'][^"']{0,128}["']"""), b' nonce=""'),
    # Cache-buster query suffixes on asset URLs (?v=, ?_=, ?ts=, ?cb=).
    (
        re.compile(rb"(?i)([?&](?:v|_|t|ts|cb|cachebust|build)=)[A-Za-z0-9._-]{1,64}"),
        rb"\1",
    ),
)


def _is_texty(content_type: str | None) -> bool:
    if not content_type:
        # Unknown type: treat as opaque bytes rather than guessing. Hashing raw
        # bytes is always correct, just slightly noisier.
        return False
    lowered = content_type.lower()
    return any(hint in lowered for hint in _TEXT_HINTS)


def _is_json(content_type: str | None) -> bool:
    if not content_type:
        return False
    lowered = content_type.lower()
    return "json" in lowered


def _is_markup(content_type: str | None) -> bool:
    if not content_type:
        return False
    lowered = content_type.lower()
    return "html" in lowered or "xml" in lowered


def normalise_body(raw: bytes, content_type: str | None = None) -> bytes:
    """Strip provably volatile bits so that "changed" means changed.

    Without this, a page that embeds a fresh CSRF token on every request would
    report a content change on every single poll, and the queue would be pure
    noise within a day. The normalisation is deliberately conservative:

    * Binary / unknown content types are returned verbatim — normalising bytes
      we cannot interpret would risk masking a real change.
    * JSON is re-serialised with sorted keys and canonical separators, because
      registry APIs routinely reorder keys and re-indent between responses and
      neither is a supply-chain signal.
    * Text is line-ending normalised, BOM-stripped and trailing-whitespace
      trimmed.
    * HTML/XML additionally has per-request tokens (CSRF, CSP nonce,
      cache-buster query suffixes) blanked — see ``_VOLATILE_PATTERNS``.

    Pure and deterministic: same input, same output, no clock, no I/O.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError("normalise_body expects bytes")
    data = bytes(raw)
    if not data:
        return b""
    if not _is_texty(content_type):
        return data

    if _is_json(content_type):
        canonical = _canonical_json(data)
        if canonical is not None:
            return canonical
        # Not actually JSON despite the header — fall through to text handling.

    data = data.lstrip(b"\xef\xbb\xbf")  # UTF-8 BOM
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

    if _is_markup(content_type):
        for pattern, replacement in _VOLATILE_PATTERNS:
            data = pattern.sub(replacement, data)

    lines = [line.rstrip(b" \t") for line in data.split(b"\n")]
    return b"\n".join(lines).strip(b"\n")


def _canonical_json(data: bytes) -> bytes | None:
    """Re-serialise JSON canonically, or None if it is not valid JSON."""
    try:
        parsed = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError):
        return None
    try:
        return json.dumps(
            parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except (TypeError, ValueError):  # pragma: no cover - json.loads output is safe
        return None


def sha256_hex(data: bytes) -> str:
    """sha256 hex digest of bytes exactly as given (no normalisation)."""
    return hashlib.sha256(data).hexdigest()


def content_hash(raw: bytes, content_type: str | None = None) -> str:
    """sha256 hex of the normalised body — the fingerprint stored on a source.

    This is a real digest of bytes we actually received. There is no code path
    in this module that produces a hash from anything else.
    """
    return sha256_hex(normalise_body(raw, content_type))


# ---------------------------------------------------------------------------
# Scheduling (pure)
# ---------------------------------------------------------------------------


def backoff_minutes(check_interval_minutes: int, consecutive_failures: int) -> int:
    """Effective poll interval for a source, given its failure streak.

    Exponential: base interval doubled once per consecutive failure, capped at
    ``BACKOFF_MAX_DOUBLINGS`` doublings and hard-limited to ``MAX_BACKOFF_MINUTES``.

    The point is not politeness alone — a source that has failed twenty times is
    almost certainly gone or blocking us, and hammering it produces no signal
    while consuming the batch budget that live sources need.

    Zero failures returns the base interval unchanged.
    """
    base = max(int(check_interval_minutes or DEFAULT_CHECK_INTERVAL_MINUTES), 1)
    failures = max(int(consecutive_failures or 0), 0)
    doublings = min(failures, BACKOFF_MAX_DOUBLINGS)
    return min(base * (2**doublings), MAX_BACKOFF_MINUTES)


def next_check_due_at(
    source: MonitoredSource, *, now: datetime | None = None
) -> datetime:
    """When this source next becomes eligible for a poll.

    A source that has never been checked is due immediately, which is why this
    returns ``now`` rather than an epoch — callers compare, they do not sort.
    """
    reference = now or utcnow()
    if source.last_checked_at is None:
        return reference
    interval = backoff_minutes(
        source.check_interval_minutes, source.consecutive_failures
    )
    return source.last_checked_at + timedelta(minutes=interval)


def is_due(source: MonitoredSource, *, now: datetime | None = None) -> bool:
    """True when a source is enabled and its (backed-off) interval has elapsed."""
    if not source.enabled:
        return False
    reference = now or utcnow()
    return next_check_due_at(source, now=reference) <= reference


def should_enqueue_rescan(event: ChangeEvent) -> bool:
    """True when an event means the artifact needs to be looked at again.

    ``content`` and ``first_seen`` qualify. ``etag`` does not — the validators
    moved but the normalised content did not, so there is nothing new to scan.
    ``gone`` does not, because there is no longer anything to fetch. ``error``
    does not, because a failed fetch is not evidence of anything.
    """
    return event.change_kind in CHANGE_KINDS_REQUIRING_RESCAN


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------


def _declared_length_exceeds_cap(content_length: str | None) -> bool:
    """True when a declared ``Content-Length`` is already over the cap.

    A declared length is a claim, not a measurement, so it is only used to
    refuse early — a body that under-declares itself is still counted as it
    arrives by :func:`_read_capped_body`.
    """
    if not content_length:
        return False
    try:
        return int(content_length.strip()) > MAX_RESPONSE_BYTES
    except (TypeError, ValueError):
        return False


async def _read_capped_body(resp: Any) -> tuple[bytes, bool]:
    """Accumulate a streamed body, aborting the transfer once it passes the cap.

    Iterates the *undecoded* stream (``aiter_raw``) deliberately: httpx's own
    decoder inflates a whole network chunk before handing it back, so counting
    decoded bytes still lets one chunk of a compression bomb land in memory
    first. Decoding is done afterwards, bounded, by :func:`_decode_body`.

    Returns ``(raw_body, truncated)``. Nothing over ``MAX_RESPONSE_BYTES`` is
    ever held: the accumulator stops on the chunk that crosses the line and the
    partial body is dropped, because a prefix is not the document.
    """
    chunks: list[bytes] = []
    total = 0
    async for chunk in resp.aiter_raw():
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            return b"", True
        chunks.append(chunk)
    return b"".join(chunks), False


def _decode_body(raw: bytes, content_encoding: str | None) -> tuple[bytes, bool, str]:
    """Apply the response's content coding with a hard output bound.

    Returns ``(body, truncated, error)``. The request asks for ``identity``, so
    an encoded body is already the origin ignoring us; it is still decoded when
    the coding is one the stdlib handles, but never past
    ``MAX_RESPONSE_BYTES`` — that bound is the whole point, since a few hundred
    kilobytes of gzip expands to gigabytes.
    """
    coding = (content_encoding or "").strip().lower()
    if coding in ("", "identity"):
        return raw, False, ""
    if coding in ("gzip", "x-gzip"):
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif coding == "deflate":
        decompressor = zlib.decompressobj()
    else:
        return b"", False, f"unsupported content-encoding {coding!r}"

    try:
        decoded = decompressor.decompress(raw, MAX_RESPONSE_BYTES + 1)
    except zlib.error as e:
        return b"", False, f"malformed {coding} body: {e}"
    if len(decoded) > MAX_RESPONSE_BYTES or decompressor.unconsumed_tail:
        return b"", True, ""
    return decoded, False, ""


async def default_fetcher(
    url: str,
    headers: dict[str, str],
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> FetchResult:
    """Fetch a URL with httpx, safely. Never raises.

    Redirects are followed manually (httpx's ``follow_redirects`` stays off) so
    that every hop is re-validated by the SSRF guard — an origin that 302s to
    169.254.169.254 must not be silently followed. At most ``MAX_REDIRECTS``
    hops.

    Two things this deliberately does not trust the origin about:

    * **Where it is.** The connection is pinned to an address that
      :func:`resolve_safe_url` validated on this hop, with the ``Host`` header
      and TLS SNI still carrying the original name. Handing httpx the hostname
      would let it perform its own lookup at connect time, and a TTL-0 record
      that answers a public address to the guard and a private one to httpx
      milliseconds later would walk straight through the check.
    * **How big it is.** The body is streamed and the transfer is abandoned as
      soon as ``MAX_RESPONSE_BYTES`` is passed, rather than measured after httpx
      has buffered whatever the origin chose to send. A ``Content-Length`` that
      already exceeds the cap is refused before any body is read;
      ``Accept-Encoding: identity`` is requested; and the bytes are counted
      *undecoded* as they arrive and decoded afterwards with a bounded
      decompressor, so an origin that compresses anyway cannot inflate past the
      cap even for a single chunk.
    """
    import httpx

    current = url
    for hop in range(MAX_REDIRECTS + 1):
        try:
            safe_url, addresses = await resolve_safe_url(current)
        except UnsafeURLError as e:
            logger.warning("Refusing to fetch unsafe URL: %s", e)
            return FetchResult(error=f"unsafe_url: {e}")

        request_url, host_header, sni_hostname = _pinned_request_target(
            safe_url, addresses[0]
        )
        request_headers = dict(headers)
        request_headers["Accept-Encoding"] = "identity"
        if host_header:
            request_headers["Host"] = host_header
        extensions = {"sni_hostname": sni_hostname} if sni_hostname else {}

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                async with client.stream(
                    "GET",
                    request_url,
                    headers=request_headers,
                    extensions=extensions,
                ) as resp:
                    status_code = resp.status_code

                    if status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location", "")
                        if not location:
                            return FetchResult(
                                status_code=status_code,
                                error="redirect without location",
                            )
                        if hop >= MAX_REDIRECTS:
                            return FetchResult(
                                status_code=status_code,
                                error=f"too many redirects (>{MAX_REDIRECTS})",
                            )
                        current = httpx.URL(safe_url).join(location).human_repr()
                        continue

                    if _declared_length_exceeds_cap(resp.headers.get("content-length")):
                        logger.warning(
                            "Response from %s declares more than %d bytes",
                            safe_url,
                            MAX_RESPONSE_BYTES,
                        )
                        return FetchResult(
                            status_code=status_code,
                            error=f"response exceeded {MAX_RESPONSE_BYTES} bytes",
                            truncated=True,
                        )

                    raw_body, truncated = await _read_capped_body(resp)
                    content_encoding = resp.headers.get("content-encoding")
                    etag = resp.headers.get("etag")
                    last_modified = resp.headers.get("last-modified")
                    content_type = resp.headers.get("content-type")
        except Exception as e:
            logger.warning("Fetch failed for %s: %s", safe_url, e)
            return FetchResult(error=f"{type(e).__name__}: {e}")

        body = b""
        decode_error = ""
        if not truncated:
            body, truncated, decode_error = _decode_body(raw_body, content_encoding)

        if truncated:
            # Truncation makes the hash meaningless as a whole-document
            # fingerprint, so this is reported as an error rather than silently
            # hashing a prefix and calling it "the content".
            logger.warning(
                "Response from %s exceeded %d bytes", safe_url, MAX_RESPONSE_BYTES
            )
            return FetchResult(
                status_code=status_code,
                error=f"response exceeded {MAX_RESPONSE_BYTES} bytes",
                truncated=True,
            )
        if decode_error:
            logger.warning("Undecodable response from %s: %s", safe_url, decode_error)
            return FetchResult(status_code=status_code, error=decode_error)

        return FetchResult(
            status_code=status_code,
            body=body,
            etag=etag,
            last_modified=last_modified,
            content_type=content_type,
        )

    return FetchResult(error="redirect loop")  # pragma: no cover - loop always returns


# ---------------------------------------------------------------------------
# Core check
# ---------------------------------------------------------------------------


async def observe_source(
    source: MonitoredSource,
    *,
    fetcher: Fetcher | None = None,
    now: datetime | None = None,
) -> tuple[ChangeEvent, FetchResult | None]:
    """Poll one source once and classify the outcome. Performs no writes.

    Returns the classified event **and** the raw :class:`FetchResult`, because
    the caller needs the response validators (ETag / Last-Modified) to store on
    the source — those live on the HTTP response, not on the event row. Callers
    that only want the classification should use :func:`check_source`.

    Cheapest-first, as the docstring of this module promises:

    1. Replay the stored ETag / Last-Modified as ``If-None-Match`` /
       ``If-Modified-Since``. A **304 short-circuits everything** — the origin
       has asserted the representation is unchanged, so there is no body to
       download, no bytes to normalise and no hash to compute. This is the whole
       reason the validators are stored.
    2. Otherwise hash the normalised body and compare it to the stored hash.

    Outcomes:

    ==============  ========================================================
    ``unchanged``   304, or a 2xx whose normalised hash and validators match
    ``first_seen``  2xx and we had no previous hash
    ``content``     2xx and the normalised hash differs — the real signal
    ``etag``        2xx, hash identical, but ETag/Last-Modified moved
    ``gone``        404 or 410 — the artifact is no longer published
    ``error``       transport failure, unsafe URL, oversize body, other non-2xx
    ==============  ========================================================

    ``fetcher`` is injectable and defaults to :func:`default_fetcher`; tests
    pass their own and never touch the network.
    """
    detected_at = now or utcnow()
    fetch = fetcher or default_fetcher

    def _event(kind: str, **kwargs: Any) -> ChangeEvent:
        return ChangeEvent(
            source_id=source.id,
            change_kind=kind,
            detected_at=detected_at,
            previous_hash=source.content_hash,
            **kwargs,
        )

    try:
        assert_safe_url(source.url)
    except UnsafeURLError as e:
        logger.warning("Source %s has an unsafe URL: %s", source.id, e)
        return _event("error", notes=f"unsafe_url: {e}"), None

    try:
        result = await fetch(
            source.url, source.conditional_headers(), REQUEST_TIMEOUT_SECONDS
        )
    except Exception as e:
        # A fetcher is contracted not to raise, but an injected one might.
        logger.exception("Fetcher raised for source %s: %s", source.id, e)
        return _event("error", notes=f"fetcher_raised: {type(e).__name__}: {e}"), None

    if result.error:
        event = _event("error", http_status=result.status_code, notes=result.error)
        return event, result

    status = result.status_code

    if status == 304:
        # Short-circuit: no body was transferred, so there is nothing to hash.
        # Reusing the stored hash here would be inventing an observation we did
        # not make, so new_hash stays None and the source keeps what it had.
        event = _event("unchanged", http_status=status, notes="304 not modified")
        return event, result

    if status in (404, 410):
        return _event("gone", http_status=status, notes=f"HTTP {status}"), result

    if status is None or not (200 <= status < 300):
        return _event("error", http_status=status, notes=f"HTTP {status}"), result

    normalised = normalise_body(result.body, result.content_type)
    new_hash = sha256_hex(normalised)
    bytes_after = len(normalised)

    if not source.content_hash:
        event = _event(
            "first_seen",
            http_status=status,
            new_hash=new_hash,
            bytes_after=bytes_after,
            notes="no previous content hash recorded",
        )
        return event, result

    if new_hash != source.content_hash:
        event = _event(
            "content",
            http_status=status,
            new_hash=new_hash,
            bytes_after=bytes_after,
            notes="normalised content hash changed",
        )
        return event, result

    validators_moved = bool(
        (source.etag and result.etag and result.etag != source.etag)
        or (
            source.last_modified
            and result.last_modified
            and result.last_modified != source.last_modified
        )
    )
    if validators_moved:
        # The origin re-issued the resource but the content we care about is
        # byte-identical after normalisation. Worth recording, not worth a
        # rescan -- see should_enqueue_rescan.
        event = _event(
            "etag",
            http_status=status,
            new_hash=new_hash,
            bytes_after=bytes_after,
            notes="validators changed but normalised content is identical",
        )
        return event, result

    event = _event(
        "unchanged",
        http_status=status,
        new_hash=new_hash,
        bytes_after=bytes_after,
        notes="normalised content hash unchanged",
    )
    return event, result


async def check_source(
    source: MonitoredSource,
    *,
    fetcher: Fetcher | None = None,
    now: datetime | None = None,
) -> ChangeEvent:
    """Poll one source once and return only the classified event.

    Thin wrapper over :func:`observe_source` for callers that do not need the
    HTTP response. Performs no writes and never raises.
    """
    event, _result = await observe_source(source, fetcher=fetcher, now=now)
    return event


def apply_event(
    source: MonitoredSource,
    event: ChangeEvent,
    result: FetchResult | None = None,
    *,
    now: datetime | None = None,
) -> MonitoredSource:
    """Return the source with the outcome of ``event`` folded in. Pure.

    Split out from :func:`record_check_result` so the state transition can be
    unit-tested without a database. Mutates and returns the given instance.
    """
    checked_at = now or event.detected_at or utcnow()
    source.last_checked_at = checked_at
    source.last_status_code = event.http_status
    source.updated_at = checked_at

    if event.is_failure:
        source.consecutive_failures += 1
        return source

    source.consecutive_failures = 0

    if event.new_hash:
        source.content_hash = event.new_hash
    if result is not None:
        # Only advance validators when we actually received them; a 304 carries
        # no fresh ETag and must not clear the one that produced it. Both are
        # clipped to their column widths — they come straight off an untrusted
        # response, and an over-long one would fail the UPDATE outright.
        if result.etag:
            source.etag = result.etag[:MAX_ETAG_CHARS]
        if result.last_modified:
            source.last_modified = result.last_modified[:MAX_LAST_MODIFIED_CHARS]

    if event.change_kind in CHANGE_KINDS_REQUIRING_RESCAN:
        source.last_changed_at = checked_at

    return source


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
#
# Only methods that exist on api.database.db are used: select, select_one,
# insert, update, delete and execute_raw_sql. Note db.update's signature is
# update(table, filters, data) — filters BEFORE data.


async def get_source(source_id: str) -> MonitoredSource | None:
    """Load one source by primary key."""
    row = await db.select_one(MONITORED_SOURCES_TABLE, {"id": source_id})
    return MonitoredSource.from_row(row) if row else None


async def get_source_by_url(url: str) -> MonitoredSource | None:
    """Load one source by its (unique) URL."""
    row = await db.select_one(MONITORED_SOURCES_TABLE, {"url": url})
    return MonitoredSource.from_row(row) if row else None


async def register_source(
    url: str,
    source_type: str = "other",
    *,
    ref_id: str | None = None,
    check_interval_minutes: int = DEFAULT_CHECK_INTERVAL_MINUTES,
    enabled: bool = True,
    metadata: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> MonitoredSource:
    """Create (or return the existing) monitored source for ``url``.

    Rejects unsafe URLs at the door so an unfetchable row never enters the
    table. Raises :class:`UnsafeURLError` or ``ValueError`` on bad input.
    """
    safe_url = assert_safe_url(url)
    if source_type not in SOURCE_TYPES:
        raise ValueError(
            f"unknown source_type {source_type!r}; expected {SOURCE_TYPES}"
        )
    interval = max(int(check_interval_minutes), MIN_CHECK_INTERVAL_MINUTES)

    existing = await get_source_by_url(safe_url)
    if existing is not None:
        return existing

    created_at = now or utcnow()
    source = MonitoredSource(
        id=new_id(),
        url=safe_url,
        source_type=source_type,
        ref_id=ref_id,
        enabled=enabled,
        check_interval_minutes=interval,
        metadata=metadata or {},
        created_at=created_at,
        updated_at=created_at,
    )
    await db.insert(MONITORED_SOURCES_TABLE, source.to_row())
    logger.info(
        "Registered monitored source %s (%s) every %dm", safe_url, source_type, interval
    )
    return source


async def select_due_sources(
    limit: int = DEFAULT_BATCH_SIZE, *, now: datetime | None = None
) -> list[MonitoredSource]:
    """Sources eligible for a poll right now, stalest first.

    Two paths, because the in-memory fallback in ``api/database.py`` supports
    only equality filters and turns raw SQL into a no-op:

    * With a pool: ``DUE_SOURCES_SQL`` pre-filters on the index
      (``idx_monitored_sources_due``) applying the same backoff as
      :func:`backoff_minutes`, then :func:`is_due` refines the result in Python.
      The SQL is an over-fetch, never the authority — but it must not admit rows
      that ``is_due`` will reject, or a crowd of backed-off sources fills the
      ``TOP`` window and starves the healthy sources behind them.
    * Without a pool (tests, local dev): every enabled row is loaded and
      filtered with the same :func:`is_due`. No row limit is pushed down here
      either, for exactly the same reason.

    The Python predicate is identical on both paths, so behaviour does not
    diverge; only the amount of work pushed into the database does.
    """
    reference = now or utcnow()
    limit = max(int(limit), 1)
    # The SQL predicate now matches is_due, but it still ignores the ordering
    # refinement below, so over-fetch a little.
    fetch_limit = min(limit * 4, 1000)

    rows: list[dict[str, Any]] = []
    if db.connected:
        try:
            rows = await db.execute_raw_sql(
                DUE_SOURCES_SQL, (fetch_limit, reference.isoformat())
            )
        except Exception as e:
            logger.exception("Due-source query failed: %s", e)
            return []
    else:
        try:
            rows = await db.select(MONITORED_SOURCES_TABLE, {"enabled": True})
        except Exception as e:
            logger.exception("Due-source select failed: %s", e)
            return []

    sources = [MonitoredSource.from_row(row) for row in rows]
    due = [s for s in sources if is_due(s, now=reference)]
    # Stalest first; never-checked sources sort ahead of everything.
    due.sort(
        key=lambda s: (s.last_checked_at is not None, s.last_checked_at or reference)
    )
    return due[:limit]


async def record_check_result(
    source: MonitoredSource,
    event: ChangeEvent,
    result: FetchResult | None = None,
    *,
    now: datetime | None = None,
) -> MonitoredSource:
    """Persist the post-poll state of a source (hash, validators, counters).

    Always called, for every outcome including ``unchanged`` — otherwise
    ``last_checked_at`` never advances and the source is due forever.

    A write failure propagates. Swallowing it would return an in-memory object
    describing state that is not in the database, and every caller above here
    reports that object as fact — the API would answer 200 with a
    ``last_checked_at`` and ``content_hash`` that were never stored.
    """
    updated = apply_event(source, event, result, now=now)
    payload = {
        "last_checked_at": _iso(updated.last_checked_at),
        "last_changed_at": _iso(updated.last_changed_at),
        "last_status_code": updated.last_status_code,
        "content_hash": updated.content_hash,
        "etag": updated.etag,
        "last_modified": updated.last_modified,
        "consecutive_failures": updated.consecutive_failures,
        "updated_at": _iso(updated.updated_at),
    }
    try:
        await db.update(MONITORED_SOURCES_TABLE, {"id": updated.id}, payload)
    except Exception as e:
        logger.exception(
            "Failed to record check result for source %s: %s", updated.id, e
        )
        raise
    return updated


async def latest_event(source_id: str) -> ChangeEvent | None:
    """Most recent recorded event for a source, or None."""
    try:
        rows = await db.select(
            SOURCE_CHANGE_EVENTS_TABLE,
            {"source_id": source_id},
            limit=1,
            order_by="detected_at",
            order_desc=True,
        )
    except Exception as e:
        logger.exception("Failed to load latest event for source %s: %s", source_id, e)
        return None
    return ChangeEvent.from_row(rows[0]) if rows else None


async def record_change_event(
    event: ChangeEvent,
    *,
    queued_for_rescan: bool | None = None,
    now: datetime | None = None,
) -> ChangeEvent:
    """Write a change event and return it with its assigned id.

    ``bytes_before`` is backfilled from the previous event's ``bytes_after``
    when the caller did not supply it — a measured value from a real prior
    observation, or left NULL if we have none. It is never estimated.

    ``queued_for_rescan`` defaults to :func:`should_enqueue_rescan`.

    A failed insert propagates rather than being logged and hidden: the
    returned event already carries ``queued_for_rescan``, and callers report
    that flag as "an event row was written and a rescan is queued". Reporting
    that over a write that did not land is a fabricated result, and the change
    would be silently dropped from the queue.
    """
    event.id = event.id or new_id()
    event.detected_at = event.detected_at or now or utcnow()
    if queued_for_rescan is None:
        queued_for_rescan = should_enqueue_rescan(event)
    event.queued_for_rescan = bool(queued_for_rescan)

    if event.bytes_before is None:
        previous = await latest_event(event.source_id)
        if previous is not None:
            event.bytes_before = previous.bytes_after

    try:
        await db.insert(SOURCE_CHANGE_EVENTS_TABLE, event.to_row())
    except Exception as e:
        logger.exception(
            "Failed to record change event for source %s: %s", event.source_id, e
        )
        raise
    return event


async def pending_rescan_events(limit: int = DEFAULT_BATCH_SIZE) -> list[ChangeEvent]:
    """Events waiting to be turned into a rescan, oldest first.

    This is the queue a worker drains. It is deliberately a queue of events
    rather than a call into ``api.services.rescan_queue``: RescanQueue selects
    ``public_scans`` rows by (ecosystem, package_name, package_version) and a
    watched URL does not always map to one of those. Rather than invent a
    parallel scanning path or fake a package identity, this module records what
    it actually knows — this source changed — and leaves resolution to the
    worker that owns scanning.
    """
    try:
        rows = await db.select(
            SOURCE_CHANGE_EVENTS_TABLE,
            {"queued_for_rescan": True},
            limit=max(int(limit), 1),
            order_by="detected_at",
        )
    except Exception as e:
        logger.exception("Failed to load pending rescan events: %s", e)
        return []
    return [ChangeEvent.from_row(row) for row in rows]


async def enqueue_rescan(event: ChangeEvent) -> bool:
    """Mark an already-recorded event as queued for rescan.

    Returns True when the row was updated. Requires ``event.id``, i.e. the event
    must have been through :func:`record_change_event` first.
    """
    if not event.id:
        logger.warning("Cannot enqueue rescan for an unsaved event")
        return False
    event.queued_for_rescan = True
    event.rescan_enqueued_at = None
    updated = await _update_event(
        event.id, {"queued_for_rescan": True, "rescan_enqueued_at": None}
    )
    if updated:
        logger.info(
            "Queued rescan for source %s (%s)", event.source_id, event.change_kind
        )
    return updated


async def mark_rescan_enqueued(event_id: str, *, now: datetime | None = None) -> bool:
    """Remove an event from the queue after a worker has handed it to a scanner.

    ``queued_for_rescan`` flips back to 0 (so the filtered index
    ``idx_source_change_events_pending_rescan`` only ever holds the outstanding
    backlog) and ``rescan_enqueued_at`` records when that happened.
    """
    stamped = now or utcnow()
    return await _update_event(
        event_id,
        {"queued_for_rescan": False, "rescan_enqueued_at": _iso(stamped)},
    )


async def _update_event(event_id: str, payload: dict[str, Any]) -> bool:
    try:
        row = await db.update(SOURCE_CHANGE_EVENTS_TABLE, {"id": event_id}, payload)
    except Exception as e:
        logger.exception("Failed to update change event %s: %s", event_id, e)
        return False
    return row is not None


async def source_events(source_id: str, limit: int = 50) -> list[ChangeEvent]:
    """Recent events for one source, newest first."""
    try:
        rows = await db.select(
            SOURCE_CHANGE_EVENTS_TABLE,
            {"source_id": source_id},
            limit=max(int(limit), 1),
            order_by="detected_at",
            order_desc=True,
        )
    except Exception as e:
        logger.exception("Failed to load events for source %s: %s", source_id, e)
        return []
    return [ChangeEvent.from_row(row) for row in rows]


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


async def process_source(
    source: MonitoredSource,
    *,
    fetcher: Fetcher | None = None,
    now: datetime | None = None,
) -> ChangeEvent:
    """Poll one source and persist everything that follows from the outcome.

    Check -> update the source row -> record the event if it is a change ->
    queue a rescan if the change warrants one. This is the single call a worker
    needs per source; it does no sleeping and no batching of its own.

    Observation itself never raises — a transport failure comes back as an
    ``error`` event. A *persistence* failure does raise, because the returned
    event is what callers report to operators; returning it after a failed
    write would claim an event row and a queue entry that do not exist. The
    worker counts that as a crashed source and the API answers 500.
    """
    event, result = await observe_source(source, fetcher=fetcher, now=now)
    await record_check_result(source, event, result, now=now)

    if not event.is_change:
        return event

    await record_change_event(event, now=now)
    if should_enqueue_rescan(event) and not event.queued_for_rescan:
        await enqueue_rescan(event)
    return event


async def get_queue_status(now: datetime | None = None) -> dict[str, Any]:
    """Counts for observability. Every number here is a real row count.

    Uses ``db.select`` (not aggregate SQL) so it returns true values in the
    in-memory fallback as well as against Azure SQL.
    """
    reference = now or utcnow()
    try:
        source_rows = await db.select(MONITORED_SOURCES_TABLE)
        pending = await db.select(
            SOURCE_CHANGE_EVENTS_TABLE, {"queued_for_rescan": True}
        )
    except Exception as e:
        logger.exception("Failed to compute change-monitor queue status: %s", e)
        return {"error": str(e)}

    sources = [MonitoredSource.from_row(row) for row in source_rows]
    enabled = [s for s in sources if s.enabled]
    return {
        "total_sources": len(sources),
        "enabled_sources": len(enabled),
        "due_now": sum(1 for s in enabled if is_due(s, now=reference)),
        "failing_sources": sum(1 for s in enabled if s.consecutive_failures > 0),
        "pending_rescans": len(pending),
        "as_of": reference.isoformat(),
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


async def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Sigil website change monitor (inspection helper)"
    )
    parser.add_argument("--url", help="Fetch one URL and print its content hash")
    parser.add_argument(
        "--due", type=int, metavar="N", help="Show up to N sources due for a poll"
    )
    parser.add_argument(
        "--status", action="store_true", help="Print queue status counters"
    )
    args = parser.parse_args()

    if args.url:
        safe = assert_safe_url(args.url)
        result = await default_fetcher(safe, {"User-Agent": USER_AGENT})
        if result.error:
            print(f"error: {result.error}")
            return
        normalised = normalise_body(result.body, result.content_type)
        print(f"status:       {result.status_code}")
        print(f"content-type: {result.content_type}")
        print(f"raw bytes:    {len(result.body)}")
        print(f"norm bytes:   {len(normalised)}")
        print(f"sha256:       {sha256_hex(normalised)}")
        return

    if args.due:
        for source in await select_due_sources(args.due):
            print(f"{source.id}  {source.url}  failures={source.consecutive_failures}")
        return

    if args.status:
        print(json.dumps(await get_queue_status(), indent=2))
        return

    parser.print_help()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    asyncio.run(main())
