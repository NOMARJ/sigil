"""
Sigil API — Website Change Monitor Tests

Covers ``api/services/change_monitor.py`` and the create endpoint of
``api/routers/monitor.py``.

Every HTTP response in this file is a hand-built ``FetchResult`` handed to the
service through its injectable ``fetcher`` parameter — no socket is opened, no
database is required (``conftest._force_in_memory_db`` pins the db layer to its
in-memory store), and no test sleeps: the clock is injected as ``now``.

All request/response bodies here are marked ``# synthetic test fixture``. They
are inputs to the code under test, never measurements of anything, and no
assertion in this file asserts a value that was produced by the thing it is
checking.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.services import change_monitor as cm
from api.services.change_monitor import FetchResult, MonitoredSource, UnsafeURLError

# A pinned clock. Nothing in this suite reads the wall clock.
BASE = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)


class RecordingFetcher:
    """Stand-in for ``change_monitor.default_fetcher``.

    Returns pre-built ``FetchResult`` objects in order (repeating the last one
    once the queue is down to a single entry) and records the arguments it was
    called with, so the conditional-request headers can be asserted.
    """

    def __init__(self, *results: FetchResult) -> None:
        if not results:
            raise ValueError("RecordingFetcher needs at least one result")
        self.results = list(results)
        self.calls: list[tuple[str, dict[str, str], float]] = []

    async def __call__(
        self, url: str, headers: dict[str, str], timeout: float
    ) -> FetchResult:
        self.calls.append((url, dict(headers), timeout))
        if len(self.results) > 1:
            return self.results.pop(0)
        return self.results[0]


def make_source(**overrides) -> MonitoredSource:
    """Build an in-memory MonitoredSource. # synthetic test fixture"""
    values = {
        "id": cm.new_id(),
        "url": "https://registry.example.com/packages/left-pad",
        "source_type": "package_page",
        "check_interval_minutes": 60,
        "created_at": BASE,
        "updated_at": BASE,
    }
    values.update(overrides)
    return MonitoredSource(**values)


# ---------------------------------------------------------------------------
# 1. Hashing and normalisation are deterministic and real
# ---------------------------------------------------------------------------


def test_content_hash_is_a_real_sha256_of_the_normalised_body():
    body = b"<html><body>left-pad 1.3.0</body></html>"  # synthetic test fixture
    normalised = cm.normalise_body(body, "text/html")
    expected = hashlib.sha256(normalised).hexdigest()

    digest = cm.content_hash(body, "text/html")

    assert digest == expected
    assert len(digest) == 64
    assert int(digest, 16) >= 0  # hex only


def test_content_hash_is_deterministic_across_calls():
    body = b'{"name":"left-pad","version":"1.3.0"}'  # synthetic test fixture
    first = cm.content_hash(body, "application/json")
    second = cm.content_hash(body, "application/json")
    third = cm.content_hash(bytes(body), "application/json")

    assert first == second == third


def test_identical_bodies_hash_equal_and_one_changed_byte_does_not():
    original = b"digest: sha256-AAAA"  # synthetic test fixture
    copy = b"digest: sha256-AAAA"  # synthetic test fixture
    tampered = b"digest: sha256-BAAA"  # synthetic test fixture

    assert cm.content_hash(original, "text/plain") == cm.content_hash(
        copy, "text/plain"
    )
    assert cm.content_hash(original, "text/plain") != cm.content_hash(
        tampered, "text/plain"
    )


def test_normalise_body_is_pure_and_leaves_its_input_alone():
    body = bytearray(b"one\r\ntwo   \r\n")  # synthetic test fixture
    snapshot = bytes(body)

    out_a = cm.normalise_body(bytes(body), "text/plain")
    out_b = cm.normalise_body(bytes(body), "text/plain")

    assert out_a == out_b == b"one\ntwo"
    assert bytes(body) == snapshot


def test_json_key_order_and_indentation_are_not_a_change():
    a = b'{"b": 2, "a": 1}'  # synthetic test fixture
    b = b'{\n  "a": 1,\n  "b": 2\n}'  # synthetic test fixture

    assert cm.content_hash(a, "application/json") == cm.content_hash(
        b, "application/json"
    )
    # ...but a different value still is a change.
    c = b'{"a": 1, "b": 3}'  # synthetic test fixture
    assert cm.content_hash(a, "application/json") != cm.content_hash(
        c, "application/json"
    )


def test_csrf_token_and_nonce_churn_is_normalised_but_script_edits_are_not():
    page_a = (  # synthetic test fixture
        b'<html><head><meta name="csrf-token" content="AAAAAAAA">'
        b'<script nonce="r1">install()</script></head></html>'
    )
    page_b = (  # synthetic test fixture
        b'<html><head><meta name="csrf-token" content="ZZZZZZZZ">'
        b'<script nonce="r2">install()</script></head></html>'
    )
    page_tampered = (  # synthetic test fixture
        b'<html><head><meta name="csrf-token" content="AAAAAAAA">'
        b'<script nonce="r1">install();exfil()</script></head></html>'
    )

    assert cm.content_hash(page_a, "text/html") == cm.content_hash(page_b, "text/html")
    assert cm.content_hash(page_a, "text/html") != cm.content_hash(
        page_tampered, "text/html"
    )


def test_binary_bodies_are_hashed_verbatim():
    blob = bytes(range(256))  # synthetic test fixture
    assert cm.normalise_body(blob, "application/octet-stream") == blob
    assert cm.content_hash(blob, "application/octet-stream") == cm.sha256_hex(blob)


def test_normalise_body_rejects_non_bytes():
    with pytest.raises(TypeError):
        cm.normalise_body("not bytes", "text/plain")


# ---------------------------------------------------------------------------
# 2-6. check_source classification, with an injected fetcher
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_first_ever_check_is_first_seen_not_a_content_change():
    source = make_source(content_hash=None)
    body = b"registry listing v1"  # synthetic test fixture
    fetcher = RecordingFetcher(
        FetchResult(status_code=200, body=body, content_type="text/plain")
    )

    event = await cm.check_source(source, fetcher=fetcher, now=BASE)

    assert event.change_kind == "first_seen"
    assert event.previous_hash is None
    assert event.new_hash == cm.content_hash(body, "text/plain")
    assert event.http_status == 200
    assert event.is_change is True
    assert event.is_failure is False
    assert cm.should_enqueue_rescan(event) is True


@pytest.mark.asyncio
async def test_304_yields_unchanged_and_replays_the_stored_validators():
    known = cm.content_hash(b"stable listing", "text/plain")  # synthetic test fixture
    source = make_source(
        content_hash=known,
        etag='W/"abc123"',
        last_modified="Wed, 02 Sep 2026 10:00:00 GMT",
        last_changed_at=BASE - timedelta(days=2),
    )
    fetcher = RecordingFetcher(FetchResult(status_code=304))

    event, result = await cm.observe_source(
        source, fetcher=fetcher, now=BASE + timedelta(hours=1)
    )

    assert event.change_kind == "unchanged"
    assert event.is_change is False
    # A 304 transfers no body, so there is nothing to hash and nothing is invented.
    assert event.new_hash is None
    assert event.bytes_after is None

    _url, headers, _timeout = fetcher.calls[0]
    assert headers["If-None-Match"] == 'W/"abc123"'
    assert headers["If-Modified-Since"] == "Wed, 02 Sep 2026 10:00:00 GMT"

    before_changed_at = source.last_changed_at
    updated = cm.apply_event(source, event, result, now=BASE + timedelta(hours=1))

    assert updated.content_hash == known
    assert updated.last_changed_at == before_changed_at
    assert updated.etag == 'W/"abc123"'
    assert updated.last_checked_at == BASE + timedelta(hours=1)
    assert updated.consecutive_failures == 0


@pytest.mark.asyncio
async def test_200_with_an_identical_body_is_unchanged_without_any_etag():
    body = b"registry listing v1"  # synthetic test fixture
    source = make_source(content_hash=cm.content_hash(body, "text/plain"), etag=None)
    fetcher = RecordingFetcher(
        FetchResult(status_code=200, body=body, content_type="text/plain")
    )

    event = await cm.check_source(source, fetcher=fetcher, now=BASE)

    assert event.change_kind == "unchanged"
    assert event.is_change is False
    assert event.new_hash == source.content_hash
    _url, headers, _timeout = fetcher.calls[0]
    assert "If-None-Match" not in headers


@pytest.mark.asyncio
async def test_200_with_a_different_body_carries_the_true_previous_and_new_hashes():
    old_body = b"left-pad 1.3.0"  # synthetic test fixture
    new_body = b"left-pad 1.3.1"  # synthetic test fixture
    old_hash = cm.content_hash(old_body, "text/plain")
    source = make_source(
        content_hash=old_hash, last_changed_at=BASE - timedelta(days=5)
    )
    fetcher = RecordingFetcher(
        FetchResult(status_code=200, body=new_body, content_type="text/plain")
    )

    event, result = await cm.observe_source(source, fetcher=fetcher, now=BASE)

    assert event.change_kind == "content"
    assert event.previous_hash == old_hash
    assert event.new_hash == cm.content_hash(new_body, "text/plain")
    assert event.new_hash != old_hash
    assert event.bytes_after == len(cm.normalise_body(new_body, "text/plain"))
    assert cm.should_enqueue_rescan(event) is True

    updated = cm.apply_event(source, event, result, now=BASE)
    assert updated.content_hash == event.new_hash
    assert updated.last_changed_at == BASE


@pytest.mark.asyncio
async def test_moved_validators_over_identical_content_is_an_etag_event_not_a_rescan():
    body = b"registry listing v1"  # synthetic test fixture
    source = make_source(content_hash=cm.content_hash(body, "text/plain"), etag='"v1"')
    fetcher = RecordingFetcher(
        FetchResult(status_code=200, body=body, content_type="text/plain", etag='"v2"')
    )

    event = await cm.check_source(source, fetcher=fetcher, now=BASE)

    assert event.change_kind == "etag"
    assert event.is_change is True
    assert event.new_hash == source.content_hash
    assert cm.should_enqueue_rescan(event) is False


@pytest.mark.asyncio
async def test_a_fetch_failure_is_an_error_event_and_never_a_content_change():
    known = cm.content_hash(b"listing", "text/plain")  # synthetic test fixture
    source = make_source(
        content_hash=known,
        etag='"v1"',
        last_changed_at=BASE - timedelta(days=1),
        consecutive_failures=2,
    )
    fetcher = RecordingFetcher(FetchResult(error="ConnectTimeout: timed out"))

    event, result = await cm.observe_source(source, fetcher=fetcher, now=BASE)

    assert event.change_kind == "error"
    assert event.is_failure is True
    assert event.new_hash is None
    assert cm.should_enqueue_rescan(event) is False
    assert "ConnectTimeout" in event.notes

    before_changed_at = source.last_changed_at
    updated = cm.apply_event(source, event, result, now=BASE)

    assert updated.consecutive_failures == 3
    assert updated.content_hash == known
    assert updated.etag == '"v1"'
    assert updated.last_changed_at == before_changed_at
    assert updated.last_checked_at == BASE


@pytest.mark.asyncio
async def test_a_non_2xx_response_is_an_error_and_404_is_gone():
    source = make_source(content_hash=cm.content_hash(b"x", "text/plain"))

    gone = await cm.check_source(
        source, fetcher=RecordingFetcher(FetchResult(status_code=404)), now=BASE
    )
    assert gone.change_kind == "gone"
    assert gone.is_failure is True
    assert cm.should_enqueue_rescan(gone) is False

    server_error = await cm.check_source(
        source, fetcher=RecordingFetcher(FetchResult(status_code=503)), now=BASE
    )
    assert server_error.change_kind == "error"
    assert server_error.new_hash is None


@pytest.mark.asyncio
async def test_a_fetcher_that_raises_is_contained_as_an_error_event():
    source = make_source()

    async def exploding_fetcher(url, headers, timeout):
        raise RuntimeError("injected transport explosion")

    event = await cm.check_source(source, fetcher=exploding_fetcher, now=BASE)

    assert event.change_kind == "error"
    assert "RuntimeError" in event.notes


@pytest.mark.asyncio
async def test_an_unsafe_source_url_is_never_fetched():
    source = make_source(url="http://169.254.169.254/latest/meta-data/")
    fetcher = RecordingFetcher(FetchResult(status_code=200, body=b"secrets"))

    event = await cm.check_source(source, fetcher=fetcher, now=BASE)

    assert event.change_kind == "error"
    assert "unsafe_url" in event.notes
    assert fetcher.calls == []


# ---------------------------------------------------------------------------
# 7. Backoff and due-selection are pure
# ---------------------------------------------------------------------------


def test_backoff_grows_with_failures_and_is_capped():
    assert cm.backoff_minutes(60, 0) == 60
    assert cm.backoff_minutes(60, 1) == 120
    assert cm.backoff_minutes(60, 2) == 240
    assert cm.backoff_minutes(60, 3) == 480

    curve = [cm.backoff_minutes(60, n) for n in range(12)]
    assert curve == sorted(curve)
    assert max(curve) == cm.MAX_BACKOFF_MINUTES
    # The ceiling holds no matter how bad the streak gets.
    assert cm.backoff_minutes(60, 10_000) == cm.MAX_BACKOFF_MINUTES
    # Doubling stops after BACKOFF_MAX_DOUBLINGS.
    assert (
        cm.backoff_minutes(1, cm.BACKOFF_MAX_DOUBLINGS) == 2**cm.BACKOFF_MAX_DOUBLINGS
    )
    assert cm.backoff_minutes(1, cm.BACKOFF_MAX_DOUBLINGS + 5) == (
        2**cm.BACKOFF_MAX_DOUBLINGS
    )


def test_backoff_is_a_pure_function():
    assert cm.backoff_minutes(30, 4) == cm.backoff_minutes(30, 4)
    # Negative / zero inputs are coerced, never crash.
    assert cm.backoff_minutes(0, 0) == cm.DEFAULT_CHECK_INTERVAL_MINUTES
    assert cm.backoff_minutes(60, -3) == 60


def test_is_due_respects_the_interval_the_backoff_and_the_enabled_flag():
    never_checked = make_source(last_checked_at=None)
    assert cm.is_due(never_checked, now=BASE) is True

    fresh = make_source(last_checked_at=BASE - timedelta(minutes=30))
    assert cm.is_due(fresh, now=BASE) is False

    stale = make_source(last_checked_at=BASE - timedelta(minutes=61))
    assert cm.is_due(stale, now=BASE) is True

    # Same staleness, but a failure streak pushes the next check out to 120m.
    failing = make_source(
        last_checked_at=BASE - timedelta(minutes=61), consecutive_failures=1
    )
    assert cm.is_due(failing, now=BASE) is False
    assert cm.next_check_due_at(failing, now=BASE) == BASE - timedelta(
        minutes=61
    ) + timedelta(minutes=120)
    assert cm.is_due(failing, now=BASE + timedelta(minutes=60)) is True

    disabled = make_source(last_checked_at=None, enabled=False)
    assert cm.is_due(disabled, now=BASE) is False


def test_only_content_and_first_seen_warrant_a_rescan():
    kinds = {
        kind: cm.should_enqueue_rescan(cm.ChangeEvent(source_id="s", change_kind=kind))
        for kind in cm.CHANGE_KINDS
    }
    assert kinds == {
        "content": True,
        "first_seen": True,
        "etag": False,
        "gone": False,
        "error": False,
        "unchanged": False,
    }


# ---------------------------------------------------------------------------
# 8. SSRF guard — the security-critical surface
# ---------------------------------------------------------------------------


UNSAFE_URLS = [
    # Explicitly required by the brief.
    "http://localhost/",
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "file:///etc/passwd",
    "gopher://example.com/_data",
    # Loopback and link-local in other spellings.
    "https://localhost:443/",
    "http://127.1.2.3/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://2130706433/",
    "http://0177.0.0.1/",
    "http://0x7f.0.0.1/",
    "http://0.0.0.0/",
    "http://169.254.170.2/v2/credentials",
    # Other RFC1918 / non-public ranges.
    "http://172.16.0.1/",
    "http://172.31.255.254/",
    "http://100.64.0.1/",
    "http://[fd00::1]/",
    # IPv6 forms that tunnel an IPv4 address. ipaddress.is_global does not see
    # through the wrapper, so each of these reached loopback/link-local until
    # _embedded_ipv4 unwrapped them.
    "http://[::127.0.0.1]/",  # IPv4-compatible ::/96
    "http://[::a9fe:a9fe]/",  # IPv4-compatible form of 169.254.169.254
    "http://[64:ff9b::7f00:1]/",  # NAT64 well-known prefix
    "http://[64:ff9b::a9fe:a9fe]/",  # NAT64 pointing at cloud IMDS
    "http://[2002:7f00:1::]/",  # 6to4 wrapping 127.0.0.1
    "http://[2002:a9fe:a9fe::]/",  # 6to4 wrapping 169.254.169.254
    "http://[fe80::1]/",  # link-local
    "http://[fc00::1]/",  # unique-local
    "http://[::]/",  # unspecified
    "http://[not:an:address]/",  # malformed literal must not fall through
    "http://[fe80::1%25eth0]/",  # zone id is never valid for a remote fetch
    # Internal naming.
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://buildserver.local/",
    "http://db.corp/",
    "http://intranet/",
    # Other schemes and shapes.
    "ftp://example.com/pkg.tar.gz",
    "data:text/plain,hello",
    "javascript:alert(1)",
    "",
    "https://user:password@example.com/",
    "https://example.com:6379/",
    "https://example.com:22/",
    "https://" + "a" * (cm.MAX_URL_LENGTH + 10) + ".example.com/",
]

SAFE_URLS = [
    "https://example.com/listing",
    "https://registry.npmjs.org/left-pad",
    "http://example.org/plain",
    "https://example.com:8443/api/v1/packages",
    "http://example.org:8080/listing",
    "https://raw.githubusercontent.com/owner/repo/main/server.json",
    "https://8.8.8.8/",
    # Globally routable IPv6 literals. urlsplit strips the brackets, so these
    # used to be read as single-label hostnames and rejected outright — the
    # guard must not block the entire public IPv6 internet to stop ::1.
    "https://[2606:4700:4700::1111]/",
    "https://[2001:4860:4860::8888]/listing",
    "https://[2606:4700:4700::1111]:8443/api",
]


@pytest.mark.parametrize("url", UNSAFE_URLS)
def test_assert_safe_url_rejects_unsafe_targets(url):
    with pytest.raises(UnsafeURLError):
        cm.assert_safe_url(url)
    assert cm.is_safe_url(url) is False


@pytest.mark.parametrize("url", SAFE_URLS)
def test_assert_safe_url_accepts_ordinary_public_urls(url):
    assert cm.assert_safe_url(url)
    assert cm.is_safe_url(url) is True


def test_assert_safe_url_normalises_and_drops_the_fragment():
    assert (
        cm.assert_safe_url("  https://example.com/a/b?x=1#frag  ")
        == "https://example.com/a/b?x=1"
    )
    assert cm.assert_safe_url("HTTPS://example.com/a").startswith("https://")


def test_is_safe_url_never_raises_on_junk_input():
    for junk in [None, 12345, b"https://example.com", object()]:
        assert cm.is_safe_url(junk) is False


@pytest.mark.asyncio
async def test_dns_resolution_to_a_private_address_is_rejected():
    def resolver(hostname):
        # synthetic test fixture: a public name pointing inside the VPC
        return ["10.0.0.5"]

    with pytest.raises(UnsafeURLError):
        await cm.assert_safe_url_resolved(
            "https://evil.example.com/listing", resolver=resolver
        )


@pytest.mark.asyncio
async def test_dns_resolution_rejects_when_any_answer_is_private():
    def resolver(hostname):
        # synthetic test fixture: DNS round-robin with one poisoned answer
        return ["93.184.216.34", "127.0.0.1"]

    with pytest.raises(UnsafeURLError):
        await cm.assert_safe_url_resolved(
            "https://mixed.example.com/listing", resolver=resolver
        )


@pytest.mark.asyncio
async def test_dns_resolution_to_public_addresses_is_allowed():
    def resolver(hostname):
        return ["93.184.216.34"]  # synthetic test fixture

    safe = await cm.assert_safe_url_resolved(
        "https://good.example.com/listing", resolver=resolver
    )
    assert safe == "https://good.example.com/listing"


@pytest.mark.asyncio
async def test_dns_failure_is_treated_as_unsafe_not_as_permission():
    def resolver(hostname):
        raise OSError("nxdomain")

    with pytest.raises(UnsafeURLError):
        await cm.assert_safe_url_resolved(
            "https://nowhere.example.com/", resolver=resolver
        )


@pytest.mark.asyncio
async def test_a_public_ip_literal_does_not_need_the_resolver():
    calls: list[str] = []

    def resolver(hostname):
        calls.append(hostname)
        return ["10.0.0.5"]

    assert await cm.assert_safe_url_resolved("https://8.8.8.8/x", resolver=resolver)
    assert calls == []


# ---------------------------------------------------------------------------
# Persistence and queue behaviour (in-memory db, no network)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_source_is_idempotent_and_rejects_bad_input():
    url = "https://registry.example.com/packages/left-pad"
    first = await cm.register_source(url, "package_page", now=BASE)
    second = await cm.register_source(url, "package_page", now=BASE)

    assert first.id == second.id
    assert first.check_interval_minutes == cm.DEFAULT_CHECK_INTERVAL_MINUTES

    with pytest.raises(UnsafeURLError):
        await cm.register_source("http://127.0.0.1/", "package_page", now=BASE)
    with pytest.raises(ValueError):
        await cm.register_source("https://example.com/other", "not_a_type", now=BASE)

    floored = await cm.register_source(
        "https://example.com/fast", "other", check_interval_minutes=1, now=BASE
    )
    assert floored.check_interval_minutes == cm.MIN_CHECK_INTERVAL_MINUTES


@pytest.mark.asyncio
async def test_full_poll_lifecycle_persists_only_real_observations():
    source = await cm.register_source(
        "https://registry.example.com/packages/left-pad",
        "package_page",
        check_interval_minutes=60,
        now=BASE,
    )
    v1 = b'{"name":"left-pad","version":"1.3.0"}'  # synthetic test fixture
    v2 = b'{"name":"left-pad","version":"1.3.1"}'  # synthetic test fixture
    v1_hash = cm.content_hash(v1, "application/json")
    v2_hash = cm.content_hash(v2, "application/json")

    # 1. First poll — first_seen, queued for rescan.
    first = await cm.process_source(
        source,
        fetcher=RecordingFetcher(
            FetchResult(
                status_code=200, body=v1, content_type="application/json", etag='"v1"'
            )
        ),
        now=BASE,
    )
    assert first.change_kind == "first_seen"
    assert first.new_hash == v1_hash
    assert first.queued_for_rescan is True

    stored = await cm.get_source(source.id)
    assert stored.content_hash == v1_hash
    assert stored.etag == '"v1"'
    assert stored.last_checked_at == BASE
    assert stored.last_changed_at == BASE
    assert len(await cm.source_events(source.id)) == 1

    # 2. Second poll — 304, and the stored ETag is replayed.
    t2 = BASE + timedelta(hours=2)
    fetcher = RecordingFetcher(FetchResult(status_code=304))
    second = await cm.process_source(stored, fetcher=fetcher, now=t2)
    assert second.change_kind == "unchanged"
    assert fetcher.calls[0][1]["If-None-Match"] == '"v1"'

    stored = await cm.get_source(source.id)
    assert stored.content_hash == v1_hash  # not rewritten
    assert stored.last_changed_at == BASE  # not rewritten
    assert stored.last_checked_at == t2  # but the schedule advanced
    # "unchanged" is not persisted as an event.
    assert len(await cm.source_events(source.id)) == 1

    # 3. Third poll — the content really moved.
    t3 = BASE + timedelta(hours=4)
    third = await cm.process_source(
        stored,
        fetcher=RecordingFetcher(
            FetchResult(
                status_code=200, body=v2, content_type="application/json", etag='"v2"'
            )
        ),
        now=t3,
    )
    assert third.change_kind == "content"
    assert third.previous_hash == v1_hash
    assert third.new_hash == v2_hash
    assert third.queued_for_rescan is True

    stored = await cm.get_source(source.id)
    assert stored.content_hash == v2_hash
    assert stored.etag == '"v2"'
    assert stored.last_changed_at == t3
    assert stored.consecutive_failures == 0

    events = await cm.source_events(source.id)
    assert [e.change_kind for e in events] == ["content", "first_seen"]

    # 4. Fourth poll — a transport failure. Recorded, counted, never a change.
    t4 = BASE + timedelta(hours=8)
    fourth = await cm.process_source(
        stored,
        fetcher=RecordingFetcher(FetchResult(error="ReadTimeout: too slow")),
        now=t4,
    )
    assert fourth.change_kind == "error"
    assert fourth.queued_for_rescan is False

    stored = await cm.get_source(source.id)
    assert stored.consecutive_failures == 1
    assert stored.content_hash == v2_hash  # untouched by a failure
    assert stored.last_changed_at == t3  # untouched by a failure

    kinds = [e.change_kind for e in await cm.source_events(source.id)]
    assert kinds == ["error", "content", "first_seen"]
    assert "unchanged" not in kinds


@pytest.mark.asyncio
async def test_pending_queue_drains_only_when_a_worker_takes_an_item():
    source = await cm.register_source(
        "https://registry.example.com/packages/queued", "package_page", now=BASE
    )
    body = b"listing v1"  # synthetic test fixture
    event = await cm.process_source(
        source,
        fetcher=RecordingFetcher(
            FetchResult(status_code=200, body=body, content_type="text/plain")
        ),
        now=BASE,
    )
    assert event.change_kind == "first_seen"

    pending = await cm.pending_rescan_events()
    assert [e.id for e in pending] == [event.id]

    handed_off = await cm.mark_rescan_enqueued(
        event.id, now=BASE + timedelta(minutes=1)
    )
    assert handed_off is True
    assert await cm.pending_rescan_events() == []

    stored = await cm.latest_event(source.id)
    assert stored.queued_for_rescan is False
    assert stored.rescan_enqueued_at == BASE + timedelta(minutes=1)

    assert await cm.mark_rescan_enqueued("no-such-event-id") is False


@pytest.mark.asyncio
async def test_select_due_sources_applies_backoff_and_orders_stalest_first():
    never = await cm.register_source(
        "https://example.com/never", "other", check_interval_minutes=60, now=BASE
    )
    stale = await cm.register_source(
        "https://example.com/stale", "other", check_interval_minutes=60, now=BASE
    )
    fresh = await cm.register_source(
        "https://example.com/fresh", "other", check_interval_minutes=60, now=BASE
    )
    failing = await cm.register_source(
        "https://example.com/failing", "other", check_interval_minutes=60, now=BASE
    )
    disabled = await cm.register_source(
        "https://example.com/disabled",
        "other",
        check_interval_minutes=60,
        enabled=False,
        now=BASE,
    )

    from api.database import db

    await db.update(
        cm.MONITORED_SOURCES_TABLE,
        {"id": stale.id},
        {"last_checked_at": (BASE - timedelta(hours=5)).isoformat()},
    )
    await db.update(
        cm.MONITORED_SOURCES_TABLE,
        {"id": fresh.id},
        {"last_checked_at": (BASE - timedelta(minutes=10)).isoformat()},
    )
    await db.update(
        cm.MONITORED_SOURCES_TABLE,
        {"id": failing.id},
        {
            "last_checked_at": (BASE - timedelta(minutes=90)).isoformat(),
            "consecutive_failures": 3,  # backoff -> 480m, so not due yet
        },
    )
    await db.update(
        cm.MONITORED_SOURCES_TABLE,
        {"id": disabled.id},
        {"last_checked_at": None},
    )

    due = await cm.select_due_sources(limit=10, now=BASE)
    due_ids = [s.id for s in due]

    assert never.id in due_ids
    assert stale.id in due_ids
    assert fresh.id not in due_ids
    assert failing.id not in due_ids
    assert disabled.id not in due_ids
    # Never-checked sorts ahead of merely-stale.
    assert due_ids.index(never.id) < due_ids.index(stale.id)

    assert len(await cm.select_due_sources(limit=1, now=BASE)) == 1


@pytest.mark.asyncio
async def test_queue_status_counts_are_real_row_counts():
    empty = await cm.get_queue_status(now=BASE)
    assert empty["total_sources"] == 0
    assert empty["enabled_sources"] == 0
    assert empty["pending_rescans"] == 0

    source = await cm.register_source(
        "https://example.com/counted", "other", check_interval_minutes=60, now=BASE
    )
    await cm.register_source(
        "https://example.com/off", "other", enabled=False, now=BASE
    )
    await cm.process_source(
        source,
        fetcher=RecordingFetcher(
            FetchResult(status_code=200, body=b"v1", content_type="text/plain")
        ),
        now=BASE,
    )

    status_now = await cm.get_queue_status(now=BASE)
    assert status_now["total_sources"] == 2
    assert status_now["enabled_sources"] == 1
    assert status_now["pending_rescans"] == 1
    assert status_now["failing_sources"] == 0
    assert status_now["due_now"] == 0  # just polled at BASE, interval 360m

    later = await cm.get_queue_status(now=BASE + timedelta(hours=7))
    assert later["due_now"] == 1


# ---------------------------------------------------------------------------
# Round-tripping and schema agreement
# ---------------------------------------------------------------------------


def test_monitored_source_round_trips_through_a_db_row():
    source = make_source(
        content_hash=cm.content_hash(b"x", "text/plain"),
        etag='"v1"',
        last_checked_at=BASE,
        last_changed_at=BASE,
        last_status_code=200,
        consecutive_failures=2,
        metadata={"note": "synthetic test fixture"},
    )
    restored = MonitoredSource.from_row(source.to_row())

    assert restored == source


def test_change_event_round_trips_and_truncates_notes_to_the_column_width():
    event = cm.ChangeEvent(
        source_id="src-1",
        change_kind="content",
        id=cm.new_id(),
        detected_at=BASE,
        previous_hash=cm.sha256_hex(b"a"),
        new_hash=cm.sha256_hex(b"b"),
        http_status=200,
        bytes_after=42,
        notes="n" * (cm.MAX_NOTES_CHARS + 500),  # synthetic test fixture
    )
    row = event.to_row()

    assert len(row["notes"]) == cm.MAX_NOTES_CHARS
    restored = cm.ChangeEvent.from_row(row)
    assert restored.change_kind == "content"
    assert restored.new_hash == event.new_hash
    assert restored.bytes_after == 42


def test_parse_timestamp_handles_every_shape_the_db_layer_returns():
    assert cm.parse_timestamp(None) is None
    assert cm.parse_timestamp("") is None
    assert cm.parse_timestamp("not a timestamp") is None
    assert cm.parse_timestamp(BASE) == BASE
    assert cm.parse_timestamp(BASE.isoformat()) == BASE
    assert cm.parse_timestamp("2026-09-03T12:00:00Z") == BASE
    naive = datetime(2026, 9, 3, 12, 0, 0)
    assert cm.parse_timestamp(naive) == BASE


def test_service_enums_match_the_migration_check_constraints():
    sql = cm.__file__.replace(
        "services/change_monitor.py", "migrations/010_create_change_monitor.sql"
    )
    with open(sql, encoding="utf-8") as handle:
        text = handle.read()

    for source_type in cm.SOURCE_TYPES:
        assert f"'{source_type}'" in text
    for kind in cm.CHANGE_KINDS:
        assert f"'{kind}'" in text
    assert "CK_monitored_sources_source_type" in text
    assert "CK_source_change_events_kind" in text


# ---------------------------------------------------------------------------
# 9. Router — the create endpoint refuses an unsafe URL
# ---------------------------------------------------------------------------


@pytest.fixture()
def monitor_client() -> Iterator[TestClient]:
    """A TestClient carrying only the monitor router.

    ``api/main.py`` does register this router (see
    ``tests/test_monitor_router_registered.py``); mounting it alone here keeps
    these cases off the full app's middleware stack. Auth is replaced with a
    reviewer identity — the role check itself is asserted separately.
    """
    from api.models import UserResponse
    from api.routers import monitor
    from api.routers.auth import get_current_user_unified

    async def _reviewer() -> UserResponse:
        # synthetic test fixture: a reviewer identity, no Auth0 round trip
        return UserResponse(
            id="test-reviewer", email="reviewer@sigil.dev", role="reviewer"
        )

    app = FastAPI()
    app.include_router(monitor.router)
    app.dependency_overrides[get_current_user_unified] = _reviewer

    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/listing",
        "http://127.0.0.1:8080/listing",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/admin",
        "file:///etc/passwd",
        "gopher://example.com/_data",
        "https://user:pass@example.com/listing",
        "http://metadata.google.internal/computeMetadata/v1/",
    ],
)
def test_create_source_rejects_unsafe_urls_with_4xx(monitor_client, url):
    response = monitor_client.post(
        "/api/monitor/sources", json={"url": url, "source_type": "registry_listing"}
    )

    assert 400 <= response.status_code < 500, response.text
    # Specifically the SSRF guard, not a routing or schema-validation accident.
    assert response.status_code == 400, response.text
    assert "Unsafe URL" in response.json()["detail"]
    # And nothing was written.
    from api.database import db

    assert db._memory_store.get(cm.MONITORED_SOURCES_TABLE, {}) == {}


def test_create_source_rejects_an_unknown_source_type(monitor_client):
    response = monitor_client.post(
        "/api/monitor/sources",
        json={"url": "https://example.com/listing", "source_type": "not_a_type"},
    )
    assert response.status_code == 400
    assert "source_type" in response.json()["detail"]


def test_create_source_accepts_a_normal_https_url_and_is_idempotent(monitor_client):
    payload = {
        "url": "https://registry.example.com/packages/left-pad",
        "source_type": "package_page",
        "check_interval_minutes": 60,
    }
    first = monitor_client.post("/api/monitor/sources", json=payload)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["created"] is True
    assert body["source"]["url"] == payload["url"]
    assert body["source"]["content_hash"] is None  # nothing polled yet
    assert body["source"]["is_due"] is True

    second = monitor_client.post("/api/monitor/sources", json=payload)
    assert second.json()["created"] is False
    assert second.json()["source"]["id"] == body["source"]["id"]


def test_create_source_requires_a_review_role(monitor_client):
    from api.models import UserResponse
    from api.routers.auth import get_current_user_unified

    async def _member() -> UserResponse:
        # synthetic test fixture: a plain member identity
        return UserResponse(id="test-member", email="member@sigil.dev", role="member")

    monitor_client.app.dependency_overrides[get_current_user_unified] = _member
    response = monitor_client.post(
        "/api/monitor/sources",
        json={"url": "https://example.com/listing", "source_type": "other"},
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# 10. default_fetcher — bounded transfers and a connection pinned to the
#     address the guard actually validated.
#
# httpx is stubbed out entirely: these cases assert what default_fetcher asks
# the HTTP layer to do, and no socket is opened. The stub response only
# implements what the fetcher touches (status_code, headers, aiter_raw).
# ---------------------------------------------------------------------------


class _StubResponse:
    """A streamed httpx response. # synthetic test fixture"""

    def __init__(self, status_code=200, headers=None, chunks=()):
        import httpx as _httpx

        self.status_code = status_code
        self.headers = _httpx.Headers(headers or {})
        self._chunks = list(chunks)
        self.chunks_read = 0

    async def aiter_raw(self):
        for chunk in self._chunks:
            self.chunks_read += 1
            yield chunk


class _StubStream:
    def __init__(self, response: _StubResponse) -> None:
        self._response = response

    async def __aenter__(self) -> _StubResponse:
        return self._response

    async def __aexit__(self, *exc_info) -> bool:
        return False


def _stub_httpx(monkeypatch, response: _StubResponse) -> list[dict]:
    """Replace httpx.AsyncClient with a recorder. Returns the recorded calls."""
    import httpx as _httpx

    calls: list[dict] = []

    class _Client:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return False

        def stream(self, method, url, headers=None, extensions=None):
            calls.append(
                {
                    "method": method,
                    "url": str(url),
                    "headers": dict(headers or {}),
                    "extensions": dict(extensions or {}),
                }
            )
            return _StubStream(response)

    monkeypatch.setattr(_httpx, "AsyncClient", _Client)
    return calls


def _pin_resolver_to(monkeypatch, *addresses: str) -> None:
    """Pin the module's DNS resolver so no lookup leaves the process."""
    monkeypatch.setattr(cm, "_default_resolver", lambda hostname: list(addresses))


@pytest.mark.asyncio
async def test_fetcher_connects_to_the_validated_address_not_the_hostname(monkeypatch):
    # The guard validates addresses; if the request is then made by hostname,
    # httpx resolves again and a TTL-0 rebind answers with a private address.
    _pin_resolver_to(monkeypatch, "93.184.216.34")
    body = b"listing v1"  # synthetic test fixture
    response = _StubResponse(headers={"content-type": "text/plain"}, chunks=[body])
    calls = _stub_httpx(monkeypatch, response)

    result = await cm.default_fetcher(
        "https://listing.example.com/packages", {"User-Agent": cm.USER_AGENT}, 5.0
    )

    assert result.status_code == 200
    assert result.body == body
    assert calls[0]["url"] == "https://93.184.216.34/packages"
    # The name survives where the origin needs it: vhost routing and TLS.
    assert calls[0]["headers"]["Host"] == "listing.example.com"
    assert calls[0]["extensions"]["sni_hostname"] == "listing.example.com"
    # And a compressed body is not solicited in the first place.
    assert calls[0]["headers"]["Accept-Encoding"] == "identity"


@pytest.mark.asyncio
async def test_fetcher_pins_an_ipv6_answer_and_keeps_the_port(monkeypatch):
    _pin_resolver_to(monkeypatch, "2606:2800:220:1:248:1893:25c8:1946")
    calls = _stub_httpx(monkeypatch, _StubResponse(chunks=[b"ok"]))

    await cm.default_fetcher(
        "https://listing.example.com:8443/packages", {"User-Agent": "x"}, 5.0
    )

    assert calls[0]["url"] == (
        "https://[2606:2800:220:1:248:1893:25c8:1946]:8443/packages"
    )
    assert calls[0]["headers"]["Host"] == "listing.example.com:8443"


@pytest.mark.asyncio
async def test_fetcher_aborts_a_body_that_grows_past_the_cap(monkeypatch):
    # Four chunks, half the cap each: the transfer must stop on the third.
    _pin_resolver_to(monkeypatch, "93.184.216.34")
    chunk = b"x" * (cm.MAX_RESPONSE_BYTES // 2)  # synthetic test fixture
    response = _StubResponse(chunks=[chunk, chunk, chunk, chunk])
    _stub_httpx(monkeypatch, response)

    result = await cm.default_fetcher(
        "https://listing.example.com/big", {"User-Agent": "x"}, 5.0
    )

    assert result.truncated is True
    assert result.error == f"response exceeded {cm.MAX_RESPONSE_BYTES} bytes"
    assert result.body == b""
    # The cap is enforced during the transfer, not after it.
    assert response.chunks_read == 3


@pytest.mark.asyncio
async def test_fetcher_refuses_an_oversize_declared_length_before_reading(monkeypatch):
    _pin_resolver_to(monkeypatch, "93.184.216.34")
    response = _StubResponse(
        headers={"content-length": str(cm.MAX_RESPONSE_BYTES + 1)},
        chunks=[b"x" * 1024],
    )
    _stub_httpx(monkeypatch, response)

    result = await cm.default_fetcher(
        "https://listing.example.com/huge", {"User-Agent": "x"}, 5.0
    )

    assert result.truncated is True
    assert response.chunks_read == 0


@pytest.mark.asyncio
async def test_fetcher_will_not_let_a_compressed_body_inflate_past_the_cap(monkeypatch):
    import gzip

    _pin_resolver_to(monkeypatch, "93.184.216.34")
    # A few kilobytes on the wire, ten times the cap once inflated.
    bomb = gzip.compress(b"A" * (cm.MAX_RESPONSE_BYTES * 10))  # synthetic test fixture
    assert len(bomb) < cm.MAX_RESPONSE_BYTES
    response = _StubResponse(
        headers={"content-type": "text/html", "content-encoding": "gzip"},
        chunks=[bomb],
    )
    _stub_httpx(monkeypatch, response)

    result = await cm.default_fetcher(
        "https://listing.example.com/bomb", {"User-Agent": "x"}, 5.0
    )

    assert result.truncated is True
    assert result.error == f"response exceeded {cm.MAX_RESPONSE_BYTES} bytes"
    assert result.body == b""


@pytest.mark.asyncio
async def test_fetcher_still_decodes_a_well_behaved_compressed_body(monkeypatch):
    import gzip

    _pin_resolver_to(monkeypatch, "93.184.216.34")
    page = b"<html><body>left-pad 1.3.0</body></html>"  # synthetic test fixture
    response = _StubResponse(
        headers={"content-type": "text/html", "content-encoding": "gzip"},
        chunks=[gzip.compress(page)],
    )
    _stub_httpx(monkeypatch, response)

    result = await cm.default_fetcher(
        "https://listing.example.com/gz", {"User-Agent": "x"}, 5.0
    )

    assert result.error == ""
    assert result.body == page


# ---------------------------------------------------------------------------
# 11. Column widths, backoff agreement, and honest persistence reporting
# ---------------------------------------------------------------------------


def test_response_validators_are_clipped_to_their_column_widths():
    source = make_source()
    event = cm.ChangeEvent(
        source_id=source.id,
        change_kind="first_seen",
        detected_at=BASE,
        new_hash=cm.sha256_hex(b"x"),
        http_status=200,
    )
    # An origin chooses its own headers; these are longer than the columns.
    result = FetchResult(
        status_code=200,
        body=b"x",
        etag='"' + "e" * 400 + '"',  # synthetic test fixture
        last_modified="M" * 400,  # synthetic test fixture
    )

    updated = cm.apply_event(source, event, result, now=BASE)

    assert len(updated.etag) == cm.MAX_ETAG_CHARS
    assert len(updated.last_modified) == cm.MAX_LAST_MODIFIED_CHARS
    row = updated.to_row()
    assert len(row["etag"]) == cm.MAX_ETAG_CHARS
    assert len(row["last_modified"]) == cm.MAX_LAST_MODIFIED_CHARS


def test_string_column_widths_match_the_migration():
    sql = cm.__file__.replace(
        "services/change_monitor.py", "migrations/010_create_change_monitor.sql"
    )
    with open(sql, encoding="utf-8") as handle:
        text = handle.read()

    assert f"etag NVARCHAR({cm.MAX_ETAG_CHARS})" in text
    assert f"last_modified NVARCHAR({cm.MAX_LAST_MODIFIED_CHARS})" in text
    assert f"notes NVARCHAR({cm.MAX_NOTES_CHARS})" in text


@pytest.mark.asyncio
async def test_a_long_etag_is_stored_at_the_column_width():
    source = await cm.register_source(
        "https://registry.example.com/packages/long-etag", "package_page", now=BASE
    )
    long_etag = '"' + "e" * 400 + '"'  # synthetic test fixture
    await cm.process_source(
        source,
        fetcher=RecordingFetcher(
            FetchResult(
                status_code=200,
                body=b"listing",
                content_type="text/plain",
                etag=long_etag,
            )
        ),
        now=BASE,
    )

    stored = await cm.get_source(source.id)
    assert len(stored.etag) == cm.MAX_ETAG_CHARS
    assert stored.last_checked_at == BASE


def test_the_due_prefilter_sql_applies_the_same_backoff_as_is_due():
    # If the pre-filter selects on the base interval while is_due applies
    # backoff, backed-off rows fill the TOP window and starve healthy ones.
    sql = cm.DUE_SOURCES_SQL
    assert "consecutive_failures" in sql
    assert "POWER(2," in sql
    assert f"THEN {cm.BACKOFF_MAX_DOUBLINGS}" in sql
    assert f"THEN {cm.MAX_BACKOFF_MINUTES}" in sql


@pytest.mark.asyncio
async def test_backed_off_sources_do_not_starve_healthy_ones():
    from api.database import db

    # 40 dead hosts, polled 10 minutes ago, deep in backoff (5m * 2**6 = 320m).
    for index in range(40):
        sick = await cm.register_source(
            f"https://dead-{index}.example.com/listing",
            "other",
            check_interval_minutes=5,
            now=BASE,
        )
        await db.update(
            cm.MONITORED_SOURCES_TABLE,
            {"id": sick.id},
            {
                "last_checked_at": (BASE - timedelta(minutes=10)).isoformat(),
                "consecutive_failures": 6,
            },
        )
        assert cm.is_due(await cm.get_source(sick.id), now=BASE) is False

    # Three healthy sources, polled more recently but genuinely due.
    healthy_ids = []
    for index in range(3):
        healthy = await cm.register_source(
            f"https://live-{index}.example.com/listing",
            "other",
            check_interval_minutes=5,
            now=BASE,
        )
        await db.update(
            cm.MONITORED_SOURCES_TABLE,
            {"id": healthy.id},
            {"last_checked_at": (BASE - timedelta(minutes=9)).isoformat()},
        )
        assert cm.is_due(await cm.get_source(healthy.id), now=BASE) is True
        healthy_ids.append(healthy.id)

    due = await cm.select_due_sources(limit=5, now=BASE)

    assert sorted(s.id for s in due) == sorted(healthy_ids)


@pytest.mark.asyncio
async def test_a_failed_source_write_is_not_reported_as_a_completed_poll(monkeypatch):
    from api.database import db

    source = await cm.register_source(
        "https://registry.example.com/packages/write-fail", "package_page", now=BASE
    )

    async def _boom(*args, **kwargs):
        raise RuntimeError("TCP Provider: connection reset by peer")

    monkeypatch.setattr(db, "update", _boom)

    with pytest.raises(RuntimeError):
        await cm.process_source(
            source,
            fetcher=RecordingFetcher(
                FetchResult(status_code=200, body=b"v1", content_type="text/plain")
            ),
            now=BASE,
        )

    monkeypatch.undo()
    stored = await cm.get_source(source.id)
    assert stored.last_checked_at is None  # nothing was persisted
    assert stored.content_hash is None
    assert await cm.pending_rescan_events() == []


@pytest.mark.asyncio
async def test_a_failed_event_write_is_not_reported_as_queued(monkeypatch):
    from api.database import db

    source = await cm.register_source(
        "https://registry.example.com/packages/event-fail", "package_page", now=BASE
    )

    async def _boom(*args, **kwargs):
        raise RuntimeError("TCP Provider: connection reset by peer")

    monkeypatch.setattr(db, "insert", _boom)

    with pytest.raises(RuntimeError):
        await cm.process_source(
            source,
            fetcher=RecordingFetcher(
                FetchResult(status_code=200, body=b"v1", content_type="text/plain")
            ),
            now=BASE,
        )

    monkeypatch.undo()
    assert await cm.source_events(source.id) == []
    assert await cm.pending_rescan_events() == []


@pytest.mark.asyncio
async def test_worker_counts_an_unpersisted_poll_as_a_crash_not_as_queued(monkeypatch):
    from api.database import db
    from api.workers.change_monitor_worker import ChangeMonitorWorker

    await cm.register_source(
        "https://registry.example.com/packages/batch-fail",
        "package_page",
        check_interval_minutes=5,
        now=BASE,
    )

    async def _boom(*args, **kwargs):
        raise RuntimeError("TCP Provider: connection reset by peer")

    monkeypatch.setattr(db, "insert", _boom)

    worker = ChangeMonitorWorker(
        request_delay=0.0,
        fetcher=RecordingFetcher(
            FetchResult(status_code=200, body=b"v1", content_type="text/plain")
        ),
    )
    report = await worker.process_batch(now=BASE)

    assert report.crashed == 1
    assert report.queued_for_rescan == 0
    assert report.polled == 0
    assert report.errors


def test_force_check_reports_a_failed_write_as_an_error_not_as_recorded(
    monitor_client, monkeypatch
):
    from api.database import db

    created = monitor_client.post(
        "/api/monitor/sources",
        json={
            "url": "https://registry.example.com/packages/http-write-fail",
            "source_type": "package_page",
        },
    )
    source_id = created.json()["source"]["id"]

    async def _stub_fetcher(url, headers, timeout):
        # synthetic test fixture: a 200 with a body, no socket opened
        return FetchResult(status_code=200, body=b"v1", content_type="text/plain")

    async def _boom(*args, **kwargs):
        raise RuntimeError("TCP Provider: connection reset by peer")

    monkeypatch.setattr(cm, "default_fetcher", _stub_fetcher)
    monkeypatch.setattr(db, "insert", _boom)

    response = monitor_client.post(f"/api/monitor/sources/{source_id}/check")
    assert response.status_code == 500, response.text

    monkeypatch.undo()
    queue = monitor_client.get("/api/monitor/queue")
    assert queue.json()["returned"] == 0
