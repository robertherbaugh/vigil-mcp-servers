import datetime as dt
import json

import httpx
import pytest
from fixtures import PROMISC_RULE, VM_STARTED_RULE, hit, k8s_pod, promisc
from vigil_wazuh5_bridge import mapping
from vigil_wazuh5_bridge import suppressions as sup
from vigil_wazuh5_bridge.bridge import Bridge, parse_ts
from vigil_wazuh5_bridge.clients import UpstreamError, VigilIngest, WazuhIndexer

NOW = dt.datetime(2026, 11, 27, 23, 0, tzinfo=dt.UTC)
VETH = sup.parse(
    {
        "version": 1,
        "suppressions": [
            {
                "id": "veth-promiscuous",
                "reason": "Pod veth interfaces join the CNI bridge at every pod start.",
                "review_by": "2027-02-27",
                "rule_ids": [PROMISC_RULE],
                "match": [
                    {"field": "event.original", "regex": r"\bdev=veth[0-9a-f]+\b"},
                    {"field": "event.original", "regex": r"\bauid=4294967295\b"},
                ],
            }
        ],
    },
    NOW.date(),
)


# --- mapping ---------------------------------------------------------------------


def test_mapping_fields():
    f = mapping.to_vigil(hit(k8s_pod("admin", VM_STARTED_RULE), hid="be3VLTXmbttp0000000001"))
    assert f["finding_id"] == "wazuh5-be3VLTXmbttp0000000001"
    assert len(f["finding_id"]) <= mapping.FINDING_ID_MAX
    assert f["data_source"] == "wazuh"
    assert f["severity"] == "low"
    assert f["title"] == "Cloud VM instance started"
    assert f["entity_context"]["usernames"] == ["admin"]
    assert f["entity_context"]["src_ips"] == ["192.0.2.10"]
    assert "node-a" in f["entity_context"]["hostnames"]
    assert f["mitre_predictions"] == {"T1578.002": None}
    assert f["metadata"]["rule_id"] == VM_STARTED_RULE
    assert "Agent: node-a" in f["description"]


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        ("critical", "critical"),
        ("high", "high"),
        ("medium", "medium"),
        ("low", "low"),
        ("informational", "info"),
        ("", "medium"),
        ("weird", "medium"),
    ],
)
def test_severity(level, expected):
    doc = promisc()
    doc["wazuh"]["rule"]["level"] = level
    assert mapping.severity(doc) == expected


def test_too_long_id_is_refused():
    with pytest.raises(ValueError, match="longer"):
        mapping.finding_id("x" * 60)


def test_nanosecond_timestamps_parse():
    t = parse_ts("2026-11-27T22:35:26.656908856Z")
    assert t == dt.datetime(2026, 11, 27, 22, 35, 26, 656908, tzinfo=dt.UTC)
    assert parse_ts("2026-11-27T19:10:24.665Z").microsecond == 665000
    assert parse_ts("nonsense") is None


# --- bridge ----------------------------------------------------------------------


class FakeFindings:
    def __init__(self, hits):
        self.hits = hits
        self.calls = []

    def findings_since(self, start, end):
        self.calls.append((start, end))
        return list(self.hits)


class FakeSink:
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    def send(self, findings):
        if self.fail:
            raise UpstreamError("Vigil ingest failed: HTTP 503")
        self.sent.extend(findings)
        return {}


def make(hits, sink=None, **kw):
    return Bridge(FakeFindings(hits), sink or FakeSink(), VETH, clock=lambda: NOW, **kw)


def test_poll_forwards_and_suppresses():
    hits = [
        hit(promisc(), "a" * 22),  # suppressed
        hit(promisc(auid="1000"), "b" * 22),  # a person: forwarded
        hit(k8s_pod("admin"), "c" * 22),  # no suppression for it: forwarded
    ]
    sink = FakeSink()
    b = make(hits, sink)
    r = b.poll()
    assert r.seen == 3
    assert r.forwarded == 2
    assert r.suppressed == {"veth-promiscuous": 1}
    assert [f["finding_id"] for f in sink.sent] == ["wazuh5-" + "b" * 22, "wazuh5-" + "c" * 22]
    assert b.metrics.suppressed.labels("veth-promiscuous")._value.get() == 1


def test_overlap_does_not_resend_or_recount():
    hits = [hit(promisc(), "a" * 22), hit(k8s_pod("admin"), "c" * 22)]
    sink = FakeSink()
    b = make(hits, sink)
    b.poll()
    r = b.poll()  # the same window again (overlap)
    assert r.seen == 0 and r.skipped_known == 2
    assert len(sink.sent) == 1
    assert b.metrics.suppressed.labels("veth-promiscuous")._value.get() == 1


def test_failed_send_keeps_the_cursor_and_retries():
    hits = [hit(k8s_pod("admin"), "c" * 22)]
    failing = FakeSink(fail=True)
    b = make(hits, failing)
    with pytest.raises(UpstreamError):
        b.poll()
    assert b.cursor is None
    b.sink = FakeSink()
    r = b.poll()
    assert r.forwarded == 1


def test_dry_run_never_sends():
    sink = FakeSink()
    r = make([hit(k8s_pod("admin"), "c" * 22)], sink, dry_run=True).poll()
    assert r.forwarded == 1 and sink.sent == []


def test_first_poll_uses_the_initial_lookback_then_the_cursor():
    b = make([hit(k8s_pod("admin"), "c" * 22)], initial_lookback=dt.timedelta(hours=2))
    b.poll()
    assert b.findings.calls[0][0] == "2026-11-27T21:00:00Z"
    assert b.cursor == dt.datetime(2026, 11, 27, 19, 10, 24, 665000, tzinfo=dt.UTC)
    b.poll()
    # cursor - 10 minutes of overlap
    assert b.findings.calls[1][0] == "2026-11-27T19:00:24.665000Z"


def test_long_outage_is_reported_as_a_gap():
    b = make([], max_lookback=dt.timedelta(hours=1))
    b.cursor = NOW - dt.timedelta(hours=5)
    b.poll()
    assert b.metrics.errors.labels("gap")._value.get() == 1
    assert b.findings.calls[0][0] == "2026-11-27T22:00:00Z"


# --- clients ---------------------------------------------------------------------


def test_indexer_pages_with_search_after():
    pages = [
        [dict(hit(k8s_pod("admin"), str(i).rjust(22, "0")), sort=[i, "e", "r"]) for i in (1, 2)],
        [dict(hit(k8s_pod("admin"), "3".rjust(22, "0")), sort=[3, "e", "r"])],
    ]
    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        bodies.append(body)
        assert request.url.path == "/wazuh-findings-v5-*/_search"
        return httpx.Response(200, json={"hits": {"hits": pages[len(bodies) - 1]}})

    client = httpx.Client(
        base_url="https://indexer.example", transport=httpx.MockTransport(handler)
    )
    got = list(WazuhIndexer(client, "wazuh-findings-v5-*", page_size=2).findings_since("a", "b"))
    assert len(got) == 3
    assert "search_after" not in bodies[0]
    assert bodies[1]["search_after"] == [2, "e", "r"]
    assert bodies[0]["query"]["range"]["@timestamp"] == {"gte": "a", "lte": "b"}


def test_indexer_error_raises():
    client = httpx.Client(
        base_url="https://i.example", transport=httpx.MockTransport(lambda r: httpx.Response(403))
    )
    with pytest.raises(UpstreamError, match="403"):
        list(WazuhIndexer(client, "x").findings_since("a", "b"))


def test_vigil_ingest_posts_the_form():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("authorization")
        form = dict(httpx.QueryParams(request.content.decode()))
        seen["form"] = form
        return httpx.Response(
            200, json={"findings_imported": 1, "findings_skipped": 0, "findings_errors": 0}
        )

    client = httpx.Client(
        base_url="http://vigil.example",
        headers={"Authorization": "Bearer t"},
        transport=httpx.MockTransport(handler),
    )
    VigilIngest(client).send([mapping.to_vigil(hit(k8s_pod("admin"), "c" * 22))])
    assert seen["path"] == "/api/ingest/ingest-string"
    assert seen["auth"] == "Bearer t"
    assert seen["form"]["format"] == "jsonl" and seen["form"]["data_type"] == "finding"
    lines = seen["form"]["data"].splitlines()
    assert [json.loads(line)["finding_id"] for line in lines] == ["wazuh5-" + "c" * 22]


def test_vigil_rejections_raise():
    client = httpx.Client(
        base_url="http://vigil.example",
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"findings_imported": 0, "findings_errors": 2})
        ),
    )
    with pytest.raises(UpstreamError, match="rejected 2"):
        VigilIngest(client).send([{"finding_id": "x"}])
