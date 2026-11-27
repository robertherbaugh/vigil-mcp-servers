import datetime as dt
from pathlib import Path

import pytest
from fixtures import (
    CONFIG_RULE,
    PROMISC_RULE,
    VM_STARTED_RULE,
    VM_TERMINATED_RULE,
    k8s_pod,
    promisc,
)
from vigil_wazuh5_bridge import suppressions as sup

TODAY = dt.date(2026, 11, 27)
EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "suppressions.example.yaml"

VETH = {
    "id": "veth-promiscuous",
    "reason": "Pod veth interfaces join the CNI bridge at every pod start.",
    "review_by": "2027-02-27",
    "rule_ids": [PROMISC_RULE, CONFIG_RULE],
    "match": [
        {"field": "event.original", "regex": r"\bdev=veth[0-9a-f]+\b"},
        {"field": "event.original", "regex": r"\bauid=4294967295\b"},
    ],
}
CONTROLLERS = {
    "id": "k8s-controllers",
    "reason": "Built-in controllers create and delete pods all day.",
    "review_by": "2027-02-27",
    "rule_ids": [VM_TERMINATED_RULE, VM_STARTED_RULE],
    "match": [
        {"field": "user.name", "in": ["system:serviceaccount:kube-system:job-controller"]},
        {"field": "orchestrator.resource.type", "equals": "pods"},
    ],
}


def load(*entries):
    return sup.parse({"version": 1, "suppressions": list(entries)}, TODAY)


def test_veth_from_the_kernel_is_suppressed():
    assert load(VETH).match(promisc(), TODAY).id == "veth-promiscuous"


def test_promiscuous_by_a_person_is_forwarded():
    # tcpdump on a pod interface from a login session: auid is set.
    assert load(VETH).match(promisc(auid="1000"), TODAY) is None


def test_promiscuous_on_a_real_nic_is_forwarded():
    assert load(VETH).match(promisc(dev="eth0"), TODAY) is None
    assert load(VETH).match(promisc(dev="vethernet"), TODAY) is None  # not veth<hex>


def test_other_rule_is_not_suppressed():
    doc = promisc()
    doc["wazuh"]["rule"]["id"] = "00000000-0000-0000-0000-000000000000"
    assert load(VETH).match(doc, TODAY) is None


def test_controller_pod_lifecycle_is_suppressed():
    s = load(CONTROLLERS)
    for rule in (VM_TERMINATED_RULE, VM_STARTED_RULE):
        doc = k8s_pod("system:serviceaccount:kube-system:job-controller", rule)
        assert s.match(doc, TODAY).id == "k8s-controllers"


def test_people_and_other_accounts_are_forwarded():
    s = load(CONTROLLERS)
    assert s.match(k8s_pod("admin"), TODAY) is None
    assert s.match(k8s_pod("system:serviceaccount:kube-system:other"), TODAY) is None
    # Same controller, but not a pod.
    assert (
        s.match(
            k8s_pod("system:serviceaccount:kube-system:job-controller", resource="secrets"), TODAY
        )
        is None
    )


def test_missing_field_is_forwarded():
    doc = k8s_pod("system:serviceaccount:kube-system:job-controller")
    del doc["user"]
    assert load(CONTROLLERS).match(doc, TODAY) is None


def test_expired_suppression_forwards_again():
    s = load(dict(VETH, review_by="2026-11-26"))
    assert s.match(promisc(), TODAY) is None
    assert [e.id for e in s.expired(TODAY)] == ["veth-promiscuous"]


def test_flattened_keys_are_read_too():
    doc = {"wazuh.rule.id": PROMISC_RULE, "event.original": "dev=veth0a1b2c3 auid=4294967295"}
    assert load(VETH).match(doc, TODAY) is not None


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"rule_ids": []}, "rule_ids"),
        ({"match": []}, "rule id alone"),
        ({"reason": "x"}, "reason"),
        ({"review_by": "2028-01-01"}, "more than a year"),
        ({"review_by": "soon"}, "review_by"),
        ({"id": "Bad Id"}, "id"),
        ({"match": [{"field": "user.name", "regex": ".*"}]}, "everything"),
        ({"match": [{"field": "user.name", "regex": "a*"}]}, "empty string"),
        ({"match": [{"field": "user.name", "regex": "("}]}, "bad regex"),
        ({"match": [{"field": "user.name", "prefix": "a"}]}, "too broad"),
        ({"match": [{"field": "user.name", "equals": "a", "in": ["b"]}]}, "exactly one"),
        ({"match": [{"field": "user.name", "glob": "a"}]}, "unknown key"),
        ({"match": [{"equals": "a"}]}, "'field'"),
        ({"extra": 1}, "unknown key"),
    ],
)
def test_invalid_entries_are_refused(change, message):
    with pytest.raises(sup.SuppressionError, match=message):
        load(dict(VETH, **change))


def test_duplicate_ids_are_refused():
    with pytest.raises(sup.SuppressionError, match="duplicate"):
        load(VETH, VETH)


def test_file_needs_version_1():
    with pytest.raises(sup.SuppressionError, match="version"):
        sup.parse({"suppressions": []}, TODAY)
    assert sup.parse(None, TODAY).entries == ()


def test_example_file_is_valid():
    s = sup.load(str(EXAMPLE), TODAY)
    assert len(s.entries) >= 2
