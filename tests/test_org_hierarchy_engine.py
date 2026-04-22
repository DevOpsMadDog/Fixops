"""Tests for OrgHierarchyEngine (GAP-005) — ALDECI.

Coverage: tree creation, BFS, inheritance at depth 1/2/3, move cycle-detect,
delete cascade/no-cascade, org_id tenant isolation, effective-policies union
correctness, idempotent attach, stats.
"""

from __future__ import annotations

import pytest

from core.org_hierarchy_engine import OrgHierarchyEngine


@pytest.fixture
def engine(tmp_path):
    return OrgHierarchyEngine(db_path=str(tmp_path / "org_hierarchy.db"))


def _tree3(engine, tenant="org1"):
    """Build a 3-level tree:

        root
         └── mid
              └── leaf
    """
    root = engine.create_org(tenant, "root")
    mid = engine.create_org(tenant, "mid", parent_org_id=root["id"])
    leaf = engine.create_org(tenant, "leaf", parent_org_id=mid["id"])
    return root, mid, leaf


# ---------------------------------------------------------------------------
# create_org — validation
# ---------------------------------------------------------------------------

def test_create_org_empty_tenant_raises(engine):
    with pytest.raises(ValueError, match="org_id"):
        engine.create_org("", "root")


def test_create_org_whitespace_tenant_raises(engine):
    with pytest.raises(ValueError, match="org_id"):
        engine.create_org("   ", "root")


def test_create_org_empty_name_raises(engine):
    with pytest.raises(ValueError, match="name"):
        engine.create_org("org1", "")


def test_create_org_whitespace_name_raises(engine):
    with pytest.raises(ValueError, match="name"):
        engine.create_org("org1", "   ")


def test_create_org_missing_parent_raises(engine):
    with pytest.raises(ValueError, match="parent_org_id"):
        engine.create_org("org1", "child", parent_org_id="does-not-exist")


def test_create_org_root_ok(engine):
    root = engine.create_org("org1", "root")
    assert root["name"] == "root"
    assert root["parent_org_id"] is None
    assert root["org_id"] == "org1"
    assert "id" in root
    assert "created_at" in root


def test_create_org_child_ok(engine):
    root = engine.create_org("org1", "root")
    child = engine.create_org("org1", "child", parent_org_id=root["id"])
    assert child["parent_org_id"] == root["id"]


def test_create_org_cross_tenant_parent_rejected(engine):
    r = engine.create_org("org1", "root")
    with pytest.raises(ValueError, match="parent_org_id"):
        engine.create_org("org2", "other-child", parent_org_id=r["id"])


# ---------------------------------------------------------------------------
# get_org / list_children — BFS
# ---------------------------------------------------------------------------

def test_get_org_missing_returns_none(engine):
    assert engine.get_org("org1", "missing") is None


def test_get_org_wrong_tenant_returns_none(engine):
    r = engine.create_org("org1", "root")
    assert engine.get_org("org2", r["id"]) is None


def test_list_children_empty_tree(engine):
    root = engine.create_org("org1", "root")
    assert engine.list_children("org1", root["id"]) == []


def test_list_children_missing_root_raises(engine):
    with pytest.raises(ValueError):
        engine.list_children("org1", "missing")


def test_list_children_invalid_depth(engine):
    r = engine.create_org("org1", "root")
    with pytest.raises(ValueError, match="depth"):
        engine.list_children("org1", r["id"], depth=0)
    with pytest.raises(ValueError, match="depth"):
        engine.list_children("org1", r["id"], depth=-1)


def test_list_children_depth_1(engine):
    root, mid, leaf = _tree3(engine)
    kids = engine.list_children("org1", root["id"], depth=1)
    ids = [k["id"] for k in kids]
    assert ids == [mid["id"]]
    assert kids[0]["depth"] == 1


def test_list_children_depth_2(engine):
    root, mid, leaf = _tree3(engine)
    kids = engine.list_children("org1", root["id"], depth=2)
    ids = [k["id"] for k in kids]
    assert mid["id"] in ids
    assert leaf["id"] in ids
    depth_by_id = {k["id"]: k["depth"] for k in kids}
    assert depth_by_id[mid["id"]] == 1
    assert depth_by_id[leaf["id"]] == 2


def test_list_children_depth_3_wide_tree(engine):
    # Build: root -> [a, b]; a -> [a1]; b -> [b1, b2]
    root = engine.create_org("org1", "root")
    a = engine.create_org("org1", "a", parent_org_id=root["id"])
    b = engine.create_org("org1", "b", parent_org_id=root["id"])
    a1 = engine.create_org("org1", "a1", parent_org_id=a["id"])
    b1 = engine.create_org("org1", "b1", parent_org_id=b["id"])
    b2 = engine.create_org("org1", "b2", parent_org_id=b["id"])

    kids = engine.list_children("org1", root["id"], depth=3)
    ids = {k["id"] for k in kids}
    assert ids == {a["id"], b["id"], a1["id"], b1["id"], b2["id"]}
    depth_by_id = {k["id"]: k["depth"] for k in kids}
    assert depth_by_id[a["id"]] == 1
    assert depth_by_id[b["id"]] == 1
    assert depth_by_id[a1["id"]] == 2
    assert depth_by_id[b1["id"]] == 2
    assert depth_by_id[b2["id"]] == 2


def test_list_children_depth_clamps_to_actual_tree(engine):
    root, mid, leaf = _tree3(engine)
    kids = engine.list_children("org1", root["id"], depth=50)
    assert len(kids) == 2


# ---------------------------------------------------------------------------
# get_ancestors
# ---------------------------------------------------------------------------

def test_get_ancestors_missing_node_raises(engine):
    with pytest.raises(ValueError):
        engine.get_ancestors("org1", "missing")


def test_get_ancestors_root_returns_empty(engine):
    root = engine.create_org("org1", "root")
    assert engine.get_ancestors("org1", root["id"]) == []


def test_get_ancestors_from_leaf(engine):
    root, mid, leaf = _tree3(engine)
    ancestors = engine.get_ancestors("org1", leaf["id"])
    assert [a["id"] for a in ancestors] == [mid["id"], root["id"]]


def test_get_ancestors_tenant_isolation(engine):
    r1 = engine.create_org("org1", "root1")
    r2 = engine.create_org("org2", "root2")
    engine.create_org("org2", "child2", parent_org_id=r2["id"])
    # asking in wrong tenant should raise
    with pytest.raises(ValueError):
        engine.get_ancestors("org1", r2["id"])


# ---------------------------------------------------------------------------
# move_org — cycle detection
# ---------------------------------------------------------------------------

def test_move_org_self_parent_rejected(engine):
    r = engine.create_org("org1", "r")
    with pytest.raises(ValueError, match="itself"):
        engine.move_org("org1", r["id"], r["id"])


def test_move_org_to_descendant_rejected(engine):
    root, mid, leaf = _tree3(engine)
    with pytest.raises(ValueError, match="cycle"):
        engine.move_org("org1", root["id"], leaf["id"])


def test_move_org_to_grandchild_rejected(engine):
    root, mid, leaf = _tree3(engine)
    with pytest.raises(ValueError, match="cycle"):
        engine.move_org("org1", root["id"], mid["id"])


def test_move_org_to_sibling_ok(engine):
    root = engine.create_org("org1", "root")
    a = engine.create_org("org1", "a", parent_org_id=root["id"])
    b = engine.create_org("org1", "b", parent_org_id=root["id"])
    moved = engine.move_org("org1", a["id"], b["id"])
    assert moved["parent_org_id"] == b["id"]


def test_move_org_promote_to_root(engine):
    root, mid, leaf = _tree3(engine)
    promoted = engine.move_org("org1", mid["id"], None)
    assert promoted["parent_org_id"] is None


def test_move_org_missing_new_parent_raises(engine):
    r = engine.create_org("org1", "r")
    with pytest.raises(ValueError, match="new_parent_id"):
        engine.move_org("org1", r["id"], "does-not-exist")


def test_move_org_missing_node_raises(engine):
    with pytest.raises(ValueError):
        engine.move_org("org1", "missing", None)


# ---------------------------------------------------------------------------
# delete_org — cascade / no-cascade
# ---------------------------------------------------------------------------

def test_delete_leaf_no_cascade_ok(engine):
    root, mid, leaf = _tree3(engine)
    res = engine.delete_org("org1", leaf["id"])
    assert res["deleted"] == 1
    assert engine.get_org("org1", leaf["id"]) is None
    assert engine.get_org("org1", mid["id"]) is not None


def test_delete_parent_no_cascade_rejected(engine):
    root, mid, leaf = _tree3(engine)
    with pytest.raises(ValueError, match="cascade"):
        engine.delete_org("org1", mid["id"], cascade=False)


def test_delete_parent_with_cascade(engine):
    root, mid, leaf = _tree3(engine)
    res = engine.delete_org("org1", mid["id"], cascade=True)
    assert res["deleted"] == 2
    assert engine.get_org("org1", mid["id"]) is None
    assert engine.get_org("org1", leaf["id"]) is None
    assert engine.get_org("org1", root["id"]) is not None


def test_delete_root_cascade_removes_everything(engine):
    root, mid, leaf = _tree3(engine)
    res = engine.delete_org("org1", root["id"], cascade=True)
    assert res["deleted"] == 3
    assert engine.stats("org1")["total_orgs"] == 0


def test_delete_cascade_removes_policies_and_waivers(engine):
    root, mid, leaf = _tree3(engine)
    engine.attach_policy("org1", mid["id"], "pol-X")
    engine.attach_waiver("org1", leaf["id"], "wav-Y")
    engine.delete_org("org1", root["id"], cascade=True)
    stats = engine.stats("org1")
    assert stats["total_policies"] == 0
    assert stats["total_waivers"] == 0


def test_delete_missing_raises(engine):
    with pytest.raises(ValueError):
        engine.delete_org("org1", "missing")


# ---------------------------------------------------------------------------
# attach_policy / attach_waiver — validation + idempotency
# ---------------------------------------------------------------------------

def test_attach_policy_requires_ref(engine):
    r = engine.create_org("org1", "r")
    with pytest.raises(ValueError, match="policy_ref"):
        engine.attach_policy("org1", r["id"], "")


def test_attach_policy_missing_org_raises(engine):
    with pytest.raises(ValueError):
        engine.attach_policy("org1", "missing", "pol-1")


def test_attach_policy_ok(engine):
    r = engine.create_org("org1", "r")
    rec = engine.attach_policy("org1", r["id"], "pol-allow-gpl")
    assert rec["policy_ref"] == "pol-allow-gpl"
    assert rec["inherited_from"] is None


def test_attach_policy_idempotent(engine):
    r = engine.create_org("org1", "r")
    a = engine.attach_policy("org1", r["id"], "pol-1")
    b = engine.attach_policy("org1", r["id"], "pol-1")
    assert a["id"] == b["id"]


def test_attach_waiver_requires_ref(engine):
    r = engine.create_org("org1", "r")
    with pytest.raises(ValueError, match="waiver_ref"):
        engine.attach_waiver("org1", r["id"], "")


def test_attach_waiver_idempotent(engine):
    r = engine.create_org("org1", "r")
    a = engine.attach_waiver("org1", r["id"], "wav-1")
    b = engine.attach_waiver("org1", r["id"], "wav-1")
    assert a["id"] == b["id"]


# ---------------------------------------------------------------------------
# effective_policies — depth 1/2/3 inheritance union
# ---------------------------------------------------------------------------

def test_effective_policies_own_only(engine):
    r = engine.create_org("org1", "r")
    engine.attach_policy("org1", r["id"], "pol-own")
    eff = engine.effective_policies("org1", r["id"])
    assert len(eff) == 1
    assert eff[0]["policy_ref"] == "pol-own"
    assert eff[0]["inherited_from"] is None


def test_effective_policies_depth_1_inherit(engine):
    root = engine.create_org("org1", "root")
    child = engine.create_org("org1", "child", parent_org_id=root["id"])
    engine.attach_policy("org1", root["id"], "pol-root")
    eff = engine.effective_policies("org1", child["id"])
    assert [p["policy_ref"] for p in eff] == ["pol-root"]
    assert eff[0]["inherited_from"] == root["id"]


def test_effective_policies_depth_2_inherit(engine):
    root, mid, leaf = _tree3(engine)
    engine.attach_policy("org1", root["id"], "pol-root")
    eff = engine.effective_policies("org1", leaf["id"])
    assert len(eff) == 1
    assert eff[0]["policy_ref"] == "pol-root"
    assert eff[0]["inherited_from"] == root["id"]


def test_effective_policies_depth_3_union(engine):
    root = engine.create_org("org1", "root")
    mid = engine.create_org("org1", "mid", parent_org_id=root["id"])
    leaf = engine.create_org("org1", "leaf", parent_org_id=mid["id"])
    engine.attach_policy("org1", root["id"], "pol-root")
    engine.attach_policy("org1", mid["id"], "pol-mid")
    engine.attach_policy("org1", leaf["id"], "pol-leaf")
    eff = engine.effective_policies("org1", leaf["id"])
    refs = {p["policy_ref"]: p for p in eff}
    assert set(refs.keys()) == {"pol-root", "pol-mid", "pol-leaf"}
    assert refs["pol-leaf"]["inherited_from"] is None
    assert refs["pol-mid"]["inherited_from"] == mid["id"]
    assert refs["pol-root"]["inherited_from"] == root["id"]


def test_effective_policies_closer_ancestor_wins(engine):
    """If a policy_ref is attached to both mid and root, mid wins."""
    root, mid, leaf = _tree3(engine)
    engine.attach_policy("org1", root["id"], "pol-shared")
    engine.attach_policy("org1", mid["id"], "pol-shared")
    eff = engine.effective_policies("org1", leaf["id"])
    assert len(eff) == 1
    assert eff[0]["inherited_from"] == mid["id"]


def test_effective_waivers_depth_3(engine):
    root = engine.create_org("org1", "root")
    mid = engine.create_org("org1", "mid", parent_org_id=root["id"])
    leaf = engine.create_org("org1", "leaf", parent_org_id=mid["id"])
    engine.attach_waiver("org1", root["id"], "wav-root")
    engine.attach_waiver("org1", mid["id"], "wav-mid")
    eff = engine.effective_waivers("org1", leaf["id"])
    refs = {p["waiver_ref"]: p for p in eff}
    assert set(refs.keys()) == {"wav-root", "wav-mid"}
    assert refs["wav-mid"]["inherited_from"] == mid["id"]
    assert refs["wav-root"]["inherited_from"] == root["id"]


def test_effective_policies_missing_node_raises(engine):
    with pytest.raises(ValueError):
        engine.effective_policies("org1", "missing")


def test_effective_after_move_rebuilds_inheritance(engine):
    """After moving an org, effective resolves against the new parent chain."""
    root_a = engine.create_org("org1", "a-root")
    root_b = engine.create_org("org1", "b-root")
    engine.attach_policy("org1", root_a["id"], "pol-a")
    engine.attach_policy("org1", root_b["id"], "pol-b")
    child = engine.create_org("org1", "child", parent_org_id=root_a["id"])
    eff1 = engine.effective_policies("org1", child["id"])
    assert [p["policy_ref"] for p in eff1] == ["pol-a"]

    engine.move_org("org1", child["id"], root_b["id"])
    eff2 = engine.effective_policies("org1", child["id"])
    assert [p["policy_ref"] for p in eff2] == ["pol-b"]


# ---------------------------------------------------------------------------
# org_id tenant isolation
# ---------------------------------------------------------------------------

def test_tenant_isolation_children(engine):
    r1 = engine.create_org("org1", "root1")
    engine.create_org("org1", "c1", parent_org_id=r1["id"])
    r2 = engine.create_org("org2", "root2")
    engine.create_org("org2", "c2", parent_org_id=r2["id"])
    assert len(engine.list_children("org1", r1["id"])) == 1
    assert len(engine.list_children("org2", r2["id"])) == 1


def test_tenant_isolation_policies(engine):
    r1 = engine.create_org("org1", "r1")
    r2 = engine.create_org("org2", "r2")
    engine.attach_policy("org1", r1["id"], "pol-tenant-1")
    engine.attach_policy("org2", r2["id"], "pol-tenant-2")
    eff1 = engine.effective_policies("org1", r1["id"])
    eff2 = engine.effective_policies("org2", r2["id"])
    assert [p["policy_ref"] for p in eff1] == ["pol-tenant-1"]
    assert [p["policy_ref"] for p in eff2] == ["pol-tenant-2"]


def test_tenant_isolation_move_rejects_cross_tenant(engine):
    r1 = engine.create_org("org1", "r1")
    r2 = engine.create_org("org2", "r2")
    # moving under a parent that lives in another tenant is rejected
    with pytest.raises(ValueError):
        engine.move_org("org1", r1["id"], r2["id"])


def test_tenant_isolation_delete(engine):
    r1 = engine.create_org("org1", "r1")
    r2 = engine.create_org("org2", "r2")
    engine.delete_org("org1", r1["id"])
    assert engine.get_org("org1", r1["id"]) is None
    assert engine.get_org("org2", r2["id"]) is not None


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------

def test_stats_platform(engine):
    engine.create_org("org1", "a")
    engine.create_org("org2", "b")
    s = engine.stats()
    assert s["tenants"] == 2
    assert s["total_orgs"] == 2
    assert s["total_roots"] == 2
    assert s["total_policies"] == 0
    assert s["total_waivers"] == 0


def test_stats_per_tenant(engine):
    root, mid, leaf = _tree3(engine)
    engine.attach_policy("org1", root["id"], "pol-1")
    engine.attach_waiver("org1", leaf["id"], "wav-1")
    s = engine.stats("org1")
    assert s["org_id"] == "org1"
    assert s["total_orgs"] == 3
    assert s["total_roots"] == 1
    assert s["total_policies"] == 1
    assert s["total_waivers"] == 1


def test_stats_unknown_tenant(engine):
    s = engine.stats("never-existed")
    assert s["total_orgs"] == 0
    assert s["total_roots"] == 0
