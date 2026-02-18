"""Phase 1 verification: Knowledge Brain + Event Bus wiring in all routers.

Each suite's api/ dir is imported separately since suite-api/apps/api/__init__.py
makes it a regular package that blocks namespace merging with other suites.
"""
import importlib
import os
import sys

root = os.path.dirname(os.path.abspath(__file__))
ok = 0
fail = 0


def suite_import(suite_path, module_name):
    """Import a module from a specific suite by temporarily adjusting sys.path."""
    p = os.path.join(root, suite_path)
    inserted = False
    if p not in sys.path:
        sys.path.insert(0, p)
        inserted = True
    try:
        # Force fresh import (namespace packages can cache old paths)
        if module_name in sys.modules:
            return sys.modules[module_name]
        return importlib.import_module(module_name)
    finally:
        pass  # leave path for dependent imports


def check(label, fn):
    global ok, fail
    try:
        result = fn()
        print(f"  OK: {label} -> {result}")
        ok += 1
    except Exception as e:
        print(f"  FAIL: {label} -> {e}")
        fail += 1


# Set up core path first (needed by all routers for brain/event_bus)
for sp in [
    "suite-core",
    "suite-api",
    "suite-api/apps",
    "suite-attack",
    "suite-evidence-risk",
    "suite-feeds",
    "suite-integrations",
]:
    p = os.path.join(root, sp)
    if p not in sys.path:
        sys.path.insert(0, p)

print("=== Core Components (suite-core) ===")
check(
    "knowledge_brain",
    lambda: f"{len(list(__import__('core.knowledge_brain', fromlist=['EntityType']).EntityType))} entity types",
)
check(
    "event_bus",
    lambda: f"{len(list(__import__('core.event_bus', fromlist=['EventType']).EventType))} event types",
)

# Brain router is in suite-core/api/ - need to import without conflicting with suite-api/apps/api/
print("\n=== Brain Router (suite-core/api/) ===")
try:
    spec = importlib.util.spec_from_file_location(
        "brain_router", os.path.join(root, "suite-core/api/brain_router.py")
    )
    brain_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(brain_mod)
    print(f"  OK: brain_router -> {len(brain_mod.router.routes)} routes")
    ok += 1
except Exception as e:
    print(f"  FAIL: brain_router -> {e}")
    fail += 1

print("\n=== Routers with _HAS_BRAIN ===")

# Each router mapped to its suite path and file
routers = [
    ("copilot_router", "suite-core/api/copilot_router.py"),
    ("remediation_router", "suite-api/apps/api/remediation_router.py"),
    ("evidence_router", "suite-evidence-risk/api/evidence_router.py"),
    ("risk_router", "suite-evidence-risk/api/risk_router.py"),
    ("micro_pentest_router", "suite-attack/api/micro_pentest_router.py"),
    ("vuln_discovery_router", "suite-attack/api/vuln_discovery_router.py"),
    ("secrets_router", "suite-attack/api/secrets_router.py"),
    ("feeds_router", "suite-feeds/api/feeds_router.py"),
]

for name, filepath in routers:

    def _check(n=name, fp=filepath):
        full = os.path.join(root, fp)
        spec = importlib.util.spec_from_file_location(n, full)
        mod = importlib.util.module_from_spec(spec)
        # Python 3.14 @dataclass requires module in sys.modules
        sys.modules[n] = mod
        spec.loader.exec_module(mod)
        has_brain = getattr(mod, "_HAS_BRAIN", "MISSING")
        return f"{len(mod.router.routes)} routes, _HAS_BRAIN={has_brain}"

    check(name, _check)

print("\n=== Integration Test: Brain CRUD ===")
try:
    from core.knowledge_brain import (
        EdgeType,
        EntityType,
        GraphEdge,
        GraphNode,
        get_brain,
    )

    brain = get_brain()
    brain.upsert_node(
        GraphNode(
            node_id="v-cve-1",
            node_type=EntityType.CVE,
            org_id="v-org",
            properties={"severity": "critical"},
        )
    )
    brain.upsert_node(
        GraphNode(
            node_id="v-find-1",
            node_type=EntityType.FINDING,
            org_id="v-org",
            properties={"title": "Test"},
        )
    )
    brain.add_edge(
        GraphEdge(
            source_id="v-cve-1", target_id="v-find-1", edge_type=EdgeType.EXPLOITS
        )
    )
    stats = brain.stats()
    print(f"  Nodes: {stats['total_nodes']}, Edges: {stats['total_edges']}")
    brain.delete_node("v-cve-1")
    brain.delete_node("v-find-1")
    print("  CRUD: OK")
    ok += 1
except Exception as e:
    print(f"  CRUD FAIL: {e}")
    fail += 1

print(f"\n=== Results: {ok} OK, {fail} FAIL ===")
sys.exit(1 if fail > 0 else 0)
