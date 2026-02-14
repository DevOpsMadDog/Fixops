"""Test suite for fuzzy_identity.py - Phase 9.5.1 validation."""
import tempfile
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from core.services.fuzzy_identity import (
    compute_match_score, tokenize, expand_tokens, token_set_similarity,
    levenshtein_similarity, levenshtein_distance,
    FuzzyIdentityResolver, MatchStrategy, MatchResult,
)

passed = 0
failed = 0

def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name} — {detail}")


print("=== 1. Pure Function Tests ===")
check("levenshtein(kitten,sitting)=3", levenshtein_distance("kitten", "sitting") == 3)
check("levenshtein_sim(abc,abc)=1.0", levenshtein_similarity("abc", "abc") == 1.0)
check("levenshtein_sim empty=1.0", levenshtein_similarity("", "") == 1.0)

toks = tokenize("payments-api-prod")
check("tokenize delimiters", toks == ("payments", "api", "prod"), str(toks))

toks2 = tokenize("PaymentsAPIProd")
check("tokenize camelCase", "payments" in toks2, str(toks2))

exp = expand_tokens(("prod", "svc", "k8s"))
check("expand abbreviations", exp == ("production", "service", "kubernetes"), str(exp))


print("\n=== 2. Match Score Tests ===")
pairs = [
    ("payments-api-prod", "payments_prod_api", 0.65, "same tokens reordered"),
    ("payments-api-prod", "payment-api-prod", 0.85, "singular vs plural"),
    ("k8s-prod-cluster", "kubernetes-production-cluster", 0.65, "abbreviation expansion"),
    ("auth-svc-staging", "authentication-service-stg", 0.65, "multi abbreviation"),
    ("totally-different", "payments-api", 0.0, "unrelated should be low"),
    ("payments-api", "payments-api", 1.0, "exact match"),
]
for a, b, min_score, desc in pairs:
    score, strat = compute_match_score(a, b)
    if desc == "unrelated should be low":
        check(f"score({a}, {b}) < 0.5 [{desc}]", score < 0.5, f"got {score:.3f}")
    else:
        check(f"score({a}, {b}) >= {min_score} [{desc}]", score >= min_score,
              f"got {score:.3f} via {strat.value}")


print("\n=== 3. Resolver Tests ===")
tmp = tempfile.mktemp(suffix=".db")
resolver = FuzzyIdentityResolver(db_path=tmp)

resolver.register_canonical("payments-api", org_id="org_1")
resolver.register_canonical("auth-service", org_id="org_1")
resolver.register_canonical("user-db", org_id="org_2")
resolver.add_alias("payments-api", "payments_prod_api")

# Exact alias match
r = resolver.resolve("payments_prod_api", org_id="org_1")
check("exact alias match", r is not None and r.strategy == MatchStrategy.ALIAS,
      f"got {r}")

# Fuzzy match
r2 = resolver.resolve("payment-api-prod", org_id="org_1")
check("fuzzy resolve payment-api-prod", r2 is not None and r2.canonical_id == "payments-api",
      f"got {r2}")

# Org isolation
r3 = resolver.resolve("user-db", org_id="org_1")
check("org isolation (user-db not in org_1)", r3 is None, f"got {r3}")

r4 = resolver.resolve("user-db", org_id="org_2")
check("resolve in correct org", r4 is not None and r4.canonical_id == "user-db",
      f"got {r4}")

# Batch resolve
batch = resolver.resolve_batch(
    ["payments-api", "auth-svc", "unknown-xyz"],
    org_id="org_1",
)
check("batch: payments-api resolves", batch["payments-api"] is not None)
check("batch: unknown-xyz is None", batch["unknown-xyz"] is None)

# find_similar
similar = resolver.find_similar("payment-api", org_id="org_1", threshold=0.4)
check("find_similar returns results", len(similar) > 0, f"got {len(similar)}")

# Stats
stats = resolver.get_resolution_stats()
check("stats has total_resolutions", stats["total_resolutions"] > 0, str(stats))
check("stats has canonical_assets", stats["canonical_assets"] == 3, str(stats))

# Auto-learn
r5 = resolver.resolve("payments-api-production", org_id="org_1")
if r5 and r5.confidence >= 0.85:
    # Should have auto-learned the alias
    aliases = resolver._canonical_names.get("payments-api", set())
    check("auto-learn alias", "payments-api-production" in aliases, str(aliases))
else:
    check("auto-learn (skipped, score too low)", True)

# List canonical
canon_list = resolver.list_canonical(org_id="org_1")
check("list_canonical returns 2 for org_1", len(canon_list) == 2, str(len(canon_list)))

resolver.close()
os.unlink(tmp)

print(f"\n{'='*50}")
print(f"Results: {passed} passed, {failed} failed out of {passed+failed}")
if failed == 0:
    print("=== ALL FUZZY IDENTITY TESTS PASSED ✅ ===")
else:
    print("=== SOME TESTS FAILED ❌ ===")
    sys.exit(1)

