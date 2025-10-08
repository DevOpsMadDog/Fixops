from __future__ import annotations

from src.services.marketplace import get_recommendations


def test_marketplace_returns_pack_for_ac2() -> None:
    recs = get_recommendations(["ISO27001:AC-2"])
    assert recs
    assert recs[0]["pack_id"] == "iso-ac2-lp"
    assert recs[0]["link"].endswith("/iso/ac-2")
