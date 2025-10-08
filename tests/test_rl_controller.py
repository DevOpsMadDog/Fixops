from __future__ import annotations

import asyncio

from src.services.rl_controller import Experience, ReinforcementLearningController


def test_rl_controller_updates_q_values() -> None:
    async def _run() -> None:
        ReinforcementLearningController.reset_instance()
        controller = ReinforcementLearningController.get_instance()

        await controller.record_experience(
            "tenant-a",
            Experience(state="prod:2", action="ALLOW", reward=1.0, next_state=None),
        )
        await controller.record_experience(
            "tenant-a",
            Experience(state="prod:2", action="BLOCK", reward=-0.5, next_state=None),
        )

        policy = await controller.export_policy()
        q_values = policy.get(("tenant-a", "prod:2"))
        assert q_values is not None
        assert q_values["ALLOW"] > 0
        assert q_values["BLOCK"] < 0

        recommendation = await controller.recommend_action("tenant-a", "prod:2")
        assert recommendation == "ALLOW"

    asyncio.run(_run())
