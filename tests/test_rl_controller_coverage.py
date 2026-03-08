"""Tests for RL controller — Q-learning primitives and singleton management."""
import asyncio
import pytest

from core.services.enterprise.rl_controller import (
    Experience,
    ReinforcementLearningController,
    DEFAULT_ALPHA,
    DEFAULT_GAMMA,
)


class TestExperience:
    def test_create_basic(self):
        exp = Experience(state="vulnerable", action="patch", reward=1.0, next_state="patched")
        assert exp.state == "vulnerable"
        assert exp.action == "patch"
        assert exp.reward == 1.0
        assert exp.next_state == "patched"

    def test_none_next_state(self):
        exp = Experience(state="exploited", action="isolate", reward=0.5, next_state=None)
        assert exp.next_state is None

    def test_negative_reward(self):
        exp = Experience(state="secure", action="ignore", reward=-1.0, next_state="vulnerable")
        assert exp.reward == -1.0


class TestConstants:
    def test_default_alpha(self):
        assert DEFAULT_ALPHA == 0.3

    def test_default_gamma(self):
        assert DEFAULT_GAMMA == 0.8


class TestReinforcementLearningController:
    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        ReinforcementLearningController.reset_instance()
        yield
        ReinforcementLearningController.reset_instance()

    def test_init_defaults(self):
        ctrl = ReinforcementLearningController()
        assert ctrl.alpha == DEFAULT_ALPHA
        assert ctrl.gamma == DEFAULT_GAMMA

    def test_init_custom_params(self):
        ctrl = ReinforcementLearningController(alpha=0.1, gamma=0.9)
        assert ctrl.alpha == 0.1
        assert ctrl.gamma == 0.9

    def test_singleton_pattern(self):
        c1 = ReinforcementLearningController.get_instance()
        c2 = ReinforcementLearningController.get_instance()
        assert c1 is c2

    def test_singleton_reset(self):
        c1 = ReinforcementLearningController.get_instance()
        ReinforcementLearningController.reset_instance()
        c2 = ReinforcementLearningController.get_instance()
        assert c1 is not c2

    def test_empty_q_table(self):
        ctrl = ReinforcementLearningController()
        assert ctrl._q_table == {}

    def test_recommend_action_empty_returns_none(self):
        ctrl = ReinforcementLearningController()
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                ctrl.recommend_action("tenant-1", "unknown_state")
            )
        finally:
            loop.close()
        assert result is None

    def test_record_and_recommend(self):
        ctrl = ReinforcementLearningController()
        loop = asyncio.new_event_loop()
        try:
            exp = Experience(state="vulnerable", action="patch", reward=1.0, next_state="patched")
            loop.run_until_complete(ctrl.record_experience("tenant-1", exp))
            result = loop.run_until_complete(ctrl.recommend_action("tenant-1", "vulnerable"))
        finally:
            loop.close()
        assert result == "patch"

    def test_multiple_actions_best_selected(self):
        ctrl = ReinforcementLearningController()
        loop = asyncio.new_event_loop()
        try:
            # Record low-reward action
            exp1 = Experience(state="vuln", action="monitor", reward=0.1, next_state=None)
            loop.run_until_complete(ctrl.record_experience("t1", exp1))
            # Record high-reward action
            exp2 = Experience(state="vuln", action="patch", reward=1.0, next_state=None)
            loop.run_until_complete(ctrl.record_experience("t1", exp2))
            result = loop.run_until_complete(ctrl.recommend_action("t1", "vuln"))
        finally:
            loop.close()
        assert result == "patch"
