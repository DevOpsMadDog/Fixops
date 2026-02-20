"""Lightweight reinforcement learning controller for decision automation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import structlog
from core.services.enterprise.cache_service import CacheService

logger = structlog.get_logger()


DEFAULT_ALPHA = 0.3
DEFAULT_GAMMA = 0.8


@dataclass
class Experience:
    """Captured experience tuple for the RL controller."""

    state: str
    action: str
    reward: float
    next_state: Optional[str]


class ReinforcementLearningController:
    """Simple tabular Q-learning controller used for Part 3 alignment."""

    _instance: "ReinforcementLearningController" | None = None

    def __init__(
        self, *, alpha: float = DEFAULT_ALPHA, gamma: float = DEFAULT_GAMMA
    ) -> None:
        self.alpha = alpha
        self.gamma = gamma
        self.cache = CacheService.get_instance()
        self._q_table: Dict[Tuple[str, str], Dict[str, float]] = {}

    # ------------------------------------------------------------------
    # Singleton helpers
    # ------------------------------------------------------------------
    @classmethod
    def get_instance(cls) -> "ReinforcementLearningController":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        cls._instance = None

    # ------------------------------------------------------------------
    # Q-learning primitives
    # ------------------------------------------------------------------
    async def record_experience(
        self,
        tenant: str,
        experience: Experience,
    ) -> None:
        """Update the Q-table using the provided experience tuple."""

        state_key = (tenant, experience.state)
        q_values = await self._load_state(state_key)
        current_value = q_values.get(experience.action, 0.0)

        future_estimate = 0.0
        if experience.next_state is not None:
            next_state_values = await self._load_state((tenant, experience.next_state))
            future_estimate = (
                max(next_state_values.values()) if next_state_values else 0.0
            )

        updated_value = (1 - self.alpha) * current_value + self.alpha * (
            experience.reward + self.gamma * future_estimate
        )

        q_values[experience.action] = round(updated_value, 4)
        await self._persist_state(state_key, q_values)

        logger.debug(
            "RL experience recorded",
            tenant=tenant,
            state=experience.state,
            action=experience.action,
            reward=experience.reward,
            next_state=experience.next_state,
            updated_value=updated_value,
        )

    async def recommend_action(self, tenant: str, state: str) -> Optional[str]:
        """Return the action with the highest Q-value for the given state."""

        q_values = await self._load_state((tenant, state))
        if not q_values:
            return None

        best_action = max(q_values.items(), key=lambda item: item[1])[0]
        logger.debug(
            "RL recommended action", tenant=tenant, state=state, action=best_action
        )
        return best_action

    async def export_policy(self) -> Dict[str, Dict[str, float]]:
        """Return the entire Q-table for observability or debugging."""

        return dict(self._q_table)

    # ------------------------------------------------------------------
    # Internal cache helpers
    # ------------------------------------------------------------------
    async def _load_state(self, key: Tuple[str, str]) -> Dict[str, float]:
        if key in self._q_table:
            return self._q_table[key]

        cache_key = self._cache_key(key)
        cached = await self.cache.get(cache_key)
        if isinstance(cached, dict):
            self._q_table[key] = {
                str(action): float(value) for action, value in cached.items()
            }
            return self._q_table[key]

        self._q_table[key] = {}
        return self._q_table[key]

    async def _persist_state(
        self, key: Tuple[str, str], values: Dict[str, float]
    ) -> None:
        cache_key = self._cache_key(key)
        await self.cache.set(cache_key, values, ttl=24 * 60 * 60)  # cache for a day
        self._q_table[key] = dict(values)

    @staticmethod
    def _cache_key(key: Tuple[str, str]) -> str:
        tenant, state = key
        return f"rl:{tenant}:{state}"


__all__ = ["Experience", "ReinforcementLearningController"]
