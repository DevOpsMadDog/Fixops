"""Utilities for building Markov transition probabilities for vulnerabilities."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import Dict, Iterable, List, Sequence

import numpy as np
from mchmm import MarkovChain


class TimelineEventType(str, Enum):
    """Types of events that can appear in a vulnerability timeline."""

    DISCLOSURE = "disclosure"
    EXPLOIT_POC_RELEASED = "exploit_poc_released"
    EXPLOIT_CONFIRMED = "exploit_confirmed"
    PATCH_RELEASED = "patch_released"


@dataclass(frozen=True)
class TimelineEvent:
    """Represents a dated event in a vulnerability lifecycle."""

    occurred: date
    event_type: TimelineEventType


@dataclass
class VulnerabilityRecord:
    """Container for the context needed to build Markov transitions."""

    cve_id: str
    timeline: Sequence[TimelineEvent]
    epss_score: float
    kev: bool = False


class MarkovState(str, Enum):
    """Canonical states used for the Markov transition matrix."""

    DISCLOSED = "disclosed"
    WEAPONIZED = "weaponized"
    EXPLOITED = "exploited"
    MITIGATED = "mitigated"


@dataclass
class MarkovStateProbabilities:
    """Result of running the transition builder."""

    states: List[MarkovState]
    transition_matrix: np.ndarray
    state_sequences: Dict[str, List[MarkovState]]
    markov_chain: MarkovChain
    state_index: Dict[MarkovState, int] = field(init=False)

    def __post_init__(self) -> None:
        self.states = list(self.states)
        self.transition_matrix = np.array(self.transition_matrix, dtype=float)
        self.state_index = {state: idx for idx, state in enumerate(self.states)}

    def probability(self, from_state: MarkovState, to_state: MarkovState) -> float:
        """Convenience helper to read the probability of a transition."""

        return float(
            self.transition_matrix[self.state_index[from_state], self.state_index[to_state]]
        )


class MarkovTransitionBuilder:
    """Constructs a Markov transition matrix from vulnerability timelines."""

    def __init__(self, epss_high_risk_threshold: float = 0.7) -> None:
        self.epss_high_risk_threshold = epss_high_risk_threshold
        self._states_order = [
            MarkovState.DISCLOSED,
            MarkovState.WEAPONIZED,
            MarkovState.EXPLOITED,
            MarkovState.MITIGATED,
        ]

    def build(self, records: Iterable[VulnerabilityRecord]) -> MarkovStateProbabilities:
        """Construct a Markov chain from vulnerability records."""

        sequences: Dict[str, List[MarkovState]] = {}
        for record in records:
            sequence = self._derive_sequence(record)
            if len(sequence) <= 1:
                # A single state does not add any new information; skip.
                continue
            sequences[record.cve_id] = sequence

        transition_probs = self._compute_transition_matrix(sequences.values())
        markov_chain = MarkovChain(
            states=[state.value for state in self._states_order],
            obs_p=transition_probs,
        )
        return MarkovStateProbabilities(
            states=self._states_order,
            transition_matrix=transition_probs,
            state_sequences=sequences,
            markov_chain=markov_chain,
        )

    def _derive_sequence(self, record: VulnerabilityRecord) -> List[MarkovState]:
        timeline = sorted(record.timeline, key=lambda event: event.occurred)
        sequence: List[MarkovState] = []

        def append_state(state: MarkovState) -> None:
            if not sequence or sequence[-1] != state:
                sequence.append(state)

        append_state(MarkovState.DISCLOSED)

        # EPSS and KEV directly influence the risk state ordering.
        if record.epss_score >= self.epss_high_risk_threshold:
            append_state(MarkovState.WEAPONIZED)
        if record.kev:
            append_state(MarkovState.WEAPONIZED)
            append_state(MarkovState.EXPLOITED)

        for event in timeline:
            if event.event_type == TimelineEventType.DISCLOSURE:
                # The disclosure state is our baseline; we do not transition back to it.
                continue
            elif event.event_type == TimelineEventType.EXPLOIT_POC_RELEASED:
                append_state(MarkovState.WEAPONIZED)
            elif event.event_type == TimelineEventType.EXPLOIT_CONFIRMED:
                append_state(MarkovState.EXPLOITED)
            elif event.event_type == TimelineEventType.PATCH_RELEASED:
                # Once mitigation happens we consider the vulnerability stabilized.
                append_state(MarkovState.MITIGATED)

        return sequence

    def _compute_transition_matrix(
        self, sequences: Iterable[Sequence[MarkovState]]
    ) -> np.ndarray:
        state_indices = {state: idx for idx, state in enumerate(self._states_order)}
        counts = np.zeros((len(self._states_order), len(self._states_order)), dtype=float)

        for sequence in sequences:
            for current, nxt in zip(sequence, sequence[1:]):
                counts[state_indices[current], state_indices[nxt]] += 1

        return self._normalize(counts)

    @staticmethod
    def _normalize(counts: np.ndarray) -> np.ndarray:
        probs = np.zeros_like(counts, dtype=float)
        for idx, row in enumerate(counts):
            total = row.sum()
            if total == 0:
                probs[idx, idx] = 1.0
            else:
                probs[idx, :] = row / total
        return probs
