"""Bayesian network inference for security risk assessment."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


def update_probabilities(
    components: List[Dict[str, Any]], network: Dict[str, Any]
) -> Dict[str, Dict[str, float]]:
    """Update probabilities for components using Bayesian inference.

    Args:
        components: List of component dictionaries with optional observed_state
        network: Bayesian network definition with nodes and CPTs

    Returns:
        Dictionary mapping component IDs to state probabilities
    """
    nodes = network.get("nodes", {})
    posteriors: Dict[str, Dict[str, float]] = {}

    # Build a mapping of component IDs to their observed states
    observed: Dict[str, str] = {}
    for component in components:
        comp_id = component.get("id")
        if comp_id and "observed_state" in component:
            observed[comp_id] = component["observed_state"]

    # Process nodes in topological order (parents before children)
    # For simplicity, we assume the nodes dict is already in topological order
    for node_id, node_def in nodes.items():
        states = node_def.get("states", [])
        parents = node_def.get("parents", [])
        cpt = node_def.get("cpt", [])

        if node_id in observed:
            # If observed, set probability to 1 for observed state, 0 for others
            posteriors[node_id] = {
                state: 1.0 if state == observed[node_id] else 0.0 for state in states
            }
        elif not parents:
            # Root node with no parents - use prior probabilities
            if isinstance(cpt, list):
                posteriors[node_id] = {state: prob for state, prob in zip(states, cpt)}
            else:
                # Default uniform distribution
                posteriors[node_id] = {state: 1.0 / len(states) for state in states}
        else:
            # Node with parents - compute posterior using parent posteriors
            posteriors[node_id] = _compute_posterior(
                node_id, states, parents, cpt, posteriors
            )

    return posteriors


def _compute_posterior(
    node_id: str,
    states: List[str],
    parents: List[str],
    cpt: Dict[Tuple[str, ...], List[float]],
    posteriors: Dict[str, Dict[str, float]],
) -> Dict[str, float]:
    """Compute posterior probabilities for a node given parent posteriors.

    Args:
        node_id: ID of the node
        states: List of possible states for this node
        parents: List of parent node IDs
        cpt: Conditional probability table
        posteriors: Current posteriors for all processed nodes

    Returns:
        Dictionary mapping states to probabilities
    """
    result = {state: 0.0 for state in states}

    # Get all possible parent state combinations
    parent_states_list = [list(posteriors[p].keys()) for p in parents]

    def get_combinations(
        states_list: List[List[str]], index: int = 0
    ) -> List[Tuple[str, ...]]:
        if index >= len(states_list):
            return [()]
        rest = get_combinations(states_list, index + 1)
        return [(s,) + r for s in states_list[index] for r in rest]

    combinations = get_combinations(parent_states_list)

    for parent_combo in combinations:
        # Calculate probability of this parent combination
        combo_prob = 1.0
        for i, parent_id in enumerate(parents):
            parent_state = parent_combo[i]
            combo_prob *= posteriors[parent_id].get(parent_state, 0.0)

        if combo_prob > 0:
            # Get conditional probabilities for this parent combination
            cond_probs = cpt.get(parent_combo, [1.0 / len(states)] * len(states))
            for state, cond_prob in zip(states, cond_probs):
                result[state] += combo_prob * cond_prob

    return result


def attach_component_posterior(
    components: List[Dict[str, Any]], posteriors: Dict[str, Dict[str, float]]
) -> List[Dict[str, Any]]:
    """Attach posterior probabilities to components.

    Args:
        components: List of component dictionaries
        posteriors: Dictionary mapping component IDs to state probabilities

    Returns:
        New list of components with posterior field added (does not modify originals)
    """
    result = []
    for component in components:
        comp_id = component.get("id")
        new_component = dict(component)

        # Only attach posterior if not observed
        if comp_id and comp_id in posteriors and "observed_state" not in component:
            new_component["posterior"] = posteriors[comp_id]

        result.append(new_component)

    return result


__all__ = ["update_probabilities", "attach_component_posterior"]
