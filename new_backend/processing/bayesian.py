"""Bayesian network utilities for the modernised backend.

This module replaces the previous heuristic probability calculations with an
actual Bayesian network evaluated through :mod:`pgmpy`.  Components are
modelled as nodes while probability tables define their relationships.  The
public helpers exposed here build the network, perform inference, and annotate
component metadata with the computed posteriors.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Any, Dict, Iterable, List, Mapping, Optional

try:  # pragma: no cover - exercised indirectly in tests
    from pgmpy.factors.discrete import TabularCPD
    from pgmpy.inference import VariableElimination
    from pgmpy.models import BayesianNetwork
except ModuleNotFoundError as exc:  # pragma: no cover - handled at runtime
    BayesianNetwork = None  # type: ignore[assignment]
    TabularCPD = None  # type: ignore[assignment]
    VariableElimination = None  # type: ignore[assignment]
    _IMPORT_ERROR = exc
else:  # pragma: no cover - trivial branch exercised in tests
    _IMPORT_ERROR = None

_HAS_PGMPY = BayesianNetwork is not None and TabularCPD is not None and VariableElimination is not None


class BayesianProcessorError(RuntimeError):
    """Raised when the Bayesian network cannot be constructed or queried."""


@dataclass(frozen=True)
class NodeSpecification:
    """Declarative description of a Bayesian node.

    Attributes
    ----------
    states:
        Ordered collection of valid states for the node.
    parents:
        Optional ordered collection of parent node identifiers.
    cpt:
        For root nodes, a sequence representing the prior probability of each
        state.  For non-root nodes, a mapping from tuples of parent states to
        the probability distribution of the node.  Each distribution must align
        with the ``states`` order.
    """

    states: tuple[str, ...]
    parents: tuple[str, ...] | None
    cpt: Any


def _require_backend() -> None:
    if BayesianNetwork is None or TabularCPD is None or VariableElimination is None:
        raise BayesianProcessorError(
            "pgmpy is required for Bayesian inference but is not installed"
        ) from _IMPORT_ERROR


def _normalise_node_specifications(
    nodes: Mapping[str, Mapping[str, Any]]
) -> Dict[str, NodeSpecification]:
    normalised: Dict[str, NodeSpecification] = {}
    for node, spec in nodes.items():
        try:
            states = tuple(spec["states"])
        except KeyError as exc:  # pragma: no cover - guard against malformed input
            raise BayesianProcessorError(f"Node '{node}' is missing a 'states' definition") from exc
        if not states:
            raise BayesianProcessorError(f"Node '{node}' must declare at least one state")
        parents_tuple = tuple(spec.get("parents", ()))
        parents = parents_tuple or None
        cpt = spec.get("cpt")
        if cpt is None:
            raise BayesianProcessorError(f"Node '{node}' is missing a 'cpt' definition")
        normalised[node] = NodeSpecification(states=states, parents=parents, cpt=cpt)
    return normalised


def _build_tabular_cpd(
    node: str,
    spec: NodeSpecification,
    nodes: Mapping[str, NodeSpecification],
) -> "TabularCPD":
    _require_backend()

    states = tuple(spec.states)
    parents = tuple(spec.parents or ())
    parent_cards = [len(nodes[parent].states) for parent in parents]

    if not parents:
        values = [[float(prob)] for prob in spec.cpt]
        if len(values) != len(states):
            raise BayesianProcessorError(
                f"Node '{node}' prior distribution does not match its state count"
            )
    else:
        parent_state_space = [tuple(nodes[parent].states) for parent in parents]
        combinations = list(product(*parent_state_space))
        columns: List[List[float]] = []
        for combo in combinations:
            try:
                distribution = list(spec.cpt[combo])
            except KeyError as exc:
                raise BayesianProcessorError(
                    f"Node '{node}' missing CPT entry for parent state combination {combo}"
                ) from exc
            if len(distribution) != len(states):
                raise BayesianProcessorError(
                    f"Node '{node}' CPT entry for {combo} has incorrect length"
                )
            columns.append([float(value) for value in distribution])
        # Transpose columns so each inner list corresponds to a node state
        values = [list(state_values) for state_values in zip(*columns)]

    return TabularCPD(
        variable=node,
        variable_card=len(states),
        values=values,
        evidence=list(parents) or None,
        evidence_card=parent_cards or None,
        state_names={
            node: list(states),
            **{parent: list(nodes[parent].states) for parent in parents},
        },
    )


def _build_network(nodes: Mapping[str, Mapping[str, Any]]) -> "BayesianNetwork":
    _require_backend()

    node_specs = _normalise_node_specifications(nodes)
    edges = set()
    for node, spec in node_specs.items():
        for parent in spec.parents or ():
            if parent not in node_specs:
                raise BayesianProcessorError(
                    f"Node '{node}' references unknown parent '{parent}'"
                )
            edges.add((parent, node))

    model = BayesianNetwork(sorted(edges))
    cpds = [_build_tabular_cpd(node, spec, node_specs) for node, spec in node_specs.items()]
    model.add_cpds(*cpds)
    model.check_model()
    return model


def _coerce_key(candidate: Any) -> Optional[tuple[str, ...]]:
    if candidate is None:
        return None
    if isinstance(candidate, tuple):
        return tuple(candidate)
    if isinstance(candidate, list):
        return tuple(str(item) for item in candidate)
    return None


def _distribution_for_states(
    node: str,
    spec: NodeSpecification,
    parent_assignment: Optional[Mapping[str, str]] = None,
) -> List[float]:
    states = spec.states
    if not spec.parents:
        distribution = spec.cpt
    else:
        if parent_assignment is None:
            raise BayesianProcessorError(
                f"Parent assignment required to evaluate conditional distribution for '{node}'"
            )
        key = tuple(parent_assignment[parent] for parent in spec.parents)
        distribution = None
        if isinstance(spec.cpt, Mapping):
            # attempt direct lookup first
            distribution = spec.cpt.get(key)
            if distribution is None:
                for candidate_key, candidate_distribution in spec.cpt.items():
                    coerced = _coerce_key(candidate_key)
                    if coerced == key:
                        distribution = candidate_distribution
                        break
        if distribution is None:
            raise BayesianProcessorError(
                f"Node '{node}' missing CPT entry for parent state combination {key}"
            )

    values = [float(value) for value in distribution]
    if len(values) != len(states):
        raise BayesianProcessorError(
            f"Node '{node}' probability distribution has incorrect length"
        )
    total = sum(values)
    if total <= 0:
        raise BayesianProcessorError(
            f"Node '{node}' distribution must contain positive probabilities"
        )
    if abs(total - 1.0) > 1e-6:
        values = [value / total for value in values]
    return values


def _assignment_probability(
    assignment: Mapping[str, str],
    node_specs: Mapping[str, NodeSpecification],
) -> float:
    probability = 1.0
    for node, spec in node_specs.items():
        state = assignment[node]
        if spec.parents:
            parent_assignment = {parent: assignment[parent] for parent in spec.parents}
        else:
            parent_assignment = None
        distribution = _distribution_for_states(node, spec, parent_assignment)
        try:
            index = spec.states.index(state)
        except ValueError as exc:
            raise BayesianProcessorError(
                f"State '{state}' is not valid for node '{node}'"
            ) from exc
        probability *= distribution[index]
    return probability


def _extract_evidence(
    components: Iterable[Mapping[str, Any]],
    node_specs: Mapping[str, NodeSpecification],
) -> Dict[str, str]:
    evidence: Dict[str, str] = {}
    for component in components:
        component_id = component.get("id")
        if not component_id:
            raise BayesianProcessorError("Each component must include an 'id' field")
        if component_id not in node_specs:
            raise BayesianProcessorError(
                f"Component '{component_id}' is not present in the Bayesian network specification"
            )
        for key in ("observed_state", "state", "evidence_state"):
            state = component.get(key)
            if state is not None:
                valid_states = node_specs[component_id].states
                if state not in valid_states:
                    raise BayesianProcessorError(
                        f"State '{state}' for component '{component_id}' is not valid. "
                        f"Expected one of {valid_states}."
                    )
                evidence[component_id] = state
                break
    return evidence


def update_probabilities(
    components: Iterable[Mapping[str, Any]],
    network: Mapping[str, Any],
    evidence: Optional[Mapping[str, str]] = None,
) -> Dict[str, Dict[str, float]]:
    """Compute posterior probabilities for components.

    Parameters
    ----------
    components:
        Sequence of component metadata dictionaries.  Each component must
        declare an ``id`` matching a node in the Bayesian specification.  If a
        component carries an ``observed_state`` (or ``state``/``evidence_state``)
        it is treated as evidence.
    network:
        Mapping containing a ``"nodes"`` key whose value is a dictionary of node
        specifications.  Each specification must declare ``states`` and ``cpt``
        entries; ``parents`` is optional.
    evidence:
        Additional explicit evidence mapping node identifiers to observed
        states.  These values override any evidence embedded in the component
        dictionaries.

    Returns
    -------
    Dict[str, Dict[str, float]]
        Mapping of component identifiers to posterior probability distributions
        over their states.
    """

    if "nodes" not in network:
        raise BayesianProcessorError("Network specification must include a 'nodes' mapping")

    node_specs = _normalise_node_specifications(network["nodes"])

    combined_evidence = _extract_evidence(components, node_specs)
    if evidence:
        for node, state in evidence.items():
            if node not in node_specs:
                raise BayesianProcessorError(
                    f"Evidence provided for unknown node '{node}'"
                )
            if state not in node_specs[node].states:
                raise BayesianProcessorError(
                    f"Evidence state '{state}' for node '{node}' is invalid"
                )
            combined_evidence[node] = state

    if _HAS_PGMPY:
        model = _build_network(network["nodes"])
        inference = VariableElimination(model)

        results: Dict[str, Dict[str, float]] = {}
        for component in components:
            node = component["id"]
            if node in combined_evidence:
                observed_state = combined_evidence[node]
                results[node] = {
                    state: 1.0 if state == observed_state else 0.0
                    for state in node_specs[node].states
                }
                continue

            query = inference.query(
                variables=[node], evidence=combined_evidence or None, show_progress=False
            )
            probabilities = query.values.reshape(-1)
            states = query.state_names[node]
            results[node] = {
                state: float(prob)
                for state, prob in zip(states, probabilities)
            }

        return results

    nodes_in_order = list(node_specs.keys())
    state_accumulators: Dict[str, Dict[str, float]] = {
        node: {state: 0.0 for state in spec.states}
        for node, spec in node_specs.items()
    }
    totals: Dict[str, float] = {node: 0.0 for node in node_specs}

    state_space = [node_specs[node].states for node in nodes_in_order]
    for combination in product(*state_space):
        assignment = {node: state for node, state in zip(nodes_in_order, combination)}
        if any(assignment[node] != state for node, state in combined_evidence.items()):
            continue

        weight = _assignment_probability(assignment, node_specs)
        if weight == 0.0:
            continue
        for node, state in assignment.items():
            state_accumulators[node][state] += weight
            totals[node] += weight

    results: Dict[str, Dict[str, float]] = {}
    for node, accumulator in state_accumulators.items():
        if totals[node] == 0.0:
            raise BayesianProcessorError(
                "Evidence configuration resulted in zero probability mass; check CPT definitions"
            )
        results[node] = {
            state: probability / totals[node]
            for state, probability in accumulator.items()
        }

    return results


def attach_component_posterior(
    components: Iterable[Mapping[str, Any]],
    posteriors: Mapping[str, Mapping[str, float]],
    *,
    key: str = "posterior",
) -> List[Dict[str, Any]]:
    """Attach posterior distributions to component metadata.

    Parameters
    ----------
    components:
        Original component metadata entries.
    posteriors:
        Mapping produced by :func:`update_probabilities`.
    key:
        Dictionary key used to store the posterior distribution on each
        component.  Defaults to ``"posterior"``.

    Returns
    -------
    list of dict
        Shallow copies of the provided components with the posterior attached.
    """

    annotated: List[Dict[str, Any]] = []
    for component in components:
        component_id = component.get("id")
        if not component_id:
            raise BayesianProcessorError("Each component must include an 'id' field")
        enriched: Dict[str, Any] = dict(component)
        enriched[key] = dict(posteriors.get(component_id, {}))
        annotated.append(enriched)
    return annotated


__all__ = [
    "attach_component_posterior",
    "update_probabilities",
    "BayesianProcessorError",
]

