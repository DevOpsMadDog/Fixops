from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.agent_type import AgentType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.orchestrate_request_context import OrchestrateRequestContext


T = TypeVar("T", bound="OrchestrateRequest")


@_attrs_define
class OrchestrateRequest:
    """Request for multi-agent orchestration.

    Attributes:
        objective (str):
        agents (list[AgentType] | Unset):
        context (OrchestrateRequestContext | Unset):
        max_iterations (int | Unset):  Default: 5.
    """

    objective: str
    agents: list[AgentType] | Unset = UNSET
    context: OrchestrateRequestContext | Unset = UNSET
    max_iterations: int | Unset = 5
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        objective = self.objective

        agents: list[str] | Unset = UNSET
        if not isinstance(self.agents, Unset):
            agents = []
            for agents_item_data in self.agents:
                agents_item = agents_item_data.value
                agents.append(agents_item)

        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        max_iterations = self.max_iterations

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "objective": objective,
            }
        )
        if agents is not UNSET:
            field_dict["agents"] = agents
        if context is not UNSET:
            field_dict["context"] = context
        if max_iterations is not UNSET:
            field_dict["max_iterations"] = max_iterations

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.orchestrate_request_context import OrchestrateRequestContext

        d = dict(src_dict)
        objective = d.pop("objective")

        _agents = d.pop("agents", UNSET)
        agents: list[AgentType] | Unset = UNSET
        if _agents is not UNSET:
            agents = []
            for agents_item_data in _agents:
                agents_item = AgentType(agents_item_data)

                agents.append(agents_item)

        _context = d.pop("context", UNSET)
        context: OrchestrateRequestContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = OrchestrateRequestContext.from_dict(_context)

        max_iterations = d.pop("max_iterations", UNSET)

        orchestrate_request = cls(
            objective=objective,
            agents=agents,
            context=context,
            max_iterations=max_iterations,
        )

        orchestrate_request.additional_properties = d
        return orchestrate_request

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
