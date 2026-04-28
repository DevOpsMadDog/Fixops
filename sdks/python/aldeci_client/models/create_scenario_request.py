from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateScenarioRequest")


@_attrs_define
class CreateScenarioRequest:
    """Request to create an attack scenario.

    Attributes:
        name (str): Scenario name
        description (str | Unset): Scenario description Default: ''.
        threat_actor (str | Unset): Threat actor profile Default: 'cybercriminal'.
        complexity (str | Unset): Attack complexity Default: 'medium'.
        target_assets (list[str] | Unset): Target assets
        target_cves (list[str] | Unset): CVEs to exploit
        objectives (list[str] | Unset): Attack objectives
        initial_access_vector (str | Unset): MITRE technique ID for initial access Default: ''.
    """

    name: str
    description: str | Unset = ""
    threat_actor: str | Unset = "cybercriminal"
    complexity: str | Unset = "medium"
    target_assets: list[str] | Unset = UNSET
    target_cves: list[str] | Unset = UNSET
    objectives: list[str] | Unset = UNSET
    initial_access_vector: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description = self.description

        threat_actor = self.threat_actor

        complexity = self.complexity

        target_assets: list[str] | Unset = UNSET
        if not isinstance(self.target_assets, Unset):
            target_assets = self.target_assets

        target_cves: list[str] | Unset = UNSET
        if not isinstance(self.target_cves, Unset):
            target_cves = self.target_cves

        objectives: list[str] | Unset = UNSET
        if not isinstance(self.objectives, Unset):
            objectives = self.objectives

        initial_access_vector = self.initial_access_vector

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if threat_actor is not UNSET:
            field_dict["threat_actor"] = threat_actor
        if complexity is not UNSET:
            field_dict["complexity"] = complexity
        if target_assets is not UNSET:
            field_dict["target_assets"] = target_assets
        if target_cves is not UNSET:
            field_dict["target_cves"] = target_cves
        if objectives is not UNSET:
            field_dict["objectives"] = objectives
        if initial_access_vector is not UNSET:
            field_dict["initial_access_vector"] = initial_access_vector

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        description = d.pop("description", UNSET)

        threat_actor = d.pop("threat_actor", UNSET)

        complexity = d.pop("complexity", UNSET)

        target_assets = cast(list[str], d.pop("target_assets", UNSET))

        target_cves = cast(list[str], d.pop("target_cves", UNSET))

        objectives = cast(list[str], d.pop("objectives", UNSET))

        initial_access_vector = d.pop("initial_access_vector", UNSET)

        create_scenario_request = cls(
            name=name,
            description=description,
            threat_actor=threat_actor,
            complexity=complexity,
            target_assets=target_assets,
            target_cves=target_cves,
            objectives=objectives,
            initial_access_vector=initial_access_vector,
        )

        create_scenario_request.additional_properties = d
        return create_scenario_request

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
