from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GenerateScenarioRequest")


@_attrs_define
class GenerateScenarioRequest:
    """Request to AI-generate a scenario.

    Attributes:
        target_description (str | Unset): Description of the target Default: 'Web application'.
        target (None | str | Unset): Alias for target_description
        threat_actor (str | Unset): Threat actor profile Default: 'cybercriminal'.
        attack_type (None | str | Unset): Type of attack (e.g., rce, xss)
        cve_ids (list[str] | Unset): Known CVEs
    """

    target_description: str | Unset = "Web application"
    target: None | str | Unset = UNSET
    threat_actor: str | Unset = "cybercriminal"
    attack_type: None | str | Unset = UNSET
    cve_ids: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target_description = self.target_description

        target: None | str | Unset
        if isinstance(self.target, Unset):
            target = UNSET
        else:
            target = self.target

        threat_actor = self.threat_actor

        attack_type: None | str | Unset
        if isinstance(self.attack_type, Unset):
            attack_type = UNSET
        else:
            attack_type = self.attack_type

        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if target_description is not UNSET:
            field_dict["target_description"] = target_description
        if target is not UNSET:
            field_dict["target"] = target
        if threat_actor is not UNSET:
            field_dict["threat_actor"] = threat_actor
        if attack_type is not UNSET:
            field_dict["attack_type"] = attack_type
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        target_description = d.pop("target_description", UNSET)

        def _parse_target(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        target = _parse_target(d.pop("target", UNSET))

        threat_actor = d.pop("threat_actor", UNSET)

        def _parse_attack_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        attack_type = _parse_attack_type(d.pop("attack_type", UNSET))

        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        generate_scenario_request = cls(
            target_description=target_description,
            target=target,
            threat_actor=threat_actor,
            attack_type=attack_type,
            cve_ids=cve_ids,
        )

        generate_scenario_request.additional_properties = d
        return generate_scenario_request

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
