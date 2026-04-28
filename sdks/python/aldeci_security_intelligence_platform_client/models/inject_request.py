from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="InjectRequest")


@_attrs_define
class InjectRequest:
    """Request to inject a synthetic vulnerability (create a drill).

    Attributes:
        scenario (str): Scenario ID to inject. One of: log4shell, sqli, ssrf, path_traversal, insecure_deserialization,
            hardcoded_credentials, broken_auth, xss, crypto_weakness, supply_chain — or a custom scenario ID.
        target_component (str): The component / service to target with the synthetic finding
        org_id (str): Organisation identifier
        notes (str | Unset): Optional notes for this drill (not visible to the team being tested) Default: ''.
        injected_by (None | str | Unset): Identifier of the person / system injecting the drill
    """

    scenario: str
    target_component: str
    org_id: str
    notes: str | Unset = ""
    injected_by: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scenario = self.scenario

        target_component = self.target_component

        org_id = self.org_id

        notes = self.notes

        injected_by: None | str | Unset
        if isinstance(self.injected_by, Unset):
            injected_by = UNSET
        else:
            injected_by = self.injected_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scenario": scenario,
                "target_component": target_component,
                "org_id": org_id,
            }
        )
        if notes is not UNSET:
            field_dict["notes"] = notes
        if injected_by is not UNSET:
            field_dict["injected_by"] = injected_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scenario = d.pop("scenario")

        target_component = d.pop("target_component")

        org_id = d.pop("org_id")

        notes = d.pop("notes", UNSET)

        def _parse_injected_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        injected_by = _parse_injected_by(d.pop("injected_by", UNSET))

        inject_request = cls(
            scenario=scenario,
            target_component=target_component,
            org_id=org_id,
            notes=notes,
            injected_by=injected_by,
        )

        inject_request.additional_properties = d
        return inject_request

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
