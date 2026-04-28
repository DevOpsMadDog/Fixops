from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddStepRequest")


@_attrs_define
class AddStepRequest:
    """
    Attributes:
        technique_name (str): Technique name
        tactic (str): ATT&CK tactic
        org_id (str | Unset):  Default: 'default'.
        technique_id (str | Unset): MITRE technique ID e.g. T1059 Default: ''.
        asset_targeted (str | Unset): Asset targeted in this step Default: ''.
        outcome (str | Unset): success/failed/unknown Default: 'unknown'.
        step_number (int | None | Unset): Step number (auto if omitted)
        evidence (list[str] | Unset): Evidence items
    """

    technique_name: str
    tactic: str
    org_id: str | Unset = "default"
    technique_id: str | Unset = ""
    asset_targeted: str | Unset = ""
    outcome: str | Unset = "unknown"
    step_number: int | None | Unset = UNSET
    evidence: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        technique_name = self.technique_name

        tactic = self.tactic

        org_id = self.org_id

        technique_id = self.technique_id

        asset_targeted = self.asset_targeted

        outcome = self.outcome

        step_number: int | None | Unset
        if isinstance(self.step_number, Unset):
            step_number = UNSET
        else:
            step_number = self.step_number

        evidence: list[str] | Unset = UNSET
        if not isinstance(self.evidence, Unset):
            evidence = self.evidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "technique_name": technique_name,
                "tactic": tactic,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if technique_id is not UNSET:
            field_dict["technique_id"] = technique_id
        if asset_targeted is not UNSET:
            field_dict["asset_targeted"] = asset_targeted
        if outcome is not UNSET:
            field_dict["outcome"] = outcome
        if step_number is not UNSET:
            field_dict["step_number"] = step_number
        if evidence is not UNSET:
            field_dict["evidence"] = evidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        technique_name = d.pop("technique_name")

        tactic = d.pop("tactic")

        org_id = d.pop("org_id", UNSET)

        technique_id = d.pop("technique_id", UNSET)

        asset_targeted = d.pop("asset_targeted", UNSET)

        outcome = d.pop("outcome", UNSET)

        def _parse_step_number(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        step_number = _parse_step_number(d.pop("step_number", UNSET))

        evidence = cast(list[str], d.pop("evidence", UNSET))

        add_step_request = cls(
            technique_name=technique_name,
            tactic=tactic,
            org_id=org_id,
            technique_id=technique_id,
            asset_targeted=asset_targeted,
            outcome=outcome,
            step_number=step_number,
            evidence=evidence,
        )

        add_step_request.additional_properties = d
        return add_step_request

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
