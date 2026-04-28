from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TTPCreate")


@_attrs_define
class TTPCreate:
    """
    Attributes:
        tactic (str | Unset):  Default: ''.
        technique_id (str | Unset):  Default: ''.
        technique_name (str | Unset):  Default: ''.
        procedure_description (str | Unset):  Default: ''.
        outcome (str | Unset):  Default: 'successful'.
        detection_time_seconds (int | None | Unset):
    """

    tactic: str | Unset = ""
    technique_id: str | Unset = ""
    technique_name: str | Unset = ""
    procedure_description: str | Unset = ""
    outcome: str | Unset = "successful"
    detection_time_seconds: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tactic = self.tactic

        technique_id = self.technique_id

        technique_name = self.technique_name

        procedure_description = self.procedure_description

        outcome = self.outcome

        detection_time_seconds: int | None | Unset
        if isinstance(self.detection_time_seconds, Unset):
            detection_time_seconds = UNSET
        else:
            detection_time_seconds = self.detection_time_seconds

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if tactic is not UNSET:
            field_dict["tactic"] = tactic
        if technique_id is not UNSET:
            field_dict["technique_id"] = technique_id
        if technique_name is not UNSET:
            field_dict["technique_name"] = technique_name
        if procedure_description is not UNSET:
            field_dict["procedure_description"] = procedure_description
        if outcome is not UNSET:
            field_dict["outcome"] = outcome
        if detection_time_seconds is not UNSET:
            field_dict["detection_time_seconds"] = detection_time_seconds

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        tactic = d.pop("tactic", UNSET)

        technique_id = d.pop("technique_id", UNSET)

        technique_name = d.pop("technique_name", UNSET)

        procedure_description = d.pop("procedure_description", UNSET)

        outcome = d.pop("outcome", UNSET)

        def _parse_detection_time_seconds(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        detection_time_seconds = _parse_detection_time_seconds(d.pop("detection_time_seconds", UNSET))

        ttp_create = cls(
            tactic=tactic,
            technique_id=technique_id,
            technique_name=technique_name,
            procedure_description=procedure_description,
            outcome=outcome,
            detection_time_seconds=detection_time_seconds,
        )

        ttp_create.additional_properties = d
        return ttp_create

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
