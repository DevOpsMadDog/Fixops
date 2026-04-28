from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddEvidenceRequest")


@_attrs_define
class AddEvidenceRequest:
    """
    Attributes:
        evidence_type (str): Type of evidence (e.g. policy, screenshot)
        description (str): Evidence description
        file_reference (None | str | Unset):
        collected_at (None | str | Unset):
        expires_at (None | str | Unset):
        collector (None | str | Unset):
    """

    evidence_type: str
    description: str
    file_reference: None | str | Unset = UNSET
    collected_at: None | str | Unset = UNSET
    expires_at: None | str | Unset = UNSET
    collector: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        evidence_type = self.evidence_type

        description = self.description

        file_reference: None | str | Unset
        if isinstance(self.file_reference, Unset):
            file_reference = UNSET
        else:
            file_reference = self.file_reference

        collected_at: None | str | Unset
        if isinstance(self.collected_at, Unset):
            collected_at = UNSET
        else:
            collected_at = self.collected_at

        expires_at: None | str | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        else:
            expires_at = self.expires_at

        collector: None | str | Unset
        if isinstance(self.collector, Unset):
            collector = UNSET
        else:
            collector = self.collector

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "evidence_type": evidence_type,
                "description": description,
            }
        )
        if file_reference is not UNSET:
            field_dict["file_reference"] = file_reference
        if collected_at is not UNSET:
            field_dict["collected_at"] = collected_at
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at
        if collector is not UNSET:
            field_dict["collector"] = collector

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        evidence_type = d.pop("evidence_type")

        description = d.pop("description")

        def _parse_file_reference(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        file_reference = _parse_file_reference(d.pop("file_reference", UNSET))

        def _parse_collected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        collected_at = _parse_collected_at(d.pop("collected_at", UNSET))

        def _parse_expires_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        def _parse_collector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        collector = _parse_collector(d.pop("collector", UNSET))

        add_evidence_request = cls(
            evidence_type=evidence_type,
            description=description,
            file_reference=file_reference,
            collected_at=collected_at,
            expires_at=expires_at,
            collector=collector,
        )

        add_evidence_request.additional_properties = d
        return add_evidence_request

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
