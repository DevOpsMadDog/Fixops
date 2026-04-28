from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="StoreEvidenceIn")


@_attrs_define
class StoreEvidenceIn:
    """
    Attributes:
        org_id (str):
        evidence_name (str):
        evidence_type (str | Unset):  Default: 'screenshot'.
        framework (str | Unset):  Default: 'SOC2'.
        control_id (str | Unset):  Default: ''.
        collected_by (str | Unset):  Default: ''.
        collection_method (str | Unset):  Default: 'manual'.
        file_path (str | Unset):  Default: ''.
        content (str | Unset):  Default: ''.
        retention_years (int | Unset):  Default: 7.
    """

    org_id: str
    evidence_name: str
    evidence_type: str | Unset = "screenshot"
    framework: str | Unset = "SOC2"
    control_id: str | Unset = ""
    collected_by: str | Unset = ""
    collection_method: str | Unset = "manual"
    file_path: str | Unset = ""
    content: str | Unset = ""
    retention_years: int | Unset = 7
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        evidence_name = self.evidence_name

        evidence_type = self.evidence_type

        framework = self.framework

        control_id = self.control_id

        collected_by = self.collected_by

        collection_method = self.collection_method

        file_path = self.file_path

        content = self.content

        retention_years = self.retention_years

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "evidence_name": evidence_name,
            }
        )
        if evidence_type is not UNSET:
            field_dict["evidence_type"] = evidence_type
        if framework is not UNSET:
            field_dict["framework"] = framework
        if control_id is not UNSET:
            field_dict["control_id"] = control_id
        if collected_by is not UNSET:
            field_dict["collected_by"] = collected_by
        if collection_method is not UNSET:
            field_dict["collection_method"] = collection_method
        if file_path is not UNSET:
            field_dict["file_path"] = file_path
        if content is not UNSET:
            field_dict["content"] = content
        if retention_years is not UNSET:
            field_dict["retention_years"] = retention_years

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        evidence_name = d.pop("evidence_name")

        evidence_type = d.pop("evidence_type", UNSET)

        framework = d.pop("framework", UNSET)

        control_id = d.pop("control_id", UNSET)

        collected_by = d.pop("collected_by", UNSET)

        collection_method = d.pop("collection_method", UNSET)

        file_path = d.pop("file_path", UNSET)

        content = d.pop("content", UNSET)

        retention_years = d.pop("retention_years", UNSET)

        store_evidence_in = cls(
            org_id=org_id,
            evidence_name=evidence_name,
            evidence_type=evidence_type,
            framework=framework,
            control_id=control_id,
            collected_by=collected_by,
            collection_method=collection_method,
            file_path=file_path,
            content=content,
            retention_years=retention_years,
        )

        store_evidence_in.additional_properties = d
        return store_evidence_in

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
