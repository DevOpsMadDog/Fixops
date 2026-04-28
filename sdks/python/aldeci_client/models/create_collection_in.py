from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateCollectionIn")


@_attrs_define
class CreateCollectionIn:
    """
    Attributes:
        org_id (str):
        collection_name (str):
        framework (str | Unset):  Default: 'SOC2'.
        audit_period (str | Unset):  Default: ''.
        auditor (str | Unset):  Default: ''.
    """

    org_id: str
    collection_name: str
    framework: str | Unset = "SOC2"
    audit_period: str | Unset = ""
    auditor: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        collection_name = self.collection_name

        framework = self.framework

        audit_period = self.audit_period

        auditor = self.auditor

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "collection_name": collection_name,
            }
        )
        if framework is not UNSET:
            field_dict["framework"] = framework
        if audit_period is not UNSET:
            field_dict["audit_period"] = audit_period
        if auditor is not UNSET:
            field_dict["auditor"] = auditor

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        collection_name = d.pop("collection_name")

        framework = d.pop("framework", UNSET)

        audit_period = d.pop("audit_period", UNSET)

        auditor = d.pop("auditor", UNSET)

        create_collection_in = cls(
            org_id=org_id,
            collection_name=collection_name,
            framework=framework,
            audit_period=audit_period,
            auditor=auditor,
        )

        create_collection_in.additional_properties = d
        return create_collection_in

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
