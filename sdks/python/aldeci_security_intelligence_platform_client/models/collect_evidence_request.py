from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CollectEvidenceRequest")


@_attrs_define
class CollectEvidenceRequest:
    """
    Attributes:
        framework (str): Target framework (SOC2, PCI-DSS, HIPAA, FedRAMP, ISO27001, NIST-800-53, CMMC)
        control_id (None | str | Unset): Specific control ID; omit to collect for all controls in the framework
        org_id (None | str | Unset): Organisation identifier
    """

    framework: str
    control_id: None | str | Unset = UNSET
    org_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework = self.framework

        control_id: None | str | Unset
        if isinstance(self.control_id, Unset):
            control_id = UNSET
        else:
            control_id = self.control_id

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "framework": framework,
            }
        )
        if control_id is not UNSET:
            field_dict["control_id"] = control_id
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        framework = d.pop("framework")

        def _parse_control_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        control_id = _parse_control_id(d.pop("control_id", UNSET))

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        collect_evidence_request = cls(
            framework=framework,
            control_id=control_id,
            org_id=org_id,
        )

        collect_evidence_request.additional_properties = d
        return collect_evidence_request

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
