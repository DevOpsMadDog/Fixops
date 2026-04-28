from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssessmentRequest")


@_attrs_define
class AssessmentRequest:
    """
    Attributes:
        org_id (str):
        target (str):
        cve_ids (list[str]):
        scan_type (str | Unset):  Default: 'comprehensive'.
        compliance_frameworks (list[str] | None | Unset):
    """

    org_id: str
    target: str
    cve_ids: list[str]
    scan_type: str | Unset = "comprehensive"
    compliance_frameworks: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        target = self.target

        cve_ids = self.cve_ids

        scan_type = self.scan_type

        compliance_frameworks: list[str] | None | Unset
        if isinstance(self.compliance_frameworks, Unset):
            compliance_frameworks = UNSET
        elif isinstance(self.compliance_frameworks, list):
            compliance_frameworks = self.compliance_frameworks

        else:
            compliance_frameworks = self.compliance_frameworks

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "target": target,
                "cve_ids": cve_ids,
            }
        )
        if scan_type is not UNSET:
            field_dict["scan_type"] = scan_type
        if compliance_frameworks is not UNSET:
            field_dict["compliance_frameworks"] = compliance_frameworks

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        target = d.pop("target")

        cve_ids = cast(list[str], d.pop("cve_ids"))

        scan_type = d.pop("scan_type", UNSET)

        def _parse_compliance_frameworks(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                compliance_frameworks_type_0 = cast(list[str], data)

                return compliance_frameworks_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        compliance_frameworks = _parse_compliance_frameworks(d.pop("compliance_frameworks", UNSET))

        assessment_request = cls(
            org_id=org_id,
            target=target,
            cve_ids=cve_ids,
            scan_type=scan_type,
            compliance_frameworks=compliance_frameworks,
        )

        assessment_request.additional_properties = d
        return assessment_request

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
