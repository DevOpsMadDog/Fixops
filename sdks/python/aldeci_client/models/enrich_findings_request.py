from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.enrich_findings_request_findings_item import EnrichFindingsRequestFindingsItem


T = TypeVar("T", bound="EnrichFindingsRequest")


@_attrs_define
class EnrichFindingsRequest:
    """Request to enrich findings with vulnerability intelligence.

    Attributes:
        findings (list[EnrichFindingsRequestFindingsItem]):
        target_region (None | str | Unset): Target region for geo-weighted scoring Default: 'global'.
    """

    findings: list[EnrichFindingsRequestFindingsItem]
    target_region: None | str | Unset = "global"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        target_region: None | str | Unset
        if isinstance(self.target_region, Unset):
            target_region = UNSET
        else:
            target_region = self.target_region

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "findings": findings,
            }
        )
        if target_region is not UNSET:
            field_dict["target_region"] = target_region

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.enrich_findings_request_findings_item import EnrichFindingsRequestFindingsItem

        d = dict(src_dict)
        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = EnrichFindingsRequestFindingsItem.from_dict(findings_item_data)

            findings.append(findings_item)

        def _parse_target_region(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        target_region = _parse_target_region(d.pop("target_region", UNSET))

        enrich_findings_request = cls(
            findings=findings,
            target_region=target_region,
        )

        enrich_findings_request.additional_properties = d
        return enrich_findings_request

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
