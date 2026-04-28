from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.per_bu_risk_request_findings_type_0_item import PerBuRiskRequestFindingsType0Item


T = TypeVar("T", bound="PerBuRiskRequest")


@_attrs_define
class PerBuRiskRequest:
    """
    Attributes:
        bu_id (str): Business unit ID
        findings (list[PerBuRiskRequestFindingsType0Item] | None | Unset): Optional list of findings. If omitted, pulled
            from security_findings by BU tag.
    """

    bu_id: str
    findings: list[PerBuRiskRequestFindingsType0Item] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        bu_id = self.bu_id

        findings: list[dict[str, Any]] | None | Unset
        if isinstance(self.findings, Unset):
            findings = UNSET
        elif isinstance(self.findings, list):
            findings = []
            for findings_type_0_item_data in self.findings:
                findings_type_0_item = findings_type_0_item_data.to_dict()
                findings.append(findings_type_0_item)

        else:
            findings = self.findings

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "bu_id": bu_id,
            }
        )
        if findings is not UNSET:
            field_dict["findings"] = findings

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.per_bu_risk_request_findings_type_0_item import PerBuRiskRequestFindingsType0Item

        d = dict(src_dict)
        bu_id = d.pop("bu_id")

        def _parse_findings(data: object) -> list[PerBuRiskRequestFindingsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                findings_type_0 = []
                _findings_type_0 = data
                for findings_type_0_item_data in _findings_type_0:
                    findings_type_0_item = PerBuRiskRequestFindingsType0Item.from_dict(findings_type_0_item_data)

                    findings_type_0.append(findings_type_0_item)

                return findings_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[PerBuRiskRequestFindingsType0Item] | None | Unset, data)

        findings = _parse_findings(d.pop("findings", UNSET))

        per_bu_risk_request = cls(
            bu_id=bu_id,
            findings=findings,
        )

        per_bu_risk_request.additional_properties = d
        return per_bu_risk_request

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
