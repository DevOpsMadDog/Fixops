from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ingest_findings_request_findings_item import IngestFindingsRequestFindingsItem


T = TypeVar("T", bound="IngestFindingsRequest")


@_attrs_define
class IngestFindingsRequest:
    """
    Attributes:
        findings (list[IngestFindingsRequestFindingsItem]): Findings to ingest into graph
        app_id (None | str | Unset): Application ID context
    """

    findings: list[IngestFindingsRequestFindingsItem]
    app_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        app_id: None | str | Unset
        if isinstance(self.app_id, Unset):
            app_id = UNSET
        else:
            app_id = self.app_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "findings": findings,
            }
        )
        if app_id is not UNSET:
            field_dict["app_id"] = app_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ingest_findings_request_findings_item import IngestFindingsRequestFindingsItem

        d = dict(src_dict)
        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = IngestFindingsRequestFindingsItem.from_dict(findings_item_data)

            findings.append(findings_item)

        def _parse_app_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        app_id = _parse_app_id(d.pop("app_id", UNSET))

        ingest_findings_request = cls(
            findings=findings,
            app_id=app_id,
        )

        ingest_findings_request.additional_properties = d
        return ingest_findings_request

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
