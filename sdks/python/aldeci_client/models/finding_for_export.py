from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.finding_severity import FindingSeverity
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.finding_for_export_external_ids import FindingForExportExternalIds
    from ..models.finding_for_export_metadata import FindingForExportMetadata


T = TypeVar("T", bound="FindingForExport")


@_attrs_define
class FindingForExport:
    """Finding ready for export to external system.

    Attributes:
        finding_id (str): ALDECI finding ID
        source (str): Original connector source
        title (str): Finding title
        severity (FindingSeverity): Finding severity levels.
        description (None | str | Unset): Description
        remediation (None | str | Unset): Remediation guidance
        external_ids (FindingForExportExternalIds | Unset): IDs in external systems (e.g. {'jira': 'PROJ-123'})
        metadata (FindingForExportMetadata | Unset): Additional metadata
    """

    finding_id: str
    source: str
    title: str
    severity: FindingSeverity
    description: None | str | Unset = UNSET
    remediation: None | str | Unset = UNSET
    external_ids: FindingForExportExternalIds | Unset = UNSET
    metadata: FindingForExportMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        source = self.source

        title = self.title

        severity = self.severity.value

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        remediation: None | str | Unset
        if isinstance(self.remediation, Unset):
            remediation = UNSET
        else:
            remediation = self.remediation

        external_ids: dict[str, Any] | Unset = UNSET
        if not isinstance(self.external_ids, Unset):
            external_ids = self.external_ids.to_dict()

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "source": source,
                "title": title,
                "severity": severity,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if remediation is not UNSET:
            field_dict["remediation"] = remediation
        if external_ids is not UNSET:
            field_dict["external_ids"] = external_ids
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.finding_for_export_external_ids import FindingForExportExternalIds
        from ..models.finding_for_export_metadata import FindingForExportMetadata

        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        source = d.pop("source")

        title = d.pop("title")

        severity = FindingSeverity(d.pop("severity"))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_remediation(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        remediation = _parse_remediation(d.pop("remediation", UNSET))

        _external_ids = d.pop("external_ids", UNSET)
        external_ids: FindingForExportExternalIds | Unset
        if isinstance(_external_ids, Unset):
            external_ids = UNSET
        else:
            external_ids = FindingForExportExternalIds.from_dict(_external_ids)

        _metadata = d.pop("metadata", UNSET)
        metadata: FindingForExportMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = FindingForExportMetadata.from_dict(_metadata)

        finding_for_export = cls(
            finding_id=finding_id,
            source=source,
            title=title,
            severity=severity,
            description=description,
            remediation=remediation,
            external_ids=external_ids,
            metadata=metadata,
        )

        finding_for_export.additional_properties = d
        return finding_for_export

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
