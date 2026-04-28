from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.ia_c_provider import IaCProvider
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ia_c_finding_create_metadata import IaCFindingCreateMetadata


T = TypeVar("T", bound="IaCFindingCreate")


@_attrs_define
class IaCFindingCreate:
    """Request model for creating IaC finding.

    Attributes:
        provider (IaCProvider): IaC provider types.
        severity (str):
        title (str):
        description (str):
        file_path (str):
        line_number (int):
        resource_type (str):
        resource_name (str):
        rule_id (str):
        remediation (None | str | Unset):
        metadata (IaCFindingCreateMetadata | Unset):
    """

    provider: IaCProvider
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    resource_type: str
    resource_name: str
    rule_id: str
    remediation: None | str | Unset = UNSET
    metadata: IaCFindingCreateMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        provider = self.provider.value

        severity = self.severity

        title = self.title

        description = self.description

        file_path = self.file_path

        line_number = self.line_number

        resource_type = self.resource_type

        resource_name = self.resource_name

        rule_id = self.rule_id

        remediation: None | str | Unset
        if isinstance(self.remediation, Unset):
            remediation = UNSET
        else:
            remediation = self.remediation

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "provider": provider,
                "severity": severity,
                "title": title,
                "description": description,
                "file_path": file_path,
                "line_number": line_number,
                "resource_type": resource_type,
                "resource_name": resource_name,
                "rule_id": rule_id,
            }
        )
        if remediation is not UNSET:
            field_dict["remediation"] = remediation
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ia_c_finding_create_metadata import IaCFindingCreateMetadata

        d = dict(src_dict)
        provider = IaCProvider(d.pop("provider"))

        severity = d.pop("severity")

        title = d.pop("title")

        description = d.pop("description")

        file_path = d.pop("file_path")

        line_number = d.pop("line_number")

        resource_type = d.pop("resource_type")

        resource_name = d.pop("resource_name")

        rule_id = d.pop("rule_id")

        def _parse_remediation(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        remediation = _parse_remediation(d.pop("remediation", UNSET))

        _metadata = d.pop("metadata", UNSET)
        metadata: IaCFindingCreateMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = IaCFindingCreateMetadata.from_dict(_metadata)

        ia_c_finding_create = cls(
            provider=provider,
            severity=severity,
            title=title,
            description=description,
            file_path=file_path,
            line_number=line_number,
            resource_type=resource_type,
            resource_name=resource_name,
            rule_id=rule_id,
            remediation=remediation,
            metadata=metadata,
        )

        ia_c_finding_create.additional_properties = d
        return ia_c_finding_create

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
