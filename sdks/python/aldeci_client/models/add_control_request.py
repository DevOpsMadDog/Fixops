from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddControlRequest")


@_attrs_define
class AddControlRequest:
    """
    Attributes:
        control_id (str): Control identifier (e.g. CC6.1, AC-2)
        control_name (str): Short control name
        framework (str | Unset): nist_csf | iso27001 | pci_dss | soc2 | hipaa | gdpr | cis_controls | nist_800_53
            Default: 'nist_csf'.
        description (None | str | Unset):
        control_status (str | Unset): implemented | partial | not_implemented | not_applicable Default:
            'not_implemented'.
        implementation_notes (None | str | Unset):
        owner (None | str | Unset):
        last_reviewed (None | str | Unset):
    """

    control_id: str
    control_name: str
    framework: str | Unset = "nist_csf"
    description: None | str | Unset = UNSET
    control_status: str | Unset = "not_implemented"
    implementation_notes: None | str | Unset = UNSET
    owner: None | str | Unset = UNSET
    last_reviewed: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        control_id = self.control_id

        control_name = self.control_name

        framework = self.framework

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        control_status = self.control_status

        implementation_notes: None | str | Unset
        if isinstance(self.implementation_notes, Unset):
            implementation_notes = UNSET
        else:
            implementation_notes = self.implementation_notes

        owner: None | str | Unset
        if isinstance(self.owner, Unset):
            owner = UNSET
        else:
            owner = self.owner

        last_reviewed: None | str | Unset
        if isinstance(self.last_reviewed, Unset):
            last_reviewed = UNSET
        else:
            last_reviewed = self.last_reviewed

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "control_id": control_id,
                "control_name": control_name,
            }
        )
        if framework is not UNSET:
            field_dict["framework"] = framework
        if description is not UNSET:
            field_dict["description"] = description
        if control_status is not UNSET:
            field_dict["control_status"] = control_status
        if implementation_notes is not UNSET:
            field_dict["implementation_notes"] = implementation_notes
        if owner is not UNSET:
            field_dict["owner"] = owner
        if last_reviewed is not UNSET:
            field_dict["last_reviewed"] = last_reviewed

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        control_id = d.pop("control_id")

        control_name = d.pop("control_name")

        framework = d.pop("framework", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        control_status = d.pop("control_status", UNSET)

        def _parse_implementation_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        implementation_notes = _parse_implementation_notes(d.pop("implementation_notes", UNSET))

        def _parse_owner(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner = _parse_owner(d.pop("owner", UNSET))

        def _parse_last_reviewed(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_reviewed = _parse_last_reviewed(d.pop("last_reviewed", UNSET))

        add_control_request = cls(
            control_id=control_id,
            control_name=control_name,
            framework=framework,
            description=description,
            control_status=control_status,
            implementation_notes=implementation_notes,
            owner=owner,
            last_reviewed=last_reviewed,
        )

        add_control_request.additional_properties = d
        return add_control_request

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
