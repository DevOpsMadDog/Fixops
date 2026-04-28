from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreatePlaybookRequest")


@_attrs_define
class CreatePlaybookRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        playbook_name (str): Playbook name
        cloud_provider (str): Target cloud provider
        incident_type (str): Target incident type
        steps (list[str] | None | Unset): Ordered playbook steps
        estimated_mins (int | Unset): Estimated execution time in minutes Default: 30.
    """

    org_id: str
    playbook_name: str
    cloud_provider: str
    incident_type: str
    steps: list[str] | None | Unset = UNSET
    estimated_mins: int | Unset = 30
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        playbook_name = self.playbook_name

        cloud_provider = self.cloud_provider

        incident_type = self.incident_type

        steps: list[str] | None | Unset
        if isinstance(self.steps, Unset):
            steps = UNSET
        elif isinstance(self.steps, list):
            steps = self.steps

        else:
            steps = self.steps

        estimated_mins = self.estimated_mins

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "playbook_name": playbook_name,
                "cloud_provider": cloud_provider,
                "incident_type": incident_type,
            }
        )
        if steps is not UNSET:
            field_dict["steps"] = steps
        if estimated_mins is not UNSET:
            field_dict["estimated_mins"] = estimated_mins

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        playbook_name = d.pop("playbook_name")

        cloud_provider = d.pop("cloud_provider")

        incident_type = d.pop("incident_type")

        def _parse_steps(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                steps_type_0 = cast(list[str], data)

                return steps_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        steps = _parse_steps(d.pop("steps", UNSET))

        estimated_mins = d.pop("estimated_mins", UNSET)

        create_playbook_request = cls(
            org_id=org_id,
            playbook_name=playbook_name,
            cloud_provider=cloud_provider,
            incident_type=incident_type,
            steps=steps,
            estimated_mins=estimated_mins,
        )

        create_playbook_request.additional_properties = d
        return create_playbook_request

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
