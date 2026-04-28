from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.bulk_create_tickets_request_priority_mapping_type_0 import (
        BulkCreateTicketsRequestPriorityMappingType0,
    )


T = TypeVar("T", bound="BulkCreateTicketsRequest")


@_attrs_define
class BulkCreateTicketsRequest:
    """Request model for bulk ticket creation.

    Attributes:
        ids (list[str]):
        integration_id (str):
        project_key (None | str | Unset):
        issue_type (str | Unset):  Default: 'Bug'.
        priority_mapping (BulkCreateTicketsRequestPriorityMappingType0 | None | Unset):
    """

    ids: list[str]
    integration_id: str
    project_key: None | str | Unset = UNSET
    issue_type: str | Unset = "Bug"
    priority_mapping: BulkCreateTicketsRequestPriorityMappingType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.bulk_create_tickets_request_priority_mapping_type_0 import (
            BulkCreateTicketsRequestPriorityMappingType0,
        )

        ids = self.ids

        integration_id = self.integration_id

        project_key: None | str | Unset
        if isinstance(self.project_key, Unset):
            project_key = UNSET
        else:
            project_key = self.project_key

        issue_type = self.issue_type

        priority_mapping: dict[str, Any] | None | Unset
        if isinstance(self.priority_mapping, Unset):
            priority_mapping = UNSET
        elif isinstance(self.priority_mapping, BulkCreateTicketsRequestPriorityMappingType0):
            priority_mapping = self.priority_mapping.to_dict()
        else:
            priority_mapping = self.priority_mapping

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ids": ids,
                "integration_id": integration_id,
            }
        )
        if project_key is not UNSET:
            field_dict["project_key"] = project_key
        if issue_type is not UNSET:
            field_dict["issue_type"] = issue_type
        if priority_mapping is not UNSET:
            field_dict["priority_mapping"] = priority_mapping

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.bulk_create_tickets_request_priority_mapping_type_0 import (
            BulkCreateTicketsRequestPriorityMappingType0,
        )

        d = dict(src_dict)
        ids = cast(list[str], d.pop("ids"))

        integration_id = d.pop("integration_id")

        def _parse_project_key(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        project_key = _parse_project_key(d.pop("project_key", UNSET))

        issue_type = d.pop("issue_type", UNSET)

        def _parse_priority_mapping(data: object) -> BulkCreateTicketsRequestPriorityMappingType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                priority_mapping_type_0 = BulkCreateTicketsRequestPriorityMappingType0.from_dict(data)

                return priority_mapping_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(BulkCreateTicketsRequestPriorityMappingType0 | None | Unset, data)

        priority_mapping = _parse_priority_mapping(d.pop("priority_mapping", UNSET))

        bulk_create_tickets_request = cls(
            ids=ids,
            integration_id=integration_id,
            project_key=project_key,
            issue_type=issue_type,
            priority_mapping=priority_mapping,
        )

        bulk_create_tickets_request.additional_properties = d
        return bulk_create_tickets_request

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
