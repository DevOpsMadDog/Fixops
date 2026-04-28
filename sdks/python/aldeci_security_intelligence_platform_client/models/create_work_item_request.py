from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.create_work_item_request_integration_type import CreateWorkItemRequestIntegrationType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.create_work_item_request_additional_fields_type_0 import CreateWorkItemRequestAdditionalFieldsType0


T = TypeVar("T", bound="CreateWorkItemRequest")


@_attrs_define
class CreateWorkItemRequest:
    """Request to create a work item in an ALM system.

    Attributes:
        cluster_id (str | Unset):  Default: 'default-cluster'.
        integration_type (CreateWorkItemRequestIntegrationType | Unset):  Default:
            CreateWorkItemRequestIntegrationType.JIRA.
        title (str | Unset):  Default: 'Untitled Work Item'.
        description (None | str | Unset):
        severity (None | str | Unset):
        labels (list[str] | None | Unset):
        assignee (None | str | Unset):
        project_id (None | str | Unset):
        additional_fields (CreateWorkItemRequestAdditionalFieldsType0 | None | Unset):
    """

    cluster_id: str | Unset = "default-cluster"
    integration_type: CreateWorkItemRequestIntegrationType | Unset = CreateWorkItemRequestIntegrationType.JIRA
    title: str | Unset = "Untitled Work Item"
    description: None | str | Unset = UNSET
    severity: None | str | Unset = UNSET
    labels: list[str] | None | Unset = UNSET
    assignee: None | str | Unset = UNSET
    project_id: None | str | Unset = UNSET
    additional_fields: CreateWorkItemRequestAdditionalFieldsType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.create_work_item_request_additional_fields_type_0 import (
            CreateWorkItemRequestAdditionalFieldsType0,
        )

        cluster_id = self.cluster_id

        integration_type: str | Unset = UNSET
        if not isinstance(self.integration_type, Unset):
            integration_type = self.integration_type.value

        title = self.title

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        severity: None | str | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        else:
            severity = self.severity

        labels: list[str] | None | Unset
        if isinstance(self.labels, Unset):
            labels = UNSET
        elif isinstance(self.labels, list):
            labels = self.labels

        else:
            labels = self.labels

        assignee: None | str | Unset
        if isinstance(self.assignee, Unset):
            assignee = UNSET
        else:
            assignee = self.assignee

        project_id: None | str | Unset
        if isinstance(self.project_id, Unset):
            project_id = UNSET
        else:
            project_id = self.project_id

        additional_fields: dict[str, Any] | None | Unset
        if isinstance(self.additional_fields, Unset):
            additional_fields = UNSET
        elif isinstance(self.additional_fields, CreateWorkItemRequestAdditionalFieldsType0):
            additional_fields = self.additional_fields.to_dict()
        else:
            additional_fields = self.additional_fields

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cluster_id is not UNSET:
            field_dict["cluster_id"] = cluster_id
        if integration_type is not UNSET:
            field_dict["integration_type"] = integration_type
        if title is not UNSET:
            field_dict["title"] = title
        if description is not UNSET:
            field_dict["description"] = description
        if severity is not UNSET:
            field_dict["severity"] = severity
        if labels is not UNSET:
            field_dict["labels"] = labels
        if assignee is not UNSET:
            field_dict["assignee"] = assignee
        if project_id is not UNSET:
            field_dict["project_id"] = project_id
        if additional_fields is not UNSET:
            field_dict["additional_fields"] = additional_fields

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.create_work_item_request_additional_fields_type_0 import (
            CreateWorkItemRequestAdditionalFieldsType0,
        )

        d = dict(src_dict)
        cluster_id = d.pop("cluster_id", UNSET)

        _integration_type = d.pop("integration_type", UNSET)
        integration_type: CreateWorkItemRequestIntegrationType | Unset
        if isinstance(_integration_type, Unset):
            integration_type = UNSET
        else:
            integration_type = CreateWorkItemRequestIntegrationType(_integration_type)

        title = d.pop("title", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

        def _parse_labels(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                labels_type_0 = cast(list[str], data)

                return labels_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        labels = _parse_labels(d.pop("labels", UNSET))

        def _parse_assignee(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assignee = _parse_assignee(d.pop("assignee", UNSET))

        def _parse_project_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        project_id = _parse_project_id(d.pop("project_id", UNSET))

        def _parse_additional_fields(data: object) -> CreateWorkItemRequestAdditionalFieldsType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                additional_fields_type_0 = CreateWorkItemRequestAdditionalFieldsType0.from_dict(data)

                return additional_fields_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CreateWorkItemRequestAdditionalFieldsType0 | None | Unset, data)

        additional_fields = _parse_additional_fields(d.pop("additional_fields", UNSET))

        create_work_item_request = cls(
            cluster_id=cluster_id,
            integration_type=integration_type,
            title=title,
            description=description,
            severity=severity,
            labels=labels,
            assignee=assignee,
            project_id=project_id,
            additional_fields=additional_fields,
        )

        create_work_item_request.additional_properties = d
        return create_work_item_request

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
