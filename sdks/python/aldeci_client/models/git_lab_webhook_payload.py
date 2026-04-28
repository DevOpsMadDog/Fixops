from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.git_lab_webhook_payload_labels_type_0_item import GitLabWebhookPayloadLabelsType0Item
    from ..models.git_lab_webhook_payload_object_attributes_type_0 import GitLabWebhookPayloadObjectAttributesType0
    from ..models.git_lab_webhook_payload_project_type_0 import GitLabWebhookPayloadProjectType0
    from ..models.git_lab_webhook_payload_user_type_0 import GitLabWebhookPayloadUserType0


T = TypeVar("T", bound="GitLabWebhookPayload")


@_attrs_define
class GitLabWebhookPayload:
    """GitLab webhook payload for issue events.

    Attributes:
        object_kind (str):
        event_type (None | str | Unset):
        object_attributes (GitLabWebhookPayloadObjectAttributesType0 | None | Unset):
        project (GitLabWebhookPayloadProjectType0 | None | Unset):
        user (GitLabWebhookPayloadUserType0 | None | Unset):
        labels (list[GitLabWebhookPayloadLabelsType0Item] | None | Unset):
    """

    object_kind: str
    event_type: None | str | Unset = UNSET
    object_attributes: GitLabWebhookPayloadObjectAttributesType0 | None | Unset = UNSET
    project: GitLabWebhookPayloadProjectType0 | None | Unset = UNSET
    user: GitLabWebhookPayloadUserType0 | None | Unset = UNSET
    labels: list[GitLabWebhookPayloadLabelsType0Item] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.git_lab_webhook_payload_object_attributes_type_0 import GitLabWebhookPayloadObjectAttributesType0
        from ..models.git_lab_webhook_payload_project_type_0 import GitLabWebhookPayloadProjectType0
        from ..models.git_lab_webhook_payload_user_type_0 import GitLabWebhookPayloadUserType0

        object_kind = self.object_kind

        event_type: None | str | Unset
        if isinstance(self.event_type, Unset):
            event_type = UNSET
        else:
            event_type = self.event_type

        object_attributes: dict[str, Any] | None | Unset
        if isinstance(self.object_attributes, Unset):
            object_attributes = UNSET
        elif isinstance(self.object_attributes, GitLabWebhookPayloadObjectAttributesType0):
            object_attributes = self.object_attributes.to_dict()
        else:
            object_attributes = self.object_attributes

        project: dict[str, Any] | None | Unset
        if isinstance(self.project, Unset):
            project = UNSET
        elif isinstance(self.project, GitLabWebhookPayloadProjectType0):
            project = self.project.to_dict()
        else:
            project = self.project

        user: dict[str, Any] | None | Unset
        if isinstance(self.user, Unset):
            user = UNSET
        elif isinstance(self.user, GitLabWebhookPayloadUserType0):
            user = self.user.to_dict()
        else:
            user = self.user

        labels: list[dict[str, Any]] | None | Unset
        if isinstance(self.labels, Unset):
            labels = UNSET
        elif isinstance(self.labels, list):
            labels = []
            for labels_type_0_item_data in self.labels:
                labels_type_0_item = labels_type_0_item_data.to_dict()
                labels.append(labels_type_0_item)

        else:
            labels = self.labels

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "object_kind": object_kind,
            }
        )
        if event_type is not UNSET:
            field_dict["event_type"] = event_type
        if object_attributes is not UNSET:
            field_dict["object_attributes"] = object_attributes
        if project is not UNSET:
            field_dict["project"] = project
        if user is not UNSET:
            field_dict["user"] = user
        if labels is not UNSET:
            field_dict["labels"] = labels

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.git_lab_webhook_payload_labels_type_0_item import GitLabWebhookPayloadLabelsType0Item
        from ..models.git_lab_webhook_payload_object_attributes_type_0 import GitLabWebhookPayloadObjectAttributesType0
        from ..models.git_lab_webhook_payload_project_type_0 import GitLabWebhookPayloadProjectType0
        from ..models.git_lab_webhook_payload_user_type_0 import GitLabWebhookPayloadUserType0

        d = dict(src_dict)
        object_kind = d.pop("object_kind")

        def _parse_event_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        event_type = _parse_event_type(d.pop("event_type", UNSET))

        def _parse_object_attributes(data: object) -> GitLabWebhookPayloadObjectAttributesType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                object_attributes_type_0 = GitLabWebhookPayloadObjectAttributesType0.from_dict(data)

                return object_attributes_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GitLabWebhookPayloadObjectAttributesType0 | None | Unset, data)

        object_attributes = _parse_object_attributes(d.pop("object_attributes", UNSET))

        def _parse_project(data: object) -> GitLabWebhookPayloadProjectType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                project_type_0 = GitLabWebhookPayloadProjectType0.from_dict(data)

                return project_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GitLabWebhookPayloadProjectType0 | None | Unset, data)

        project = _parse_project(d.pop("project", UNSET))

        def _parse_user(data: object) -> GitLabWebhookPayloadUserType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                user_type_0 = GitLabWebhookPayloadUserType0.from_dict(data)

                return user_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GitLabWebhookPayloadUserType0 | None | Unset, data)

        user = _parse_user(d.pop("user", UNSET))

        def _parse_labels(data: object) -> list[GitLabWebhookPayloadLabelsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                labels_type_0 = []
                _labels_type_0 = data
                for labels_type_0_item_data in _labels_type_0:
                    labels_type_0_item = GitLabWebhookPayloadLabelsType0Item.from_dict(labels_type_0_item_data)

                    labels_type_0.append(labels_type_0_item)

                return labels_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[GitLabWebhookPayloadLabelsType0Item] | None | Unset, data)

        labels = _parse_labels(d.pop("labels", UNSET))

        git_lab_webhook_payload = cls(
            object_kind=object_kind,
            event_type=event_type,
            object_attributes=object_attributes,
            project=project,
            user=user,
            labels=labels,
        )

        git_lab_webhook_payload.additional_properties = d
        return git_lab_webhook_payload

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
