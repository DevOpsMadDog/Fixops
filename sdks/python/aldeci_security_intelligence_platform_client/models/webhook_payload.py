from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.webhook_payload_commits_item import WebhookPayloadCommitsItem
    from ..models.webhook_payload_object_attributes_type_0 import WebhookPayloadObjectAttributesType0
    from ..models.webhook_payload_pull_request_type_0 import WebhookPayloadPullRequestType0


T = TypeVar("T", bound="WebhookPayload")


@_attrs_define
class WebhookPayload:
    """Generic Git webhook payload (GitHub / GitLab push or PR events).

    Attributes:
        event_type (None | str | Unset):  Default: 'push'.
        ref (None | str | Unset):
        commits (list[WebhookPayloadCommitsItem] | Unset):
        pull_request (None | Unset | WebhookPayloadPullRequestType0):
        object_kind (None | str | Unset):
        object_attributes (None | Unset | WebhookPayloadObjectAttributesType0):
    """

    event_type: None | str | Unset = "push"
    ref: None | str | Unset = UNSET
    commits: list[WebhookPayloadCommitsItem] | Unset = UNSET
    pull_request: None | Unset | WebhookPayloadPullRequestType0 = UNSET
    object_kind: None | str | Unset = UNSET
    object_attributes: None | Unset | WebhookPayloadObjectAttributesType0 = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.webhook_payload_object_attributes_type_0 import WebhookPayloadObjectAttributesType0
        from ..models.webhook_payload_pull_request_type_0 import WebhookPayloadPullRequestType0

        event_type: None | str | Unset
        if isinstance(self.event_type, Unset):
            event_type = UNSET
        else:
            event_type = self.event_type

        ref: None | str | Unset
        if isinstance(self.ref, Unset):
            ref = UNSET
        else:
            ref = self.ref

        commits: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.commits, Unset):
            commits = []
            for commits_item_data in self.commits:
                commits_item = commits_item_data.to_dict()
                commits.append(commits_item)

        pull_request: dict[str, Any] | None | Unset
        if isinstance(self.pull_request, Unset):
            pull_request = UNSET
        elif isinstance(self.pull_request, WebhookPayloadPullRequestType0):
            pull_request = self.pull_request.to_dict()
        else:
            pull_request = self.pull_request

        object_kind: None | str | Unset
        if isinstance(self.object_kind, Unset):
            object_kind = UNSET
        else:
            object_kind = self.object_kind

        object_attributes: dict[str, Any] | None | Unset
        if isinstance(self.object_attributes, Unset):
            object_attributes = UNSET
        elif isinstance(self.object_attributes, WebhookPayloadObjectAttributesType0):
            object_attributes = self.object_attributes.to_dict()
        else:
            object_attributes = self.object_attributes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if event_type is not UNSET:
            field_dict["event_type"] = event_type
        if ref is not UNSET:
            field_dict["ref"] = ref
        if commits is not UNSET:
            field_dict["commits"] = commits
        if pull_request is not UNSET:
            field_dict["pull_request"] = pull_request
        if object_kind is not UNSET:
            field_dict["object_kind"] = object_kind
        if object_attributes is not UNSET:
            field_dict["object_attributes"] = object_attributes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.webhook_payload_commits_item import WebhookPayloadCommitsItem
        from ..models.webhook_payload_object_attributes_type_0 import WebhookPayloadObjectAttributesType0
        from ..models.webhook_payload_pull_request_type_0 import WebhookPayloadPullRequestType0

        d = dict(src_dict)

        def _parse_event_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        event_type = _parse_event_type(d.pop("event_type", UNSET))

        def _parse_ref(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ref = _parse_ref(d.pop("ref", UNSET))

        _commits = d.pop("commits", UNSET)
        commits: list[WebhookPayloadCommitsItem] | Unset = UNSET
        if _commits is not UNSET:
            commits = []
            for commits_item_data in _commits:
                commits_item = WebhookPayloadCommitsItem.from_dict(commits_item_data)

                commits.append(commits_item)

        def _parse_pull_request(data: object) -> None | Unset | WebhookPayloadPullRequestType0:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                pull_request_type_0 = WebhookPayloadPullRequestType0.from_dict(data)

                return pull_request_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | WebhookPayloadPullRequestType0, data)

        pull_request = _parse_pull_request(d.pop("pull_request", UNSET))

        def _parse_object_kind(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        object_kind = _parse_object_kind(d.pop("object_kind", UNSET))

        def _parse_object_attributes(data: object) -> None | Unset | WebhookPayloadObjectAttributesType0:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                object_attributes_type_0 = WebhookPayloadObjectAttributesType0.from_dict(data)

                return object_attributes_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | WebhookPayloadObjectAttributesType0, data)

        object_attributes = _parse_object_attributes(d.pop("object_attributes", UNSET))

        webhook_payload = cls(
            event_type=event_type,
            ref=ref,
            commits=commits,
            pull_request=pull_request,
            object_kind=object_kind,
            object_attributes=object_attributes,
        )

        webhook_payload.additional_properties = d
        return webhook_payload

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
