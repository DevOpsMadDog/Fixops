from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.azure_dev_ops_webhook_payload_resource_containers_type_0 import (
        AzureDevOpsWebhookPayloadResourceContainersType0,
    )
    from ..models.azure_dev_ops_webhook_payload_resource_type_0 import AzureDevOpsWebhookPayloadResourceType0


T = TypeVar("T", bound="AzureDevOpsWebhookPayload")


@_attrs_define
class AzureDevOpsWebhookPayload:
    """Azure DevOps webhook payload for work item events.

    Attributes:
        event_type (str):
        subscription_id (None | str | Unset):
        notification_id (int | None | Unset):
        resource (AzureDevOpsWebhookPayloadResourceType0 | None | Unset):
        resource_version (None | str | Unset):
        resource_containers (AzureDevOpsWebhookPayloadResourceContainersType0 | None | Unset):
    """

    event_type: str
    subscription_id: None | str | Unset = UNSET
    notification_id: int | None | Unset = UNSET
    resource: AzureDevOpsWebhookPayloadResourceType0 | None | Unset = UNSET
    resource_version: None | str | Unset = UNSET
    resource_containers: AzureDevOpsWebhookPayloadResourceContainersType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.azure_dev_ops_webhook_payload_resource_containers_type_0 import (
            AzureDevOpsWebhookPayloadResourceContainersType0,
        )
        from ..models.azure_dev_ops_webhook_payload_resource_type_0 import AzureDevOpsWebhookPayloadResourceType0

        event_type = self.event_type

        subscription_id: None | str | Unset
        if isinstance(self.subscription_id, Unset):
            subscription_id = UNSET
        else:
            subscription_id = self.subscription_id

        notification_id: int | None | Unset
        if isinstance(self.notification_id, Unset):
            notification_id = UNSET
        else:
            notification_id = self.notification_id

        resource: dict[str, Any] | None | Unset
        if isinstance(self.resource, Unset):
            resource = UNSET
        elif isinstance(self.resource, AzureDevOpsWebhookPayloadResourceType0):
            resource = self.resource.to_dict()
        else:
            resource = self.resource

        resource_version: None | str | Unset
        if isinstance(self.resource_version, Unset):
            resource_version = UNSET
        else:
            resource_version = self.resource_version

        resource_containers: dict[str, Any] | None | Unset
        if isinstance(self.resource_containers, Unset):
            resource_containers = UNSET
        elif isinstance(self.resource_containers, AzureDevOpsWebhookPayloadResourceContainersType0):
            resource_containers = self.resource_containers.to_dict()
        else:
            resource_containers = self.resource_containers

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "eventType": event_type,
            }
        )
        if subscription_id is not UNSET:
            field_dict["subscriptionId"] = subscription_id
        if notification_id is not UNSET:
            field_dict["notificationId"] = notification_id
        if resource is not UNSET:
            field_dict["resource"] = resource
        if resource_version is not UNSET:
            field_dict["resourceVersion"] = resource_version
        if resource_containers is not UNSET:
            field_dict["resourceContainers"] = resource_containers

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.azure_dev_ops_webhook_payload_resource_containers_type_0 import (
            AzureDevOpsWebhookPayloadResourceContainersType0,
        )
        from ..models.azure_dev_ops_webhook_payload_resource_type_0 import AzureDevOpsWebhookPayloadResourceType0

        d = dict(src_dict)
        event_type = d.pop("eventType")

        def _parse_subscription_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        subscription_id = _parse_subscription_id(d.pop("subscriptionId", UNSET))

        def _parse_notification_id(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        notification_id = _parse_notification_id(d.pop("notificationId", UNSET))

        def _parse_resource(data: object) -> AzureDevOpsWebhookPayloadResourceType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                resource_type_0 = AzureDevOpsWebhookPayloadResourceType0.from_dict(data)

                return resource_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AzureDevOpsWebhookPayloadResourceType0 | None | Unset, data)

        resource = _parse_resource(d.pop("resource", UNSET))

        def _parse_resource_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        resource_version = _parse_resource_version(d.pop("resourceVersion", UNSET))

        def _parse_resource_containers(data: object) -> AzureDevOpsWebhookPayloadResourceContainersType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                resource_containers_type_0 = AzureDevOpsWebhookPayloadResourceContainersType0.from_dict(data)

                return resource_containers_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AzureDevOpsWebhookPayloadResourceContainersType0 | None | Unset, data)

        resource_containers = _parse_resource_containers(d.pop("resourceContainers", UNSET))

        azure_dev_ops_webhook_payload = cls(
            event_type=event_type,
            subscription_id=subscription_id,
            notification_id=notification_id,
            resource=resource,
            resource_version=resource_version,
            resource_containers=resource_containers,
        )

        azure_dev_ops_webhook_payload.additional_properties = d
        return azure_dev_ops_webhook_payload

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
