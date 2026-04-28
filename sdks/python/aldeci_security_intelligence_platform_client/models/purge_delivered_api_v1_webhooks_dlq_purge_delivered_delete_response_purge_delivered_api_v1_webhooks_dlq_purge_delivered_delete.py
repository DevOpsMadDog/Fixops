from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar(
    "T",
    bound="PurgeDeliveredApiV1WebhooksDlqPurgeDeliveredDeleteResponsePurgeDeliveredApiV1WebhooksDlqPurgeDeliveredDelete",
)


@_attrs_define
class PurgeDeliveredApiV1WebhooksDlqPurgeDeliveredDeleteResponsePurgeDeliveredApiV1WebhooksDlqPurgeDeliveredDelete:
    """ """

    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        purge_delivered_api_v1_webhooks_dlq_purge_delivered_delete_response_purge_delivered_api_v1_webhooks_dlq_purge_delivered_delete = cls()

        purge_delivered_api_v1_webhooks_dlq_purge_delivered_delete_response_purge_delivered_api_v1_webhooks_dlq_purge_delivered_delete.additional_properties = d
        return purge_delivered_api_v1_webhooks_dlq_purge_delivered_delete_response_purge_delivered_api_v1_webhooks_dlq_purge_delivered_delete

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
