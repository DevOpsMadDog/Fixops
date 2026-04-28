from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.outbox_request_payload import OutboxRequestPayload


T = TypeVar("T", bound="OutboxRequest")


@_attrs_define
class OutboxRequest:
    """Request to queue an outbound sync operation.

    Attributes:
        integration_type (str):
        operation (str):
        payload (OutboxRequestPayload):
        cluster_id (None | str | Unset):
        external_id (None | str | Unset):
        max_retries (int | Unset):  Default: 3.
    """

    integration_type: str
    operation: str
    payload: OutboxRequestPayload
    cluster_id: None | str | Unset = UNSET
    external_id: None | str | Unset = UNSET
    max_retries: int | Unset = 3
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        integration_type = self.integration_type

        operation = self.operation

        payload = self.payload.to_dict()

        cluster_id: None | str | Unset
        if isinstance(self.cluster_id, Unset):
            cluster_id = UNSET
        else:
            cluster_id = self.cluster_id

        external_id: None | str | Unset
        if isinstance(self.external_id, Unset):
            external_id = UNSET
        else:
            external_id = self.external_id

        max_retries = self.max_retries

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "integration_type": integration_type,
                "operation": operation,
                "payload": payload,
            }
        )
        if cluster_id is not UNSET:
            field_dict["cluster_id"] = cluster_id
        if external_id is not UNSET:
            field_dict["external_id"] = external_id
        if max_retries is not UNSET:
            field_dict["max_retries"] = max_retries

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.outbox_request_payload import OutboxRequestPayload

        d = dict(src_dict)
        integration_type = d.pop("integration_type")

        operation = d.pop("operation")

        payload = OutboxRequestPayload.from_dict(d.pop("payload"))

        def _parse_cluster_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cluster_id = _parse_cluster_id(d.pop("cluster_id", UNSET))

        def _parse_external_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        external_id = _parse_external_id(d.pop("external_id", UNSET))

        max_retries = d.pop("max_retries", UNSET)

        outbox_request = cls(
            integration_type=integration_type,
            operation=operation,
            payload=payload,
            cluster_id=cluster_id,
            external_id=external_id,
            max_retries=max_retries,
        )

        outbox_request.additional_properties = d
        return outbox_request

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
