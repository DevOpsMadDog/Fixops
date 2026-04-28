from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.index_entity_request_data import IndexEntityRequestData


T = TypeVar("T", bound="IndexEntityRequest")


@_attrs_define
class IndexEntityRequest:
    """Index any ALDECI entity into TrustGraph.

    Attributes:
        entity_type (str): One of: finding, asset, incident, compliance_control, vendor, threat_actor
        data (IndexEntityRequestData): Entity data payload
        org_id (None | str | Unset): Tenant org ID Default: 'default'.
    """

    entity_type: str
    data: IndexEntityRequestData
    org_id: None | str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity_type = self.entity_type

        data = self.data.to_dict()

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_type": entity_type,
                "data": data,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.index_entity_request_data import IndexEntityRequestData

        d = dict(src_dict)
        entity_type = d.pop("entity_type")

        data = IndexEntityRequestData.from_dict(d.pop("data"))

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        index_entity_request = cls(
            entity_type=entity_type,
            data=data,
            org_id=org_id,
        )

        index_entity_request.additional_properties = d
        return index_entity_request

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
