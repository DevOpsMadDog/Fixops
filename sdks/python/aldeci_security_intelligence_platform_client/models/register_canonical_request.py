from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.register_canonical_request_properties_type_0 import RegisterCanonicalRequestPropertiesType0


T = TypeVar("T", bound="RegisterCanonicalRequest")


@_attrs_define
class RegisterCanonicalRequest:
    """
    Attributes:
        canonical_id (str): Unique canonical asset identifier
        org_id (None | str | Unset):
        properties (None | RegisterCanonicalRequestPropertiesType0 | Unset):
    """

    canonical_id: str
    org_id: None | str | Unset = UNSET
    properties: None | RegisterCanonicalRequestPropertiesType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.register_canonical_request_properties_type_0 import RegisterCanonicalRequestPropertiesType0

        canonical_id = self.canonical_id

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        properties: dict[str, Any] | None | Unset
        if isinstance(self.properties, Unset):
            properties = UNSET
        elif isinstance(self.properties, RegisterCanonicalRequestPropertiesType0):
            properties = self.properties.to_dict()
        else:
            properties = self.properties

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "canonical_id": canonical_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if properties is not UNSET:
            field_dict["properties"] = properties

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.register_canonical_request_properties_type_0 import RegisterCanonicalRequestPropertiesType0

        d = dict(src_dict)
        canonical_id = d.pop("canonical_id")

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        def _parse_properties(data: object) -> None | RegisterCanonicalRequestPropertiesType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                properties_type_0 = RegisterCanonicalRequestPropertiesType0.from_dict(data)

                return properties_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RegisterCanonicalRequestPropertiesType0 | Unset, data)

        properties = _parse_properties(d.pop("properties", UNSET))

        register_canonical_request = cls(
            canonical_id=canonical_id,
            org_id=org_id,
            properties=properties,
        )

        register_canonical_request.additional_properties = d
        return register_canonical_request

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
