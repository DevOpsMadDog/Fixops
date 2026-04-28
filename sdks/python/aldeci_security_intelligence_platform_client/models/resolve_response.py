from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.resolve_response_owner_type_0 import ResolveResponseOwnerType0


T = TypeVar("T", bound="ResolveResponse")


@_attrs_define
class ResolveResponse:
    """
    Attributes:
        file_path (str):
        resolved (bool):
        owner (None | ResolveResponseOwnerType0 | Unset):
    """

    file_path: str
    resolved: bool
    owner: None | ResolveResponseOwnerType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.resolve_response_owner_type_0 import ResolveResponseOwnerType0

        file_path = self.file_path

        resolved = self.resolved

        owner: dict[str, Any] | None | Unset
        if isinstance(self.owner, Unset):
            owner = UNSET
        elif isinstance(self.owner, ResolveResponseOwnerType0):
            owner = self.owner.to_dict()
        else:
            owner = self.owner

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "file_path": file_path,
                "resolved": resolved,
            }
        )
        if owner is not UNSET:
            field_dict["owner"] = owner

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.resolve_response_owner_type_0 import ResolveResponseOwnerType0

        d = dict(src_dict)
        file_path = d.pop("file_path")

        resolved = d.pop("resolved")

        def _parse_owner(data: object) -> None | ResolveResponseOwnerType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                owner_type_0 = ResolveResponseOwnerType0.from_dict(data)

                return owner_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | ResolveResponseOwnerType0 | Unset, data)

        owner = _parse_owner(d.pop("owner", UNSET))

        resolve_response = cls(
            file_path=file_path,
            resolved=resolved,
            owner=owner,
        )

        resolve_response.additional_properties = d
        return resolve_response

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
