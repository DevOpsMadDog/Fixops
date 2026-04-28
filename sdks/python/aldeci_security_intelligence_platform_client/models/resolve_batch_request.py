from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ResolveBatchRequest")


@_attrs_define
class ResolveBatchRequest:
    """
    Attributes:
        names (list[str]):
        org_id (None | str | Unset):
        threshold (float | Unset):  Default: 0.65.
    """

    names: list[str]
    org_id: None | str | Unset = UNSET
    threshold: float | Unset = 0.65
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        names = self.names

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        threshold = self.threshold

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "names": names,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if threshold is not UNSET:
            field_dict["threshold"] = threshold

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        names = cast(list[str], d.pop("names"))

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        threshold = d.pop("threshold", UNSET)

        resolve_batch_request = cls(
            names=names,
            org_id=org_id,
            threshold=threshold,
        )

        resolve_batch_request.additional_properties = d
        return resolve_batch_request

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
