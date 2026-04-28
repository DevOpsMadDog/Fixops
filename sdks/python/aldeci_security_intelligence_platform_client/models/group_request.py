from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GroupRequest")


@_attrs_define
class GroupRequest:
    """
    Attributes:
        org_id (str):
        signal_ids (list[str]):
        group_name (None | str | Unset):
        ingest_into_correlation (bool | Unset):  Default: True.
    """

    org_id: str
    signal_ids: list[str]
    group_name: None | str | Unset = UNSET
    ingest_into_correlation: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        signal_ids = self.signal_ids

        group_name: None | str | Unset
        if isinstance(self.group_name, Unset):
            group_name = UNSET
        else:
            group_name = self.group_name

        ingest_into_correlation = self.ingest_into_correlation

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "signal_ids": signal_ids,
            }
        )
        if group_name is not UNSET:
            field_dict["group_name"] = group_name
        if ingest_into_correlation is not UNSET:
            field_dict["ingest_into_correlation"] = ingest_into_correlation

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        signal_ids = cast(list[str], d.pop("signal_ids"))

        def _parse_group_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        group_name = _parse_group_name(d.pop("group_name", UNSET))

        ingest_into_correlation = d.pop("ingest_into_correlation", UNSET)

        group_request = cls(
            org_id=org_id,
            signal_ids=signal_ids,
            group_name=group_name,
            ingest_into_correlation=ingest_into_correlation,
        )

        group_request.additional_properties = d
        return group_request

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
