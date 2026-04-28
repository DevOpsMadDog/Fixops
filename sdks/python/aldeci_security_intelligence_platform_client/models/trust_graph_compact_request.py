from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TrustGraphCompactRequest")


@_attrs_define
class TrustGraphCompactRequest:
    """
    Attributes:
        cores (list[int] | None | Unset):
        dry_run (bool | Unset):  Default: False.
    """

    cores: list[int] | None | Unset = UNSET
    dry_run: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cores: list[int] | None | Unset
        if isinstance(self.cores, Unset):
            cores = UNSET
        elif isinstance(self.cores, list):
            cores = self.cores

        else:
            cores = self.cores

        dry_run = self.dry_run

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cores is not UNSET:
            field_dict["cores"] = cores
        if dry_run is not UNSET:
            field_dict["dry_run"] = dry_run

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_cores(data: object) -> list[int] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                cores_type_0 = cast(list[int], data)

                return cores_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[int] | None | Unset, data)

        cores = _parse_cores(d.pop("cores", UNSET))

        dry_run = d.pop("dry_run", UNSET)

        trust_graph_compact_request = cls(
            cores=cores,
            dry_run=dry_run,
        )

        trust_graph_compact_request.additional_properties = d
        return trust_graph_compact_request

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
