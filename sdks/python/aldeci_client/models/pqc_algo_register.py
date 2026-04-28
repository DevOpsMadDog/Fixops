from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="PQCAlgoRegister")


@_attrs_define
class PQCAlgoRegister:
    """
    Attributes:
        org_id (str):
        service_ref (str):
        algo (str):
        category (str):
    """

    org_id: str
    service_ref: str
    algo: str
    category: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        service_ref = self.service_ref

        algo = self.algo

        category = self.category

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "service_ref": service_ref,
                "algo": algo,
                "category": category,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        service_ref = d.pop("service_ref")

        algo = d.pop("algo")

        category = d.pop("category")

        pqc_algo_register = cls(
            org_id=org_id,
            service_ref=service_ref,
            algo=algo,
            category=category,
        )

        pqc_algo_register.additional_properties = d
        return pqc_algo_register

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
