from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReconcileRequest")


@_attrs_define
class ReconcileRequest:
    """Body for POST /reconcile.

    Attributes:
        prior_scan_id (str): The previous scan run id
        current_scan_id (str): The current scan run id
        org_id (str | Unset): Tenant org identifier Default: 'default'.
    """

    prior_scan_id: str
    current_scan_id: str
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        prior_scan_id = self.prior_scan_id

        current_scan_id = self.current_scan_id

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "prior_scan_id": prior_scan_id,
                "current_scan_id": current_scan_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        prior_scan_id = d.pop("prior_scan_id")

        current_scan_id = d.pop("current_scan_id")

        org_id = d.pop("org_id", UNSET)

        reconcile_request = cls(
            prior_scan_id=prior_scan_id,
            current_scan_id=current_scan_id,
            org_id=org_id,
        )

        reconcile_request.additional_properties = d
        return reconcile_request

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
