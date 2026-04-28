from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SubscribeReevalRequest")


@_attrs_define
class SubscribeReevalRequest:
    """POST /api/v1/sbom/subscribe-for-reeval body.

    Attributes:
        sbom_id (str):
        cron_expr (str | Unset):  Default: '@daily'.
    """

    sbom_id: str
    cron_expr: str | Unset = "@daily"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        sbom_id = self.sbom_id

        cron_expr = self.cron_expr

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "sbom_id": sbom_id,
            }
        )
        if cron_expr is not UNSET:
            field_dict["cron_expr"] = cron_expr

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        sbom_id = d.pop("sbom_id")

        cron_expr = d.pop("cron_expr", UNSET)

        subscribe_reeval_request = cls(
            sbom_id=sbom_id,
            cron_expr=cron_expr,
        )

        subscribe_reeval_request.additional_properties = d
        return subscribe_reeval_request

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
