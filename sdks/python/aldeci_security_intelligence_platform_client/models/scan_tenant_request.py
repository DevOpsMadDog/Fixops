from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScanTenantRequest")


@_attrs_define
class ScanTenantRequest:
    """
    Attributes:
        tenant (str): Tenant directory name under fleet root
        org_id (str | Unset): Organization id for ingestion Default: 'default'.
        build_image (bool | Unset): Build+scan Dockerfile if present Default: True.
    """

    tenant: str
    org_id: str | Unset = "default"
    build_image: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tenant = self.tenant

        org_id = self.org_id

        build_image = self.build_image

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "tenant": tenant,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if build_image is not UNSET:
            field_dict["build_image"] = build_image

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        tenant = d.pop("tenant")

        org_id = d.pop("org_id", UNSET)

        build_image = d.pop("build_image", UNSET)

        scan_tenant_request = cls(
            tenant=tenant,
            org_id=org_id,
            build_image=build_image,
        )

        scan_tenant_request.additional_properties = d
        return scan_tenant_request

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
