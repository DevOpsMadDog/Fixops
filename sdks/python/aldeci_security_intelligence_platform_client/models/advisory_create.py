from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AdvisoryCreate")


@_attrs_define
class AdvisoryCreate:
    """
    Attributes:
        vendor (str):
        advisory_id (str | Unset):  Default: ''.
        product (str | Unset):  Default: ''.
        severity (str | Unset):  Default: 'medium'.
        advisory_url (str | Unset):  Default: ''.
        cves_covered (list[str] | Unset):
        patch_version (str | Unset):  Default: ''.
        release_date (str | Unset):  Default: ''.
        status (str | Unset):  Default: 'new'.
    """

    vendor: str
    advisory_id: str | Unset = ""
    product: str | Unset = ""
    severity: str | Unset = "medium"
    advisory_url: str | Unset = ""
    cves_covered: list[str] | Unset = UNSET
    patch_version: str | Unset = ""
    release_date: str | Unset = ""
    status: str | Unset = "new"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vendor = self.vendor

        advisory_id = self.advisory_id

        product = self.product

        severity = self.severity

        advisory_url = self.advisory_url

        cves_covered: list[str] | Unset = UNSET
        if not isinstance(self.cves_covered, Unset):
            cves_covered = self.cves_covered

        patch_version = self.patch_version

        release_date = self.release_date

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vendor": vendor,
            }
        )
        if advisory_id is not UNSET:
            field_dict["advisory_id"] = advisory_id
        if product is not UNSET:
            field_dict["product"] = product
        if severity is not UNSET:
            field_dict["severity"] = severity
        if advisory_url is not UNSET:
            field_dict["advisory_url"] = advisory_url
        if cves_covered is not UNSET:
            field_dict["cves_covered"] = cves_covered
        if patch_version is not UNSET:
            field_dict["patch_version"] = patch_version
        if release_date is not UNSET:
            field_dict["release_date"] = release_date
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        vendor = d.pop("vendor")

        advisory_id = d.pop("advisory_id", UNSET)

        product = d.pop("product", UNSET)

        severity = d.pop("severity", UNSET)

        advisory_url = d.pop("advisory_url", UNSET)

        cves_covered = cast(list[str], d.pop("cves_covered", UNSET))

        patch_version = d.pop("patch_version", UNSET)

        release_date = d.pop("release_date", UNSET)

        status = d.pop("status", UNSET)

        advisory_create = cls(
            vendor=vendor,
            advisory_id=advisory_id,
            product=product,
            severity=severity,
            advisory_url=advisory_url,
            cves_covered=cves_covered,
            patch_version=patch_version,
            release_date=release_date,
            status=status,
        )

        advisory_create.additional_properties = d
        return advisory_create

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
