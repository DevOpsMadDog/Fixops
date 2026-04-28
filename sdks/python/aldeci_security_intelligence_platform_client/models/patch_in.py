from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PatchIn")


@_attrs_define
class PatchIn:
    """
    Attributes:
        patch_id (str):
        vendor (str | Unset):  Default: ''.
        product (str | Unset):  Default: ''.
        version (str | Unset):  Default: ''.
        patch_type (str | Unset):  Default: 'security'.
        cves_addressed (list[str] | Unset):
        severity (str | Unset):  Default: 'medium'.
        release_date (None | str | Unset):
        kb_article (str | Unset):  Default: ''.
        download_url (str | Unset):  Default: ''.
        status (str | Unset):  Default: 'available'.
    """

    patch_id: str
    vendor: str | Unset = ""
    product: str | Unset = ""
    version: str | Unset = ""
    patch_type: str | Unset = "security"
    cves_addressed: list[str] | Unset = UNSET
    severity: str | Unset = "medium"
    release_date: None | str | Unset = UNSET
    kb_article: str | Unset = ""
    download_url: str | Unset = ""
    status: str | Unset = "available"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        patch_id = self.patch_id

        vendor = self.vendor

        product = self.product

        version = self.version

        patch_type = self.patch_type

        cves_addressed: list[str] | Unset = UNSET
        if not isinstance(self.cves_addressed, Unset):
            cves_addressed = self.cves_addressed

        severity = self.severity

        release_date: None | str | Unset
        if isinstance(self.release_date, Unset):
            release_date = UNSET
        else:
            release_date = self.release_date

        kb_article = self.kb_article

        download_url = self.download_url

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "patch_id": patch_id,
            }
        )
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if product is not UNSET:
            field_dict["product"] = product
        if version is not UNSET:
            field_dict["version"] = version
        if patch_type is not UNSET:
            field_dict["patch_type"] = patch_type
        if cves_addressed is not UNSET:
            field_dict["cves_addressed"] = cves_addressed
        if severity is not UNSET:
            field_dict["severity"] = severity
        if release_date is not UNSET:
            field_dict["release_date"] = release_date
        if kb_article is not UNSET:
            field_dict["kb_article"] = kb_article
        if download_url is not UNSET:
            field_dict["download_url"] = download_url
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        patch_id = d.pop("patch_id")

        vendor = d.pop("vendor", UNSET)

        product = d.pop("product", UNSET)

        version = d.pop("version", UNSET)

        patch_type = d.pop("patch_type", UNSET)

        cves_addressed = cast(list[str], d.pop("cves_addressed", UNSET))

        severity = d.pop("severity", UNSET)

        def _parse_release_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        release_date = _parse_release_date(d.pop("release_date", UNSET))

        kb_article = d.pop("kb_article", UNSET)

        download_url = d.pop("download_url", UNSET)

        status = d.pop("status", UNSET)

        patch_in = cls(
            patch_id=patch_id,
            vendor=vendor,
            product=product,
            version=version,
            patch_type=patch_type,
            cves_addressed=cves_addressed,
            severity=severity,
            release_date=release_date,
            kb_article=kb_article,
            download_url=download_url,
            status=status,
        )

        patch_in.additional_properties = d
        return patch_in

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
