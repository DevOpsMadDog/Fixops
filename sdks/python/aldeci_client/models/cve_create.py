from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CVECreate")


@_attrs_define
class CVECreate:
    """
    Attributes:
        cve_id (str):
        title (str | Unset):  Default: ''.
        description (str | Unset):  Default: ''.
        cvss_score (float | Unset):  Default: 0.0.
        cvss_vector (str | Unset):  Default: ''.
        epss_score (float | Unset):  Default: 0.0.
        kev_listed (bool | Unset):  Default: False.
        kev_added_date (None | str | Unset):
        severity (str | Unset):  Default: 'medium'.
        affected_products (list[Any] | Unset):
        exploit_available (bool | Unset):  Default: False.
        exploit_type (None | str | Unset):
        patch_available (bool | Unset):  Default: False.
        patch_url (str | Unset):  Default: ''.
        references (list[str] | Unset):
        threat_actors_using (list[str] | Unset):
        affected_org_assets (list[str] | Unset):
        status (str | Unset):  Default: 'new'.
    """

    cve_id: str
    title: str | Unset = ""
    description: str | Unset = ""
    cvss_score: float | Unset = 0.0
    cvss_vector: str | Unset = ""
    epss_score: float | Unset = 0.0
    kev_listed: bool | Unset = False
    kev_added_date: None | str | Unset = UNSET
    severity: str | Unset = "medium"
    affected_products: list[Any] | Unset = UNSET
    exploit_available: bool | Unset = False
    exploit_type: None | str | Unset = UNSET
    patch_available: bool | Unset = False
    patch_url: str | Unset = ""
    references: list[str] | Unset = UNSET
    threat_actors_using: list[str] | Unset = UNSET
    affected_org_assets: list[str] | Unset = UNSET
    status: str | Unset = "new"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        title = self.title

        description = self.description

        cvss_score = self.cvss_score

        cvss_vector = self.cvss_vector

        epss_score = self.epss_score

        kev_listed = self.kev_listed

        kev_added_date: None | str | Unset
        if isinstance(self.kev_added_date, Unset):
            kev_added_date = UNSET
        else:
            kev_added_date = self.kev_added_date

        severity = self.severity

        affected_products: list[Any] | Unset = UNSET
        if not isinstance(self.affected_products, Unset):
            affected_products = self.affected_products

        exploit_available = self.exploit_available

        exploit_type: None | str | Unset
        if isinstance(self.exploit_type, Unset):
            exploit_type = UNSET
        else:
            exploit_type = self.exploit_type

        patch_available = self.patch_available

        patch_url = self.patch_url

        references: list[str] | Unset = UNSET
        if not isinstance(self.references, Unset):
            references = self.references

        threat_actors_using: list[str] | Unset = UNSET
        if not isinstance(self.threat_actors_using, Unset):
            threat_actors_using = self.threat_actors_using

        affected_org_assets: list[str] | Unset = UNSET
        if not isinstance(self.affected_org_assets, Unset):
            affected_org_assets = self.affected_org_assets

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
            }
        )
        if title is not UNSET:
            field_dict["title"] = title
        if description is not UNSET:
            field_dict["description"] = description
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if cvss_vector is not UNSET:
            field_dict["cvss_vector"] = cvss_vector
        if epss_score is not UNSET:
            field_dict["epss_score"] = epss_score
        if kev_listed is not UNSET:
            field_dict["kev_listed"] = kev_listed
        if kev_added_date is not UNSET:
            field_dict["kev_added_date"] = kev_added_date
        if severity is not UNSET:
            field_dict["severity"] = severity
        if affected_products is not UNSET:
            field_dict["affected_products"] = affected_products
        if exploit_available is not UNSET:
            field_dict["exploit_available"] = exploit_available
        if exploit_type is not UNSET:
            field_dict["exploit_type"] = exploit_type
        if patch_available is not UNSET:
            field_dict["patch_available"] = patch_available
        if patch_url is not UNSET:
            field_dict["patch_url"] = patch_url
        if references is not UNSET:
            field_dict["references"] = references
        if threat_actors_using is not UNSET:
            field_dict["threat_actors_using"] = threat_actors_using
        if affected_org_assets is not UNSET:
            field_dict["affected_org_assets"] = affected_org_assets
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        title = d.pop("title", UNSET)

        description = d.pop("description", UNSET)

        cvss_score = d.pop("cvss_score", UNSET)

        cvss_vector = d.pop("cvss_vector", UNSET)

        epss_score = d.pop("epss_score", UNSET)

        kev_listed = d.pop("kev_listed", UNSET)

        def _parse_kev_added_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        kev_added_date = _parse_kev_added_date(d.pop("kev_added_date", UNSET))

        severity = d.pop("severity", UNSET)

        affected_products = cast(list[Any], d.pop("affected_products", UNSET))

        exploit_available = d.pop("exploit_available", UNSET)

        def _parse_exploit_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        exploit_type = _parse_exploit_type(d.pop("exploit_type", UNSET))

        patch_available = d.pop("patch_available", UNSET)

        patch_url = d.pop("patch_url", UNSET)

        references = cast(list[str], d.pop("references", UNSET))

        threat_actors_using = cast(list[str], d.pop("threat_actors_using", UNSET))

        affected_org_assets = cast(list[str], d.pop("affected_org_assets", UNSET))

        status = d.pop("status", UNSET)

        cve_create = cls(
            cve_id=cve_id,
            title=title,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            epss_score=epss_score,
            kev_listed=kev_listed,
            kev_added_date=kev_added_date,
            severity=severity,
            affected_products=affected_products,
            exploit_available=exploit_available,
            exploit_type=exploit_type,
            patch_available=patch_available,
            patch_url=patch_url,
            references=references,
            threat_actors_using=threat_actors_using,
            affected_org_assets=affected_org_assets,
            status=status,
        )

        cve_create.additional_properties = d
        return cve_create

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
