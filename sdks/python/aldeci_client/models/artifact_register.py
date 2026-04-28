from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ArtifactRegister")


@_attrs_define
class ArtifactRegister:
    """
    Attributes:
        artifact_name (str): Name of the security artifact
        artifact_type (str | Unset): policy | standard | procedure | guideline | control | framework | tool | runbook
            Default: 'policy'.
        version (str | Unset):  Default: '1.0'.
        artifact_status (str | Unset): draft | active | deprecated | under_review | archived Default: 'draft'.
        description (str | Unset):  Default: ''.
        owner (str | Unset):  Default: ''.
        review_date (None | str | Unset):
        next_review_date (None | str | Unset):
        reviewer (str | Unset):  Default: ''.
        download_url (str | Unset):  Default: ''.
        tag_list (list[str] | Unset):
    """

    artifact_name: str
    artifact_type: str | Unset = "policy"
    version: str | Unset = "1.0"
    artifact_status: str | Unset = "draft"
    description: str | Unset = ""
    owner: str | Unset = ""
    review_date: None | str | Unset = UNSET
    next_review_date: None | str | Unset = UNSET
    reviewer: str | Unset = ""
    download_url: str | Unset = ""
    tag_list: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        artifact_name = self.artifact_name

        artifact_type = self.artifact_type

        version = self.version

        artifact_status = self.artifact_status

        description = self.description

        owner = self.owner

        review_date: None | str | Unset
        if isinstance(self.review_date, Unset):
            review_date = UNSET
        else:
            review_date = self.review_date

        next_review_date: None | str | Unset
        if isinstance(self.next_review_date, Unset):
            next_review_date = UNSET
        else:
            next_review_date = self.next_review_date

        reviewer = self.reviewer

        download_url = self.download_url

        tag_list: list[str] | Unset = UNSET
        if not isinstance(self.tag_list, Unset):
            tag_list = self.tag_list

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "artifact_name": artifact_name,
            }
        )
        if artifact_type is not UNSET:
            field_dict["artifact_type"] = artifact_type
        if version is not UNSET:
            field_dict["version"] = version
        if artifact_status is not UNSET:
            field_dict["artifact_status"] = artifact_status
        if description is not UNSET:
            field_dict["description"] = description
        if owner is not UNSET:
            field_dict["owner"] = owner
        if review_date is not UNSET:
            field_dict["review_date"] = review_date
        if next_review_date is not UNSET:
            field_dict["next_review_date"] = next_review_date
        if reviewer is not UNSET:
            field_dict["reviewer"] = reviewer
        if download_url is not UNSET:
            field_dict["download_url"] = download_url
        if tag_list is not UNSET:
            field_dict["tag_list"] = tag_list

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        artifact_name = d.pop("artifact_name")

        artifact_type = d.pop("artifact_type", UNSET)

        version = d.pop("version", UNSET)

        artifact_status = d.pop("artifact_status", UNSET)

        description = d.pop("description", UNSET)

        owner = d.pop("owner", UNSET)

        def _parse_review_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        review_date = _parse_review_date(d.pop("review_date", UNSET))

        def _parse_next_review_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        next_review_date = _parse_next_review_date(d.pop("next_review_date", UNSET))

        reviewer = d.pop("reviewer", UNSET)

        download_url = d.pop("download_url", UNSET)

        tag_list = cast(list[str], d.pop("tag_list", UNSET))

        artifact_register = cls(
            artifact_name=artifact_name,
            artifact_type=artifact_type,
            version=version,
            artifact_status=artifact_status,
            description=description,
            owner=owner,
            review_date=review_date,
            next_review_date=next_review_date,
            reviewer=reviewer,
            download_url=download_url,
            tag_list=tag_list,
        )

        artifact_register.additional_properties = d
        return artifact_register

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
