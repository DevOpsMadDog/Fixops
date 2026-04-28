from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.profile_create_attributes import ProfileCreateAttributes


T = TypeVar("T", bound="ProfileCreate")


@_attrs_define
class ProfileCreate:
    """
    Attributes:
        user_id (str):
        identity_level (str | Unset):  Default: 'ial1'.
        verification_method (str | Unset):  Default: 'self_asserted'.
        assurance_level (str | Unset):  Default: 'aal1'.
        attributes (ProfileCreateAttributes | Unset):
    """

    user_id: str
    identity_level: str | Unset = "ial1"
    verification_method: str | Unset = "self_asserted"
    assurance_level: str | Unset = "aal1"
    attributes: ProfileCreateAttributes | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        identity_level = self.identity_level

        verification_method = self.verification_method

        assurance_level = self.assurance_level

        attributes: dict[str, Any] | Unset = UNSET
        if not isinstance(self.attributes, Unset):
            attributes = self.attributes.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_id": user_id,
            }
        )
        if identity_level is not UNSET:
            field_dict["identity_level"] = identity_level
        if verification_method is not UNSET:
            field_dict["verification_method"] = verification_method
        if assurance_level is not UNSET:
            field_dict["assurance_level"] = assurance_level
        if attributes is not UNSET:
            field_dict["attributes"] = attributes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.profile_create_attributes import ProfileCreateAttributes

        d = dict(src_dict)
        user_id = d.pop("user_id")

        identity_level = d.pop("identity_level", UNSET)

        verification_method = d.pop("verification_method", UNSET)

        assurance_level = d.pop("assurance_level", UNSET)

        _attributes = d.pop("attributes", UNSET)
        attributes: ProfileCreateAttributes | Unset
        if isinstance(_attributes, Unset):
            attributes = UNSET
        else:
            attributes = ProfileCreateAttributes.from_dict(_attributes)

        profile_create = cls(
            user_id=user_id,
            identity_level=identity_level,
            verification_method=verification_method,
            assurance_level=assurance_level,
            attributes=attributes,
        )

        profile_create.additional_properties = d
        return profile_create

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
