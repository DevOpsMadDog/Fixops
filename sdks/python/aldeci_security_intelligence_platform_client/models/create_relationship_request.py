from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="CreateRelationshipRequest")


@_attrs_define
class CreateRelationshipRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        src_ci_id (str): Source CI identifier
        dst_ci_id (str): Destination CI identifier
        rel_type (str): depends_on | hosts | connects_to | backs_up | manages
    """

    org_id: str
    src_ci_id: str
    dst_ci_id: str
    rel_type: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        src_ci_id = self.src_ci_id

        dst_ci_id = self.dst_ci_id

        rel_type = self.rel_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "src_ci_id": src_ci_id,
                "dst_ci_id": dst_ci_id,
                "rel_type": rel_type,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        src_ci_id = d.pop("src_ci_id")

        dst_ci_id = d.pop("dst_ci_id")

        rel_type = d.pop("rel_type")

        create_relationship_request = cls(
            org_id=org_id,
            src_ci_id=src_ci_id,
            dst_ci_id=dst_ci_id,
            rel_type=rel_type,
        )

        create_relationship_request.additional_properties = d
        return create_relationship_request

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
