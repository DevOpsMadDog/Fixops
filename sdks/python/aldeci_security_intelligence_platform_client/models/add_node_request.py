from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddNodeRequest")


@_attrs_define
class AddNodeRequest:
    """
    Attributes:
        node_id (str): Unique node identifier (e.g. hostname or IP)
        node_type (str): Node type: workstation|server|database|cloud_service|network_device|external
        name (str): Human-readable node name
        risk_score (float | Unset): Risk score 0-100 Default: 50.0.
        is_crown_jewel (bool | Unset): Whether this node is a crown jewel asset Default: False.
        vulnerabilities (list[str] | Unset): CVE IDs present on this node
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    node_id: str
    node_type: str
    name: str
    risk_score: float | Unset = 50.0
    is_crown_jewel: bool | Unset = False
    vulnerabilities: list[str] | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        node_id = self.node_id

        node_type = self.node_type

        name = self.name

        risk_score = self.risk_score

        is_crown_jewel = self.is_crown_jewel

        vulnerabilities: list[str] | Unset = UNSET
        if not isinstance(self.vulnerabilities, Unset):
            vulnerabilities = self.vulnerabilities

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "node_id": node_id,
                "node_type": node_type,
                "name": name,
            }
        )
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if is_crown_jewel is not UNSET:
            field_dict["is_crown_jewel"] = is_crown_jewel
        if vulnerabilities is not UNSET:
            field_dict["vulnerabilities"] = vulnerabilities
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        node_id = d.pop("node_id")

        node_type = d.pop("node_type")

        name = d.pop("name")

        risk_score = d.pop("risk_score", UNSET)

        is_crown_jewel = d.pop("is_crown_jewel", UNSET)

        vulnerabilities = cast(list[str], d.pop("vulnerabilities", UNSET))

        org_id = d.pop("org_id", UNSET)

        add_node_request = cls(
            node_id=node_id,
            node_type=node_type,
            name=name,
            risk_score=risk_score,
            is_crown_jewel=is_crown_jewel,
            vulnerabilities=vulnerabilities,
            org_id=org_id,
        )

        add_node_request.additional_properties = d
        return add_node_request

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
