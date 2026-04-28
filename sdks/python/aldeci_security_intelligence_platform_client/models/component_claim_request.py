from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ComponentClaimRequest")


@_attrs_define
class ComponentClaimRequest:
    """
    Attributes:
        org_id (str): Organisation ID
        component_purl (str): Package URL
        claimant (str): Entity filing the claim
        claim_type (str | Unset): owner|maintainer|distributor|redistributor|builder Default: 'owner'.
        evidence_uri (str | Unset): URI to attestation evidence Default: ''.
        claimed_at (None | str | Unset): ISO-8601 timestamp
    """

    org_id: str
    component_purl: str
    claimant: str
    claim_type: str | Unset = "owner"
    evidence_uri: str | Unset = ""
    claimed_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        component_purl = self.component_purl

        claimant = self.claimant

        claim_type = self.claim_type

        evidence_uri = self.evidence_uri

        claimed_at: None | str | Unset
        if isinstance(self.claimed_at, Unset):
            claimed_at = UNSET
        else:
            claimed_at = self.claimed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "component_purl": component_purl,
                "claimant": claimant,
            }
        )
        if claim_type is not UNSET:
            field_dict["claim_type"] = claim_type
        if evidence_uri is not UNSET:
            field_dict["evidence_uri"] = evidence_uri
        if claimed_at is not UNSET:
            field_dict["claimed_at"] = claimed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        component_purl = d.pop("component_purl")

        claimant = d.pop("claimant")

        claim_type = d.pop("claim_type", UNSET)

        evidence_uri = d.pop("evidence_uri", UNSET)

        def _parse_claimed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        claimed_at = _parse_claimed_at(d.pop("claimed_at", UNSET))

        component_claim_request = cls(
            org_id=org_id,
            component_purl=component_purl,
            claimant=claimant,
            claim_type=claim_type,
            evidence_uri=evidence_uri,
            claimed_at=claimed_at,
        )

        component_claim_request.additional_properties = d
        return component_claim_request

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
