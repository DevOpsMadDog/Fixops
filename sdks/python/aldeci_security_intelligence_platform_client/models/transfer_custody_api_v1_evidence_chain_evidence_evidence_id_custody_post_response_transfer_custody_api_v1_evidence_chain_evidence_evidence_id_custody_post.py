from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar(
    "T",
    bound="TransferCustodyApiV1EvidenceChainEvidenceEvidenceIdCustodyPostResponseTransferCustodyApiV1EvidenceChainEvidenceEvidenceIdCustodyPost",
)


@_attrs_define
class TransferCustodyApiV1EvidenceChainEvidenceEvidenceIdCustodyPostResponseTransferCustodyApiV1EvidenceChainEvidenceEvidenceIdCustodyPost:
    """ """

    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        transfer_custody_api_v1_evidence_chain_evidence_evidence_id_custody_post_response_transfer_custody_api_v1_evidence_chain_evidence_evidence_id_custody_post = cls()

        transfer_custody_api_v1_evidence_chain_evidence_evidence_id_custody_post_response_transfer_custody_api_v1_evidence_chain_evidence_evidence_id_custody_post.additional_properties = d
        return transfer_custody_api_v1_evidence_chain_evidence_evidence_id_custody_post_response_transfer_custody_api_v1_evidence_chain_evidence_evidence_id_custody_post

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
