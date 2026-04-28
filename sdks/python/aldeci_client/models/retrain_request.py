from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RetrainRequest")


@_attrs_define
class RetrainRequest:
    """Request to retrain ML models on new vulnerability data.

    Attributes:
        vuln_ids (list[str] | Unset): Specific vulns to include in training
        model_types (list[str] | Unset): Models to retrain
        include_external (bool | Unset): Also include external CVE data Default: True.
        force_retrain (bool | Unset): Retrain even if not enough new data Default: False.
    """

    vuln_ids: list[str] | Unset = UNSET
    model_types: list[str] | Unset = UNSET
    include_external: bool | Unset = True
    force_retrain: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vuln_ids: list[str] | Unset = UNSET
        if not isinstance(self.vuln_ids, Unset):
            vuln_ids = self.vuln_ids

        model_types: list[str] | Unset = UNSET
        if not isinstance(self.model_types, Unset):
            model_types = self.model_types

        include_external = self.include_external

        force_retrain = self.force_retrain

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if vuln_ids is not UNSET:
            field_dict["vuln_ids"] = vuln_ids
        if model_types is not UNSET:
            field_dict["model_types"] = model_types
        if include_external is not UNSET:
            field_dict["include_external"] = include_external
        if force_retrain is not UNSET:
            field_dict["force_retrain"] = force_retrain

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        vuln_ids = cast(list[str], d.pop("vuln_ids", UNSET))

        model_types = cast(list[str], d.pop("model_types", UNSET))

        include_external = d.pop("include_external", UNSET)

        force_retrain = d.pop("force_retrain", UNSET)

        retrain_request = cls(
            vuln_ids=vuln_ids,
            model_types=model_types,
            include_external=include_external,
            force_retrain=force_retrain,
        )

        retrain_request.additional_properties = d
        return retrain_request

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
