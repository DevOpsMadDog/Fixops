from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ModelCreate")


@_attrs_define
class ModelCreate:
    """
    Attributes:
        model_name (str):
        model_type (str | Unset):  Default: 'llm'.
        vendor (str | Unset):  Default: ''.
        version (str | Unset):  Default: ''.
        deployment_status (str | Unset):  Default: 'development'.
        risk_level (str | Unset):  Default: 'medium'.
        use_case (str | Unset):  Default: ''.
        data_classification (str | Unset):  Default: 'internal'.
    """

    model_name: str
    model_type: str | Unset = "llm"
    vendor: str | Unset = ""
    version: str | Unset = ""
    deployment_status: str | Unset = "development"
    risk_level: str | Unset = "medium"
    use_case: str | Unset = ""
    data_classification: str | Unset = "internal"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        model_name = self.model_name

        model_type = self.model_type

        vendor = self.vendor

        version = self.version

        deployment_status = self.deployment_status

        risk_level = self.risk_level

        use_case = self.use_case

        data_classification = self.data_classification

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "model_name": model_name,
            }
        )
        if model_type is not UNSET:
            field_dict["model_type"] = model_type
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if version is not UNSET:
            field_dict["version"] = version
        if deployment_status is not UNSET:
            field_dict["deployment_status"] = deployment_status
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level
        if use_case is not UNSET:
            field_dict["use_case"] = use_case
        if data_classification is not UNSET:
            field_dict["data_classification"] = data_classification

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        model_name = d.pop("model_name")

        model_type = d.pop("model_type", UNSET)

        vendor = d.pop("vendor", UNSET)

        version = d.pop("version", UNSET)

        deployment_status = d.pop("deployment_status", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        use_case = d.pop("use_case", UNSET)

        data_classification = d.pop("data_classification", UNSET)

        model_create = cls(
            model_name=model_name,
            model_type=model_type,
            vendor=vendor,
            version=version,
            deployment_status=deployment_status,
            risk_level=risk_level,
            use_case=use_case,
            data_classification=data_classification,
        )

        model_create.additional_properties = d
        return model_create

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
