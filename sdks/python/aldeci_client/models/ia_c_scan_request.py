from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IaCScanRequest")


@_attrs_define
class IaCScanRequest:
    """
    Attributes:
        template_text (str): Raw IaC template content (Terraform HCL or CloudFormation JSON)
        template_type (str | Unset): Template type: 'terraform', 'cloudformation', or 'auto' (detected by content)
            Default: 'auto'.
        filename (str | Unset): Optional filename for context Default: 'template'.
    """

    template_text: str
    template_type: str | Unset = "auto"
    filename: str | Unset = "template"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        template_text = self.template_text

        template_type = self.template_type

        filename = self.filename

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "template_text": template_text,
            }
        )
        if template_type is not UNSET:
            field_dict["template_type"] = template_type
        if filename is not UNSET:
            field_dict["filename"] = filename

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        template_text = d.pop("template_text")

        template_type = d.pop("template_type", UNSET)

        filename = d.pop("filename", UNSET)

        ia_c_scan_request = cls(
            template_text=template_text,
            template_type=template_type,
            filename=filename,
        )

        ia_c_scan_request.additional_properties = d
        return ia_c_scan_request

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
