from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScanOutputRequest")


@_attrs_define
class ScanOutputRequest:
    """
    Attributes:
        prompt (str): Original prompt
        output (str): LLM output to scan
        fail_fast (bool | Unset): Stop on first detected issue Default: True.
    """

    prompt: str
    output: str
    fail_fast: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        prompt = self.prompt

        output = self.output

        fail_fast = self.fail_fast

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "prompt": prompt,
                "output": output,
            }
        )
        if fail_fast is not UNSET:
            field_dict["fail_fast"] = fail_fast

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        prompt = d.pop("prompt")

        output = d.pop("output")

        fail_fast = d.pop("fail_fast", UNSET)

        scan_output_request = cls(
            prompt=prompt,
            output=output,
            fail_fast=fail_fast,
        )

        scan_output_request.additional_properties = d
        return scan_output_request

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
