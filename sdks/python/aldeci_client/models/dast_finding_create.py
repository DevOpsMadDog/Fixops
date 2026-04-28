from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DASTFindingCreate")


@_attrs_define
class DASTFindingCreate:
    """
    Attributes:
        title (str):
        tool (str | Unset):  Default: 'zap'.
        endpoint (str | Unset):  Default: ''.
        method (str | Unset):  Default: 'GET'.
        category (str | Unset):  Default: 'injection'.
        severity (str | Unset):  Default: 'medium'.
        cvss_score (float | Unset):  Default: 0.0.
        request_sample (str | Unset):  Default: ''.
        response_sample (str | Unset):  Default: ''.
    """

    title: str
    tool: str | Unset = "zap"
    endpoint: str | Unset = ""
    method: str | Unset = "GET"
    category: str | Unset = "injection"
    severity: str | Unset = "medium"
    cvss_score: float | Unset = 0.0
    request_sample: str | Unset = ""
    response_sample: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        tool = self.tool

        endpoint = self.endpoint

        method = self.method

        category = self.category

        severity = self.severity

        cvss_score = self.cvss_score

        request_sample = self.request_sample

        response_sample = self.response_sample

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if tool is not UNSET:
            field_dict["tool"] = tool
        if endpoint is not UNSET:
            field_dict["endpoint"] = endpoint
        if method is not UNSET:
            field_dict["method"] = method
        if category is not UNSET:
            field_dict["category"] = category
        if severity is not UNSET:
            field_dict["severity"] = severity
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if request_sample is not UNSET:
            field_dict["request_sample"] = request_sample
        if response_sample is not UNSET:
            field_dict["response_sample"] = response_sample

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        tool = d.pop("tool", UNSET)

        endpoint = d.pop("endpoint", UNSET)

        method = d.pop("method", UNSET)

        category = d.pop("category", UNSET)

        severity = d.pop("severity", UNSET)

        cvss_score = d.pop("cvss_score", UNSET)

        request_sample = d.pop("request_sample", UNSET)

        response_sample = d.pop("response_sample", UNSET)

        dast_finding_create = cls(
            title=title,
            tool=tool,
            endpoint=endpoint,
            method=method,
            category=category,
            severity=severity,
            cvss_score=cvss_score,
            request_sample=request_sample,
            response_sample=response_sample,
        )

        dast_finding_create.additional_properties = d
        return dast_finding_create

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
