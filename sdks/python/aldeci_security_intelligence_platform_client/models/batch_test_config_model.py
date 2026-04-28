from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.batch_test_config_model_context import BatchTestConfigModelContext


T = TypeVar("T", bound="BatchTestConfigModel")


@_attrs_define
class BatchTestConfigModel:
    """Configuration for a single test in a batch.

    Security: list size limits prevent DoS via huge batch payloads.

        Attributes:
            cve_ids (list[str] | Unset): CVE IDs to test
            target_urls (list[str] | Unset): Target URLs to test
            context (BatchTestConfigModelContext | Unset): Optional context
    """

    cve_ids: list[str] | Unset = UNSET
    target_urls: list[str] | Unset = UNSET
    context: BatchTestConfigModelContext | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        target_urls: list[str] | Unset = UNSET
        if not isinstance(self.target_urls, Unset):
            target_urls = self.target_urls

        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if target_urls is not UNSET:
            field_dict["target_urls"] = target_urls
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.batch_test_config_model_context import BatchTestConfigModelContext

        d = dict(src_dict)
        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        target_urls = cast(list[str], d.pop("target_urls", UNSET))

        _context = d.pop("context", UNSET)
        context: BatchTestConfigModelContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = BatchTestConfigModelContext.from_dict(_context)

        batch_test_config_model = cls(
            cve_ids=cve_ids,
            target_urls=target_urls,
            context=context,
        )

        batch_test_config_model.additional_properties = d
        return batch_test_config_model

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
