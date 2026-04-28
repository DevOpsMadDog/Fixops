from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateDomainRequest")


@_attrs_define
class UpdateDomainRequest:
    """
    Attributes:
        spf_record (None | str | Unset):
        spf_status (None | str | Unset):
        dkim_selector (None | str | Unset):
        dkim_status (None | str | Unset):
        dmarc_policy (None | str | Unset):
    """

    spf_record: None | str | Unset = UNSET
    spf_status: None | str | Unset = UNSET
    dkim_selector: None | str | Unset = UNSET
    dkim_status: None | str | Unset = UNSET
    dmarc_policy: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        spf_record: None | str | Unset
        if isinstance(self.spf_record, Unset):
            spf_record = UNSET
        else:
            spf_record = self.spf_record

        spf_status: None | str | Unset
        if isinstance(self.spf_status, Unset):
            spf_status = UNSET
        else:
            spf_status = self.spf_status

        dkim_selector: None | str | Unset
        if isinstance(self.dkim_selector, Unset):
            dkim_selector = UNSET
        else:
            dkim_selector = self.dkim_selector

        dkim_status: None | str | Unset
        if isinstance(self.dkim_status, Unset):
            dkim_status = UNSET
        else:
            dkim_status = self.dkim_status

        dmarc_policy: None | str | Unset
        if isinstance(self.dmarc_policy, Unset):
            dmarc_policy = UNSET
        else:
            dmarc_policy = self.dmarc_policy

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if spf_record is not UNSET:
            field_dict["spf_record"] = spf_record
        if spf_status is not UNSET:
            field_dict["spf_status"] = spf_status
        if dkim_selector is not UNSET:
            field_dict["dkim_selector"] = dkim_selector
        if dkim_status is not UNSET:
            field_dict["dkim_status"] = dkim_status
        if dmarc_policy is not UNSET:
            field_dict["dmarc_policy"] = dmarc_policy

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_spf_record(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        spf_record = _parse_spf_record(d.pop("spf_record", UNSET))

        def _parse_spf_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        spf_status = _parse_spf_status(d.pop("spf_status", UNSET))

        def _parse_dkim_selector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dkim_selector = _parse_dkim_selector(d.pop("dkim_selector", UNSET))

        def _parse_dkim_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dkim_status = _parse_dkim_status(d.pop("dkim_status", UNSET))

        def _parse_dmarc_policy(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dmarc_policy = _parse_dmarc_policy(d.pop("dmarc_policy", UNSET))

        update_domain_request = cls(
            spf_record=spf_record,
            spf_status=spf_status,
            dkim_selector=dkim_selector,
            dkim_status=dkim_status,
            dmarc_policy=dmarc_policy,
        )

        update_domain_request.additional_properties = d
        return update_domain_request

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
