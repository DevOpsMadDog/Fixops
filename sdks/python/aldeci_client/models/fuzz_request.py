from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.fuzz_request_headers_type_0 import FuzzRequestHeadersType0
    from ..models.fuzz_request_openapi_spec import FuzzRequestOpenapiSpec


T = TypeVar("T", bound="FuzzRequest")


@_attrs_define
class FuzzRequest:
    """
    Attributes:
        base_url (str):
        openapi_spec (FuzzRequestOpenapiSpec):
        headers (FuzzRequestHeadersType0 | None | Unset):
        max_per_endpoint (int | Unset):  Default: 5.
    """

    base_url: str
    openapi_spec: FuzzRequestOpenapiSpec
    headers: FuzzRequestHeadersType0 | None | Unset = UNSET
    max_per_endpoint: int | Unset = 5
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.fuzz_request_headers_type_0 import FuzzRequestHeadersType0

        base_url = self.base_url

        openapi_spec = self.openapi_spec.to_dict()

        headers: dict[str, Any] | None | Unset
        if isinstance(self.headers, Unset):
            headers = UNSET
        elif isinstance(self.headers, FuzzRequestHeadersType0):
            headers = self.headers.to_dict()
        else:
            headers = self.headers

        max_per_endpoint = self.max_per_endpoint

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "base_url": base_url,
                "openapi_spec": openapi_spec,
            }
        )
        if headers is not UNSET:
            field_dict["headers"] = headers
        if max_per_endpoint is not UNSET:
            field_dict["max_per_endpoint"] = max_per_endpoint

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.fuzz_request_headers_type_0 import FuzzRequestHeadersType0
        from ..models.fuzz_request_openapi_spec import FuzzRequestOpenapiSpec

        d = dict(src_dict)
        base_url = d.pop("base_url")

        openapi_spec = FuzzRequestOpenapiSpec.from_dict(d.pop("openapi_spec"))

        def _parse_headers(data: object) -> FuzzRequestHeadersType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                headers_type_0 = FuzzRequestHeadersType0.from_dict(data)

                return headers_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(FuzzRequestHeadersType0 | None | Unset, data)

        headers = _parse_headers(d.pop("headers", UNSET))

        max_per_endpoint = d.pop("max_per_endpoint", UNSET)

        fuzz_request = cls(
            base_url=base_url,
            openapi_spec=openapi_spec,
            headers=headers,
            max_per_endpoint=max_per_endpoint,
        )

        fuzz_request.additional_properties = d
        return fuzz_request

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
