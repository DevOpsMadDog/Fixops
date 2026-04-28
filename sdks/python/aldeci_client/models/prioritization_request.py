from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.prioritization_request_business_context_type_0 import PrioritizationRequestBusinessContextType0


T = TypeVar("T", bound="PrioritizationRequest")


@_attrs_define
class PrioritizationRequest:
    """Request for vulnerability prioritization.

    Attributes:
        finding_ids (list[str] | Unset):
        algorithm (str | Unset): ssvc, epss, cvss, custom Default: 'ssvc'.
        business_context (None | PrioritizationRequestBusinessContextType0 | Unset):
    """

    finding_ids: list[str] | Unset = UNSET
    algorithm: str | Unset = "ssvc"
    business_context: None | PrioritizationRequestBusinessContextType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.prioritization_request_business_context_type_0 import PrioritizationRequestBusinessContextType0

        finding_ids: list[str] | Unset = UNSET
        if not isinstance(self.finding_ids, Unset):
            finding_ids = self.finding_ids

        algorithm = self.algorithm

        business_context: dict[str, Any] | None | Unset
        if isinstance(self.business_context, Unset):
            business_context = UNSET
        elif isinstance(self.business_context, PrioritizationRequestBusinessContextType0):
            business_context = self.business_context.to_dict()
        else:
            business_context = self.business_context

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if finding_ids is not UNSET:
            field_dict["finding_ids"] = finding_ids
        if algorithm is not UNSET:
            field_dict["algorithm"] = algorithm
        if business_context is not UNSET:
            field_dict["business_context"] = business_context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.prioritization_request_business_context_type_0 import PrioritizationRequestBusinessContextType0

        d = dict(src_dict)
        finding_ids = cast(list[str], d.pop("finding_ids", UNSET))

        algorithm = d.pop("algorithm", UNSET)

        def _parse_business_context(data: object) -> None | PrioritizationRequestBusinessContextType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                business_context_type_0 = PrioritizationRequestBusinessContextType0.from_dict(data)

                return business_context_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | PrioritizationRequestBusinessContextType0 | Unset, data)

        business_context = _parse_business_context(d.pop("business_context", UNSET))

        prioritization_request = cls(
            finding_ids=finding_ids,
            algorithm=algorithm,
            business_context=business_context,
        )

        prioritization_request.additional_properties = d
        return prioritization_request

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
