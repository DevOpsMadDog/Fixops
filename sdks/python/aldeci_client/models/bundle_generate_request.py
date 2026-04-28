from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.date_range_model import DateRangeModel


T = TypeVar("T", bound="BundleGenerateRequest")


@_attrs_define
class BundleGenerateRequest:
    """Request body for POST /evidence/bundles/generate.

    The UI sends ``frameworks`` (list), ``date_range`` (object with start/end),
    and ``categories`` (list of evidence category identifiers).

        Attributes:
            frameworks (list[str] | None | Unset): Compliance frameworks to include
            framework (None | str | Unset): (deprecated) Single framework; use 'frameworks' list instead
            date_range (DateRangeModel | None | Unset): Date range for evidence collection
            categories (list[str] | Unset): Evidence categories to include
    """

    frameworks: list[str] | None | Unset = UNSET
    framework: None | str | Unset = UNSET
    date_range: DateRangeModel | None | Unset = UNSET
    categories: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.date_range_model import DateRangeModel

        frameworks: list[str] | None | Unset
        if isinstance(self.frameworks, Unset):
            frameworks = UNSET
        elif isinstance(self.frameworks, list):
            frameworks = self.frameworks

        else:
            frameworks = self.frameworks

        framework: None | str | Unset
        if isinstance(self.framework, Unset):
            framework = UNSET
        else:
            framework = self.framework

        date_range: dict[str, Any] | None | Unset
        if isinstance(self.date_range, Unset):
            date_range = UNSET
        elif isinstance(self.date_range, DateRangeModel):
            date_range = self.date_range.to_dict()
        else:
            date_range = self.date_range

        categories: list[str] | Unset = UNSET
        if not isinstance(self.categories, Unset):
            categories = self.categories

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if frameworks is not UNSET:
            field_dict["frameworks"] = frameworks
        if framework is not UNSET:
            field_dict["framework"] = framework
        if date_range is not UNSET:
            field_dict["date_range"] = date_range
        if categories is not UNSET:
            field_dict["categories"] = categories

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.date_range_model import DateRangeModel

        d = dict(src_dict)

        def _parse_frameworks(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                frameworks_type_0 = cast(list[str], data)

                return frameworks_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        frameworks = _parse_frameworks(d.pop("frameworks", UNSET))

        def _parse_framework(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        framework = _parse_framework(d.pop("framework", UNSET))

        def _parse_date_range(data: object) -> DateRangeModel | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                date_range_type_0 = DateRangeModel.from_dict(data)

                return date_range_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DateRangeModel | None | Unset, data)

        date_range = _parse_date_range(d.pop("date_range", UNSET))

        categories = cast(list[str], d.pop("categories", UNSET))

        bundle_generate_request = cls(
            frameworks=frameworks,
            framework=framework,
            date_range=date_range,
            categories=categories,
        )

        bundle_generate_request.additional_properties = d
        return bundle_generate_request

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
